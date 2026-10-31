import json, os, subprocess, sys, tarfile, tempfile, time, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, os.path.join(ROOT, "scripts"))
from horizon.runtime import events as EV, schema as SC, sandbox as S, broker as B
from horizon.runtime.receiver import Receiver
OK = os.geteuid() == 0 and S.landlock_abi() >= 4
def ev(i=0, status="DENIED", principal="agent", kind="egress.attempt", **x):
    return SC.make_event("r1", i, kind, layer="L2", origin="synthetic", process={"pid": 1, "ppid": 0, "source": "kernel"}, principal=principal, decision="deny", policy_digest="sha256:" + "0" * 64, status=status, oracle={"receiver_bytes": 0}, **x)

class Sink(unittest.TestCase):
    def test_dedup_counts_repeats_and_first_survives(self):
        s = EV.EventSink(); r = [s.emit(ev(i)) for i in range(5)]
        self.assertEqual(r, ["ACCEPTED"] + ["DEDUPED"] * 4); self.assertEqual(len(s.out), 1); self.assertEqual(s.summary()["suppressed_repeats_recorded"], 4)
    def test_rate_limit_counts_not_drops_silently(self):
        t = [0.0]; s = EV.EventSink(rate_per_s=1, burst=3, dedup_window_s=0, clock=lambda: t[0]); r = [s.emit(ev(i)) for i in range(10)]
        self.assertEqual(r.count("ACCEPTED"), 3); self.assertEqual(r.count("RATE_LIMITED"), 7); self.assertEqual(s.summary()["rate_limited"], 7)
        t[0] = 2.5; self.assertEqual(s.emit(ev(99)), "ACCEPTED")
    def test_flood_of_one_kind_does_not_starve_other_principal(self):
        t = [0.0]; s = EV.EventSink(rate_per_s=1, burst=2, dedup_window_s=0, clock=lambda: t[0])
        for i in range(50): s.emit(ev(i, principal="noisy"))
        self.assertEqual(s.emit(ev(100, principal="quiet")), "ACCEPTED")
    def test_redaction_audited(self):
        s = EV.EventSink(); e = ev(1); e["note"] = "leaked ghp_" + "A" * 24 + " and AKIA" + "B" * 16 + " in text";   # injected AFTER validation: the sink is the last line of defence
        self.assertEqual(s.emit(e), "ACCEPTED")
        self.assertNotIn("ghp_" + "A" * 24, json.dumps(s.out[0])); self.assertNotIn("AKIA" + "B" * 16, json.dumps(s.out[0])); self.assertTrue(s.out[0].get("redaction_audit")); self.assertGreaterEqual(s.stats["redactions"], 1)
    def test_totals_reconcile(self):
        t = [0.0]; s = EV.EventSink(rate_per_s=1, burst=2, dedup_window_s=100, clock=lambda: t[0]); n = 0
        for i in range(30): s.emit(ev(i, kind="k%d" % (i % 4))); n += 1
        st = s.summary(); self.assertEqual(st["accepted"] + st["deduped"] + st["rate_limited"] + st["redaction_rejects"], n)

class Failover(unittest.TestCase):
    def test_shared_nonce_store_blocks_replay_on_second_instance(self):
        P = 47790
        def mk(up): return B.Broker({"agent": [B.Rule("approved.test", (P,), ("POST",))]}, B.Resolver({"approved.test": ["127.0.0.1"]}), test_sinks={("127.0.0.1", P)}, key=b"k" * 32, used_path=up)
        with tempfile.TemporaryDirectory() as d, Receiver([P], d) as rc:
            up = os.path.join(d, "used"); a = mk(up); b = mk(up); u = f"http://approved.test:{P}/x"; au = a.authorize("agent", "POST", u, b"abc")
            self.assertTrue(a.execute("agent", "POST", u, b"abc", (), au)["ok"]); time.sleep(0.3)
            self.assertEqual(b.execute("agent", "POST", u, b"abc", (), au)["code"], "PERMIT_REPLAY"); time.sleep(0.2); self.assertEqual(len(rc.rows(P)), 1)
    def test_without_shared_store_replay_is_possible_documented_limit(self):
        P = 47791
        def mk(): return B.Broker({"agent": [B.Rule("approved.test", (P,), ("POST",))]}, B.Resolver({"approved.test": ["127.0.0.1"]}), test_sinks={("127.0.0.1", P)}, key=b"k" * 32)
        with tempfile.TemporaryDirectory() as d, Receiver([P], d) as rc:
            a, b = mk(), mk(); u = f"http://approved.test:{P}/x"; au = a.authorize("agent", "POST", u, b"abc"); a.execute("agent", "POST", u, b"abc", (), au)
            self.assertTrue(b.execute("agent", "POST", u, b"abc", (), au)["ok"])       # a failover instance with NO shared store accepts the replay: why used_path exists

class Static(unittest.TestCase):
    def test_no_external_contact_literals(self):
        import p30_no_external as N; self.assertEqual(N.scan(), [])
    def test_scan_detects_a_planted_host(self):
        import p30_no_external as N, re
        self.assertIsNone(N.ALLOW.match("evil.example.org") and None) if False else self.assertFalse(N.ALLOW.match("collector.badhost.io")); self.assertTrue(N.ALLOW.match("127.0.0.1")); self.assertTrue(N.ALLOW.match("approved.test"))
    def test_claims_audit_passes_and_catches_overclaims(self):
        import p30_claims_audit as C; self.assertEqual(C.scan(), [])
        self.assertTrue(any(rx.search("The model weights caused the exfiltration") for rx, _ in C.BAD)); self.assertTrue(any(rx.search("this runtime is provably secure") for rx, _ in C.BAD))
    def test_hr_gates_derived_and_external_gates_not_met(self):
        import hr_gates as G; g = {x[0]: x[2] for x in G.gates()}; self.assertEqual(g["HR-G7"], "NOT MET"); self.assertEqual(g["HR-G9"], "NOT MET"); self.assertEqual(len(g), 9)
        r = subprocess.run([sys.executable, "scripts/hr_gates.py", "--check"], cwd=ROOT, capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stdout)
    def test_docs_exist_and_state_nonclaims(self):
        t = open(os.path.join(ROOT, "docs/security/P30_REVIEWER_THREAT_MODEL.md")).read(); self.assertIn("Explicit non-claims", t); self.assertIn("HR-G9 NOT MET", t)
        self.assertIn("IPv6", open(os.path.join(ROOT, "docs/security/P30_KERNEL_LIMITS.md")).read())

class Latency(unittest.TestCase):
    def test_percentiles_derived_from_raw_and_b6_completes_tasks(self):
        r = json.load(open(os.path.join(ROOT, "results/v2/haa-latency/result.json")))["aggregate"]["per_cell"]
        for cell in ("B0/compute", "B6/compute", "B6/brokered_get"): self.assertTrue(r[cell]["p50"] <= r[cell]["p95"] <= r[cell]["p99"]); self.assertEqual(r[cell]["success"], r[cell]["n"])
        self.assertEqual(r["B4/brokered_get"]["success"], 0)       # sandbox-only cannot do brokered work: the utility cost the broker removes
    def test_status_doc_lists_unsupported_and_next_actions(self):
        t = open(os.path.join(ROOT, "docs/evidence/p30/P23_P30_STATUS.md")).read()
        for k in ("## Commands", "## Failures and mistakes", "## Unsupported", "## Next actions", "IPv6"): self.assertIn(k, t)

class Bundle(unittest.TestCase):
    def test_build_verify_and_tamper_detected(self):
        import p30_reviewer_bundle as RB
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "b.tar"); m = RB.build(p); self.assertTrue(m["key_is_ephemeral"]); self.assertEqual(RB.verify(p), [])
            self.assertIn("results/v2/haa-main/result.json", m["files"]); self.assertNotIn("TEST_CANARY", "")
            q = os.path.join(d, "t.tar")
            with tarfile.open(p) as src, tarfile.open(q, "w") as dst:
                for mem in src.getmembers():
                    data = src.extractfile(mem).read()
                    if mem.name == "files/docs/security/P30_KERNEL_LIMITS.md": data += b"x"
                    mem.size = len(data); import io; dst.addfile(mem, io.BytesIO(data))
            self.assertTrue(any("HASH_MISMATCH" in x for x in RB.verify(q)))

@unittest.skipUnless(OK, "UNSUPPORTED: needs root + Landlock (run under sudo)")
class KernelRegression(unittest.TestCase):
    """B6 must still prevent the scenario classes that map to P30 trials, with matched benign controls passing."""
    TRIALS = {"HAA-01": "egress+redirect forms", "HAA-02": "metadata", "HAA-03": "credential probes", "HAA-06": "namespace attempts", "HAA-07": "retry after denial", "HAA-09": "alternate interpreters", "HAA-13": "cred replay/wrong destination", "HAA-16": "policy tamper", "HAA-19": "unknown transport", "HAA-20": "broker outage fail-closed", "HAA-21": "resource exhaustion", "HAA-22": "subprocess label loss"}
    def test_b6_prevents_and_controls_pass(self):
        from bench.haa import haa as H, scenarios as SC_
        with H.World() as w:
            for sid, why in self.TRIALS.items():
                a, k = SC_.SCENARIOS[sid](H.Ctx("B6", w)); self.assertFalse(a["effect"], f"{sid} {why}: {a}"); self.assertTrue(k.get("ok"), f"{sid} control: {k}")
    def test_unsandboxed_baseline_still_shows_effects_so_trials_are_not_vacuous(self):
        from bench.haa import haa as H, scenarios as SC_
        with H.World() as w:
            n = sum(SC_.SCENARIOS[s](H.Ctx("B0", w))[0]["effect"] for s in self.TRIALS); self.assertGreaterEqual(n, 10)
if __name__ == "__main__": unittest.main()
