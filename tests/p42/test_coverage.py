import copy, json, os, unittest
from horizon.coverage import engine as EN, harness as H, regress as RG
from scripts import p42_release_gate as GATE
ROOT = EN.ROOT; D = os.path.join(ROOT, "results/v2/p42-coverage"); CLAIMS = json.load(open(os.path.join(ROOT, "spec/protection_claims.json")))
OK, WHY = H.sandbox_available()


def synth(states):
    sinks = [{"id": i, "family": H.INVENTORY[0]["family"], "overall": s, "enforcement": [s], "observation": [s]} for i, s in states.items()]
    b = {"schema": EN.SCHEMA, "issued_at": 1000, "ttl_s": 3600, "components": EN.components(), "sinks": sinks}; return b


class States(unittest.TestCase):
    def test_fresh_verified_stays(self):
        b = synth({"A": "VERIFIED"}); r = EN.evaluate(b, EN.components(), 1010); self.assertEqual(r["sinks"][0]["state"], "VERIFIED"); self.assertEqual(r["reasons"], [])
    def test_ttl_expiry_degrades_but_never_upgrades(self):
        b = synth({"A": "VERIFIED", "B": "MISSING", "C": "UNKNOWN"}); r = EN.evaluate(b, EN.components(), 1000 + 3600)
        self.assertEqual([o["state"] for o in r["sinks"]], ["UNKNOWN", "MISSING", "UNKNOWN"]); self.assertIn("TTL_EXPIRED", r["reasons"])
        r2 = EN.evaluate(b, EN.components(), 1010); self.assertEqual([o["state"] for o in r2["sinks"]], ["VERIFIED", "MISSING", "UNKNOWN"])
    def test_every_component_change_invalidates(self):
        b = synth({"A": "VERIFIED"}); cur = EN.components()
        for k in cur:
            c = dict(cur); c[k] = "changed"; r = EN.evaluate(b, c, 1010); self.assertEqual(r["sinks"][0]["state"], "UNKNOWN", k); self.assertIn("INVALIDATED:" + k, r["reasons"])
    def test_future_issue_time_rejected(self):
        self.assertEqual(EN.evaluate(synth({"A": "VERIFIED"}), EN.components(), 100)["sinks"][0]["state"], "UNKNOWN")
    def test_components_track_real_code_changes(self):
        import shutil, tempfile
        t = tempfile.mkdtemp()
        try:
            for rel in ("horizon/adapters", "horizon/runtime", "horizon/coverage", "horizon/counterfactual", "horizon/telemetry"): shutil.copytree(os.path.join(ROOT, rel), os.path.join(t, rel), ignore=shutil.ignore_patterns("__pycache__"))
            a = EN.components(root=t); self.assertEqual(a, EN.components())
            open(os.path.join(t, "horizon/runtime/sandbox.py"), "a").write("\n#x\n"); self.assertNotEqual(EN.components(root=t)["sandbox_code"], a["sandbox_code"])
        finally: shutil.rmtree(t, ignore_errors=True)
    def test_ratios_count_missing_and_unknown_separately(self):
        r = EN.ratios([{"family": "FILE", "overall": "VERIFIED"}, {"family": "FILE", "overall": "MISSING"}, {"family": "NETWORK", "overall": "UNKNOWN"}])
        self.assertEqual((r["FILE"]["VERIFIED"], r["FILE"]["MISSING"], r["FILE"]["verified_ratio"]), (1, 1, 0.5)); self.assertEqual(r["NETWORK"]["UNKNOWN"], 1); self.assertIsNone(r["BROWSER"]["verified_ratio"]); self.assertEqual(r["ALL"]["sinks"], 3)


class Claims(unittest.TestCase):
    def test_claim_needs_all_sinks_verified(self):
        rep = {"sinks": [{"id": "A", "state": "VERIFIED"}, {"id": "B", "state": "UNKNOWN"}]}
        r = EN.claims_status({"c1": {"sinks": ["A"]}, "c2": {"sinks": ["A", "B"]}, "c3": {"sinks": ["A", "ZZ"]}}, rep)
        self.assertTrue(r["c1"]["supported"]); self.assertFalse(r["c2"]["supported"]); self.assertEqual(r["c2"]["blocking"], {"B": "UNKNOWN"}); self.assertEqual(r["c3"]["blocking"], {"ZZ": "MISSING"})
    def test_gate_blocks_on_expired_evidence(self):
        ids = {i for c in CLAIMS.values() if isinstance(c, dict) for i in c["sinks"]}; b = synth({i: "VERIFIED" for i in ids})
        self.assertTrue(all(v["supported"] for v in GATE.gate(CLAIMS, b, 1010).values())); self.assertFalse(any(v["supported"] for v in GATE.gate(CLAIMS, b, 10 ** 9).values()))
    def test_gate_blocks_when_one_sink_unknown(self):
        ids = {i for c in CLAIMS.values() if isinstance(c, dict) for i in c["sinks"]}; b = synth({i: "VERIFIED" for i in ids}); b["sinks"][0]["overall"] = "UNKNOWN"
        st = GATE.gate(CLAIMS, b, 1010); self.assertEqual(sum(1 for v in st.values() if not v["supported"]), 1)
    def test_claims_reference_real_sinks_and_unsupported_ones_listed(self):
        known = {s["id"] for s in H.INVENTORY}
        for c in CLAIMS.values():
            if isinstance(c, dict): self.assertTrue(set(c["sinks"]) <= known)
        self.assertEqual(len(CLAIMS["unsupported_do_not_claim"]), 3)
    def test_recorded_run_does_not_support_unsupported_sinks(self):
        b = json.load(open(os.path.join(D, "bundle.json"))); st = {s["id"]: s["overall"] for s in b["sinks"]}
        for i in ("CRED-READ", "PROC-SPAWN-LONG", "PROC-SPAWN-FAST", "BROWSER-ACTION"): self.assertNotEqual(st[i], "VERIFIED", i)


class Streams(unittest.TestCase):
    def test_log_tampering_detected_clean_passes(self):
        log, pub = RG.make_log(); self.assertEqual(EN.stream_health(log, pub)["state"], "VERIFIED")
        for k in ("delete", "reorder", "forge"): self.assertEqual(EN.stream_health(RG.tamper(log, k), pub)["state"], "UNKNOWN", k)
    def test_wrong_key_unknown(self):
        log, _ = RG.make_log(); _, other = RG.make_log(); self.assertEqual(EN.stream_health(log, other)["state"], "UNKNOWN")
    def test_compare_host_vs_app(self):
        h = [{"kind": "tcp", "target": "x"}]; self.assertEqual(EN.compare_streams(h, h)["state"], "VERIFIED")
        c = EN.compare_streams(h, [{"kind": "tool_call", "target": "run"}]); self.assertEqual((c["state"], c["host_only"], c["app_only"]), ("UNKNOWN", [("tcp", "x")], [("tool_call", "run")]))
    def test_ingest_clean_window(self):
        i = EN.Ingest(cap=8)
        for s in range(5): i.emit(s, {}); i.drain()
        self.assertEqual(i.window_state(4), ("VERIFIED", []))
    def test_ingest_outage_backpressure_restart_are_gaps(self):
        i = EN.Ingest(cap=2)
        for s in range(3): i.emit(s, {})            # 2 queued, seq 2 dropped by backpressure
        i.drain(); i.outage(); i.emit(3, {}); i.restart(); i.emit(4, {}); i.drain()
        st, gaps = i.window_state(4); self.assertEqual(st, "UNKNOWN"); self.assertEqual(gaps, [2, 3]); self.assertEqual({r for _, r in i.dropped}, {"BACKPRESSURE", "COLLECTOR_DOWN"})
    def test_restart_loses_queued_events(self):
        i = EN.Ingest(cap=8); i.emit(0, {}); i.emit(1, {}); i.restart(); i.emit(2, {}); i.drain(); self.assertEqual(i.gaps(2), [0, 1])
    def test_silence_is_not_safe(self):
        self.assertEqual(EN.Ingest().window_state(3)[0], "UNKNOWN")


class Classify(unittest.TestCase):
    S = {"id": "X", "enforcement_point": "e", "observation_channel": "o"}
    def c(self, weak, strong, s=None, refused=None):
        t = lambda v: {"seen": v, **({"refused": refused} if refused else {})}
        return H.classify(s or self.S, {"weak": [t(v) for v in weak], "strong": [t(v) for v in strong]})
    def test_verified_needs_effect_when_weak_and_absent_when_strong(self): self.assertEqual(self.c([True] * 3, [False] * 3)["overall"], "VERIFIED")
    def test_enforcement_leak_is_missing(self):
        r = self.c([True] * 3, [False, True, False]); self.assertEqual((r["enforcement"][0], r["overall"]), ("MISSING", "MISSING"))
    def test_blind_observer_is_unknown_not_verified(self):
        r = self.c([False] * 3, [False] * 3); self.assertEqual((r["observation"][0], r["enforcement"][0], r["overall"]), ("UNKNOWN", "UNKNOWN", "UNKNOWN"))
    def test_partial_sensitivity_unknown(self): self.assertEqual(self.c([False, True, False], [False] * 3)["overall"], "UNKNOWN")
    def test_no_observer_means_enforcement_never_verified(self):
        r = self.c([None] * 3, [False] * 3, {**self.S, "observation_channel": None}); self.assertEqual((r["observation"][0], r["enforcement"][0], r["overall"]), ("MISSING", "UNKNOWN", "MISSING"))
    def test_no_enforcement_point_is_missing_even_with_perfect_observer(self):
        r = self.c([True] * 3, [True] * 3, {**self.S, "enforcement_point": None}); self.assertEqual((r["observation"][0], r["enforcement"][0], r["overall"]), ("VERIFIED", "MISSING", "MISSING"))
    def test_no_enforcement_point_missing_even_if_nothing_leaked(self):
        r = self.c([True] * 3, [False] * 3, {**self.S, "enforcement_point": None}); self.assertEqual((r["enforcement"][0], r["overall"]), ("MISSING", "MISSING"))
    def test_refusal_overrides_apparent_evidence(self): self.assertEqual(self.c([True] * 3, [False] * 3, refused="boom")["overall"], "UNKNOWN")
    def test_refusal_is_unknown(self): self.assertEqual(self.c([None] * 3, [None] * 3, refused="boom")["overall"], "UNKNOWN")
    def test_none_results_do_not_count_as_absent(self): self.assertNotEqual(self.c([True] * 3, [None, False, False])["overall"], "VERIFIED")
    def test_browser_always_missing(self): self.assertEqual(self.c([True] * 3, [False] * 3, {**self.S, "id": "BROWSER-ACTION"})["overall"], "MISSING")
    def test_overall_is_worst_of_two(self):
        r = self.c([True, True, False], [False] * 3); self.assertEqual(r["overall"], "UNKNOWN")


class Recorded(unittest.TestCase):
    R = json.load(open(os.path.join(D, "result.json"))); B = json.load(open(os.path.join(D, "bundle.json")))
    def test_inventory_covers_all_families_and_has_both_channels(self):
        self.assertEqual({s["family"] for s in H.INVENTORY}, set(H.FAMILIES))
        rec = {s["id"]: s["overall"] for s in self.B["sinks"]}
        for s in H.INVENTORY:
            self.assertTrue(s["interface"])
            if not (s["enforcement_point"] and s["observation_channel"]): self.assertEqual(rec[s["id"]], "MISSING", s["id"])       # an absent control/observer must be recorded as MISSING, never filled in
    def test_every_family_has_ratio_and_totals_add_up(self):
        for f in H.FAMILIES: v = self.R["ratios"][f]; self.assertEqual(v["VERIFIED"] + v["UNKNOWN"] + v["MISSING"], v["sinks"])
        self.assertEqual(self.R["ratios"]["ALL"]["sinks"], len(H.INVENTORY))
    def test_all_regressions_detected_and_baselines_blind(self):
        b = self.R["benchmark"]; self.assertEqual(b["horizon_coverage"]["missed"], 0); self.assertEqual(b["unqualified_all_safe"]["loss_of_assurance_detected"], 0); self.assertEqual(b["tool_level_logging"]["loss_of_assurance_detected"], 0)
        self.assertEqual(b["tool_logging_with_hash_chain"]["loss_of_assurance_detected"], 3); self.assertGreaterEqual(b["tool_level_logging"]["false_assurance_with_real_unauthorized_effect"], 1)
    def test_healthy_control_no_false_alarm(self): self.assertFalse(self.R["healthy_control"]["false_alarm"])
    def test_bundle_digest_binds_content(self):
        b = copy.deepcopy(self.B); d = b.pop("bundle_digest"); self.assertEqual(EN.sha(b), d); b["sinks"][0]["overall"] = "VERIFIED" if b["sinks"][0]["overall"] != "VERIFIED" else "MISSING"; self.assertNotEqual(EN.sha(b), d)
    def test_report_doc_current(self):
        import subprocess, sys; self.assertEqual(subprocess.run([sys.executable, "scripts/p42_report.py", "--check"], cwd=ROOT, capture_output=True).returncode, 0)
    def test_taxonomy_doc_sections(self):
        t = open(os.path.join(ROOT, "docs/evidence/p42/ASSUMPTIONS_AND_TAXONOMY.md")).read()
        for w in ("Sink taxonomy", "States", "Expiry", "Independent observers", "Assumptions", "not discovered by tracing"): self.assertIn(w, t)


@unittest.skipUnless(OK, "live sandbox: " + WHY)
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.env = H.Env(); cls.S = {s["id"]: s for s in H.INVENTORY}
    @classmethod
    def tearDownClass(cls): cls.env.close()
    def cls_(self, i, **kw): return H.classify(self.S[i], H.run_sink(self.env, self.S[i], **kw))
    def test_file_write_verified(self): self.assertEqual(self.cls_("FILE-WRITE-OUTSIDE")["overall"], "VERIFIED")
    def test_tcp_verified_and_weakening_is_noticed(self):
        self.assertEqual(self.cls_("NET-TCP-DIRECT")["overall"], "VERIFIED")
        from horizon.runtime import sandbox as SB
        self.assertNotEqual(self.cls_("NET-TCP-DIRECT", policy_override=SB.Policy(netns=False, seccomp=False, landlock_net=False))["overall"], "VERIFIED")
    def test_native_libc_and_children_confined(self):
        for i in ("NET-NATIVE-LIBC", "PROC-CHILD-WRITE", "PROC-BACKGROUND-WRITE"): self.assertEqual(self.cls_(i)["overall"], "VERIFIED", i)
    def test_observer_down_is_not_verified(self):
        self.env.rc.stop()
        try: self.assertNotEqual(self.cls_("NET-TCP-DIRECT")["overall"], "VERIFIED")
        finally:
            from horizon.runtime.receiver import Receiver
            self.env.rc = Receiver([self.env.tcp], self.env.d).start()
    def test_fs_observer_disabled_not_verified(self): self.assertNotEqual(self.cls_("FILE-WRITE-OUTSIDE", disable=("fs",))["overall"], "VERIFIED")
    def test_credential_and_browser_never_verified(self):
        for i in ("CRED-READ", "BROWSER-ACTION"): self.assertNotEqual(self.cls_(i)["overall"], "VERIFIED", i)
    def test_full_regression_suite(self):
        b = EN.collect(env=self.env); rows = RG.run_regressions(self.env, b)
        self.assertEqual(len(rows), 11); self.assertTrue(all(r["coverage_detected"] for r in rows), [r["id"] for r in rows if not r["coverage_detected"]]); self.assertFalse(RG.healthy_control(self.env, b)["false_alarm"])
        self.assertEqual(RG.benchmark(rows)["unqualified_all_safe"]["loss_of_assurance_detected"], 0)


if __name__ == "__main__": unittest.main()
