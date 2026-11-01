import copy, json, os, shutil, socket, tempfile, threading, time, unittest
from horizon.authz.keys import Signer
from horizon.telemetry import collector as C
from horizon.runtime import sandbox as S
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OK = os.geteuid() == 0 and S.landlock_abi() >= 4
POL = "sha256:" + "p" * 8
def ev(n, tool="http_post", decision="allow", args=None, run="r1", principal="agent"): return C.make_event(principal=principal, tool=tool, args=args or {"url": f"https://approved.test/{n}"}, decision=decision, policy_hash=POL, execution_id=f"x{n}", run_id=run, status="done")
def build(n=10, batch=4):
    ch = C.Chain(Signer.generate("c", "t"), batch_size=batch)
    for i in range(n): ch.append(ev(i))
    return ch
class ChainTests(unittest.TestCase):
    def test_schema_fields_and_monotonic_order(self):
        ch = build(); log = ch.export(); r = log["records"]; self.assertTrue(all(r[i]["event"]["mono_ns"] <= r[i + 1]["event"]["mono_ns"] for i in range(len(r) - 1))); e = r[0]["event"]
        for k in ("principal", "op_digest", "policy_hash", "execution_id", "mono_ns", "source"): self.assertIn(k, e)
        self.assertEqual(e["source"], "trusted_collector"); self.assertEqual([x["seq"] for x in r], list(range(10)))
    def test_clean_chain_verifies_and_reports_unsealed_tail(self):
        ch = build(10, 4); v = C.verify_chain(ch.export(), ch.public_raw); self.assertTrue(v["ok"], v); self.assertEqual(v["sealed_through"], 9)
        ch3 = C.Chain(Signer.generate("c", "t"), batch_size=100)
        for i in range(5): ch3.append(ev(i))
        v = C.verify_chain({"records": ch3.records, "seals": ch3.seals}, ch3.public_raw); self.assertTrue(v["ok"]); self.assertEqual(v["unsealed_tail"], 5)
    def test_modification_deletion_reorder_truncation_forged_seal(self):
        ch = build(); good = ch.export(); pub = ch.public_raw; code = lambda log: " ".join(C.verify_chain(log, pub)["problems"])
        m = copy.deepcopy(good); m["records"][3]["event"]["decision"] = "deny"; self.assertIn("RECORD_MODIFIED@3", code(m))
        d = copy.deepcopy(good); del d["records"][4]; self.assertTrue("CHAIN_BREAK@4" in code(d) or "SEQ_GAP_OR_REORDER@4" in code(d))
        r = copy.deepcopy(good); r["records"][2], r["records"][3] = r["records"][3], r["records"][2]; self.assertIn("SEQ_GAP_OR_REORDER", code(r))
        t = copy.deepcopy(good); t["records"] = t["records"][:5]; self.assertIn("TRUNCATED_BELOW_SEAL", code(t))
        f = copy.deepcopy(good); f["seals"][0]["head"] = "0" * 64; self.assertIn("SEAL_FORGED", code(f))
        o = copy.deepcopy(good); o["seals"][0]["sig"] = Signer.generate("x", "y").sign(b"z").hex(); self.assertIn("SEAL_FORGED", code(o))
        rehash = copy.deepcopy(good)      # attacker rewrites a record AND repairs the hash chain forward: only the signature/seal can catch it
        rec = rehash["records"][3]; rec["event"]["decision"] = "deny"; prev = rec["prev"]
        for i in range(3, len(rehash["records"])):
            r_ = rehash["records"][i]; r_["prev"] = prev; r_["hash"] = C.sha({"seq": r_["seq"], "prev": r_["prev"], "event": r_["event"]}); prev = r_["hash"]
        self.assertIn("SEAL_HEAD_MISMATCH", code(rehash))
    def test_redaction_before_persistence_with_audit(self):
        ch = C.Chain(Signer.generate("c", "t")); e = ev(1); e["note"] = "token ghp_" + "A" * 24 + " and AKIA" + "B" * 16; rec = ch.append(e); txt = json.dumps(rec); self.assertNotIn("ghp_" + "A" * 24, txt); self.assertNotIn("AKIA" + "B" * 16, txt); self.assertTrue(rec["event"]["redaction_audit"])
class Reconcile(unittest.TestCase):
    def setUp(self):
        self.sg = Signer.generate("c", "t"); self.ch = C.Chain(self.sg, batch_size=3); self.j = C.ReceiverJournal("sink.test")
        self.tx = []
        for i in range(4):
            e = ev(i); self.ch.append(e); self.j.record(e["execution_id"], b"body%d" % i); self.tx.append({"execution_id": e["execution_id"], "tool": e["tool"], "args": {"url": f"https://approved.test/{i}"}})
    def rec(self, tx=None, ch=None, j=None): ch = ch or self.ch; return C.reconcile(self.tx if tx is None else tx, ch.export(), j or self.j, ch.public_raw)
    def codes(self, rep): return sorted(f["code"] for f in rep["findings"])
    def test_clean_run_is_clean_and_signed(self):
        rep = C.reconcile(self.tx, self.ch.export(), self.j, self.ch.public_raw, Signer.generate("rep", "t")); self.assertTrue(rep["clean"], rep["findings"]); self.assertIn("sig", rep); self.assertTrue(rep["limits"])
    def test_fabricated_transcript_call_detected(self):
        self.assertEqual(self.codes(self.rec(self.tx + [{"execution_id": "x99", "tool": "http_post", "args": {"url": "https://approved.test/99"}}])), ["TRANSCRIPT_CLAIM_WITHOUT_TRUSTED_EVENT"])
    def test_modified_or_omitted_transcript_detected(self):
        t = copy.deepcopy(self.tx); t[1]["args"]["url"] = "https://approved.test/other"; self.assertEqual(self.codes(self.rec(t)), ["TRANSCRIPT_OPERATION_DIFFERS_FROM_TRUSTED"]); self.assertEqual(self.codes(self.rec(self.tx[:2])), ["TRUSTED_EVENT_ABSENT_FROM_TRANSCRIPT"] * 2)
    def test_agent_rewrites_or_deletes_its_own_local_trace(self):      # P35-09: the trusted log is unaffected
        local = tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl"); [local.write(json.dumps(t) + "\n") for t in self.tx]; local.close(); open(local.name, "w").close()      # agent truncates its own file
        tx = [json.loads(l) for l in open(local.name) if l.strip()]; os.unlink(local.name); rep = self.rec(tx); self.assertEqual(self.codes(rep), ["TRUSTED_EVENT_ABSENT_FROM_TRANSCRIPT"] * 4); self.assertTrue(C.verify_chain(self.ch.export(), self.ch.public_raw)["ok"])
    def test_denied_but_effect_and_uninstrumented_effect_and_uncertain_allow(self):
        ch = C.Chain(self.sg, batch_size=3); j = C.ReceiverJournal("s"); d = ev(1, decision="deny"); ch.append(d); j.record(d["execution_id"], b"leak"); a = ev(2); ch.append(a); j.record("x777", b"side channel")
        tx = [{"execution_id": "x1", "tool": d["tool"], "args": {"url": "https://approved.test/1"}}, {"execution_id": "x2", "tool": a["tool"], "args": {"url": "https://approved.test/2"}}]; rep = C.reconcile(tx, ch.export(), j, ch.public_raw); self.assertEqual(self.codes(rep), ["ALLOWED_NO_EFFECT_OBSERVED", "DENIED_BUT_EFFECT_OBSERVED", "EFFECT_WITHOUT_TRUSTED_EVENT"])
        self.assertIn("uncertain", [f for f in rep["findings"] if f["code"] == "ALLOWED_NO_EFFECT_OBSERVED"][0]["note"])
    def test_conflicting_and_reused_execution_ids(self):
        ch = C.Chain(self.sg); ch.append(ev(1)); ch.append(C.make_event(principal="agent", tool="run_cmd", args={"cmd": "id"}, decision="allow", policy_hash=POL, execution_id="x1", run_id="r1", status="done")); rep = C.reconcile([], ch.export(), C.ReceiverJournal("s"), ch.public_raw); self.assertIn("CONFLICTING_EXECUTION_ID", self.codes(rep))
        tx = self.tx + [{"execution_id": "x0", "tool": "run_cmd", "args": {"cmd": "id"}}]; self.assertIn("TRANSCRIPT_REUSES_EXECUTION_ID", self.codes(self.rec(tx)))
    def test_log_tampering_surfaces_in_reconciliation(self):
        log = self.ch.export(); log["records"][1]["event"]["decision"] = "deny"; rep = C.reconcile(self.tx, log, self.j, self.ch.public_raw); self.assertFalse(rep["clean"]); self.assertIn("LOG_INTEGRITY", [f["code"] for f in rep["findings"]])
    def test_benign_restart_and_rotation_stay_clean(self):      # P35-13
        ch2 = C.Chain(self.sg, batch_size=3); first = self.ch.export(); C.link_segment(first, ch2); tx2 = []
        for i in range(10, 13): e = ev(i, run="r1-restarted"); ch2.append(e); self.j.record(e["execution_id"], b"b"); tx2.append({"execution_id": e["execution_id"], "tool": e["tool"], "args": {"url": f"https://approved.test/{i}"}})
        second = ch2.export(); self.assertTrue(C.verify_rotation(first, second)); self.assertTrue(C.verify_chain(second, ch2.public_raw)["ok"]); rep = C.reconcile(self.tx + tx2, {"records": first["records"] + second["records"][1:], "seals": []}, self.j, self.ch.public_raw)
        self.assertFalse(any(f["code"] in ("TRANSCRIPT_CLAIM_WITHOUT_TRUSTED_EVENT", "TRUSTED_EVENT_ABSENT_FROM_TRANSCRIPT") for f in rep["findings"]))
        bad = copy.deepcopy(second); bad["records"][0]["event"]["prev_segment_head"] = "0" * 64; self.assertFalse(C.verify_rotation(first, bad))
class NoEffect(unittest.TestCase):
    def test_signed_no_effect_assertion(self):
        j = C.ReceiverJournal("sink.test"); j.record("x1", b"a"); a = j.assert_no_effect(["x2", "x3"]); self.assertEqual(a["effects_found"], 0); self.assertTrue(C.verify_assertion(a, j.public_raw, j))
        bad = dict(a, effects_found=1); self.assertFalse(C.verify_assertion(bad, j.public_raw)); self.assertFalse(C.verify_assertion(a, Signer.generate("z", "z").public_raw()))
        j.entries.append({"i": 1, "execution_id": "x2", "body_sha256": "x", "t": 0}); self.assertEqual(j.assert_no_effect(["x2"])["effects_found"], 1)
        j2 = C.ReceiverJournal("s"); j2.record("x1", b"a"); a2 = j2.assert_no_effect(["x9"]); j2.entries[0]["execution_id"] = "x9"; self.assertFalse(C.verify_assertion(a2, j2.public_raw, j2))      # journal rewritten after the assertion
class Enforce(unittest.TestCase):
    def test_collector_loss_blocks_effect_enforce_and_bounds_backpressure_observe(self):
        with tempfile.TemporaryDirectory() as d:
            cp = C.CollectorProcess(d).start(); cl = cp.client(); j = C.ReceiverJournal("sink.test"); eff = lambda x, p: j.record(x, p)
            ex = C.ProtectedExecutor(cl.emit, eff, mode="enforce"); self.assertTrue(ex.run(ev(1), b"a")["ok"]); cp.kill(); r = ex.run(ev(2), b"b"); self.assertEqual(r["code"], "COLLECTOR_UNAVAILABLE_FAIL_CLOSED"); self.assertEqual([e["execution_id"] for e in j.entries], ["x1"])
            a = j.assert_no_effect(["x2"]); self.assertEqual(a["effects_found"], 0); self.assertTrue(C.verify_assertion(a, j.public_raw, j))
            cp2 = C.CollectorProcess(tempfile.mkdtemp()); cp2.start(); cl2 = cp2.client(); j2 = C.ReceiverJournal("s"); ob = C.ProtectedExecutor(cl2.emit, lambda x, p: j2.record(x, p), mode="observe", max_pending=2); cp2.kill()
            res = [ob.run(ev(i), b"x") for i in range(5)]; self.assertEqual([r["ok"] for r in res], [True, True, False, False, False]); self.assertEqual(res[2]["code"], "BACKPRESSURE_LIMIT"); self.assertEqual(len(ob.pending), 2); self.assertEqual(len(j2.entries), 2)
class OutOfProcess(unittest.TestCase):
    def test_separate_process_signs_and_survives_agent_side_tampering(self):
        with tempfile.TemporaryDirectory() as d, C.CollectorProcess(d) as cp:
            cl = cp.client(); [cl.emit(ev(i)) for i in range(9)]; log = cl.export(); self.assertTrue(C.verify_chain(log, cp.pub)["ok"]); self.assertNotEqual(cp.proc.pid, os.getpid())
            self.assertFalse(C.verify_chain(log, Signer.generate("x", "y").public_raw())["ok"])
    @unittest.skipUnless(OK, "UNSUPPORTED: needs root + Landlock")
    def test_sandboxed_agent_cannot_reach_collector_socket_or_log(self):
        d = tempfile.mkdtemp(); os.chmod(d, 0o755)
        try:
            with C.CollectorProcess(d) as cp:
                code = f"import socket,os\nout=[]\ns=socket.socket(socket.AF_UNIX)\ntry:\n  s.connect({cp.sock!r});out.append('CONNECTED')\nexcept OSError as e: out.append('connect-err')\ntry: out.append(str(os.listdir({d!r})))\nexcept OSError: out.append('list-err')\nprint(out)"
                r = S.launch(code, run_id="agent", scratch=tempfile.mkdtemp()); self.assertNotIn("CONNECTED", r.stdout); self.assertIn("connect-err", r.stdout)
        finally: shutil.rmtree(d, ignore_errors=True)
class Load(unittest.TestCase):
    def test_concurrent_agents_no_drops_and_clock_uncertainty_measured(self):
        N, M = 4, 50
        with tempfile.TemporaryDirectory() as d, C.CollectorProcess(d) as cp:
            def agent(a):
                cl = cp.client()
                for i in range(M): cl.emit(ev(f"{a}-{i}", run=f"r{a}"))
            t0 = time.time(); th = [threading.Thread(target=agent, args=(a,)) for a in range(N)]; [t.start() for t in th]; [t.join() for t in th]; dt = time.time() - t0
            log = cp.client().export(); v = C.verify_chain(log, cp.pub); self.assertTrue(v["ok"]); self.assertEqual(v["records"], N * M)      # drop rate 0 with ack-before-effect
            ids = [r["event"]["execution_id"] for r in log["records"]]; self.assertEqual(len(set(ids)), N * M)
            rs = log["records"]; drift = max(abs((rs[i + 1]["event"]["wall"] - rs[i]["event"]["wall"]) - (rs[i + 1]["event"]["mono_ns"] - rs[i]["event"]["mono_ns"]) / 1e9) for i in range(len(rs) - 1)); self.assertLess(drift, 0.5)
            self.assertGreater(N * M / dt, 20)      # sanity floor only; real numbers are in docs/evidence/p35/MEASUREMENTS.json (machine-specific)
class Measured(unittest.TestCase):
    def test_measurements_committed_with_zero_drop_and_honest_note(self):
        m = json.load(open(os.path.join(ROOT, "docs/evidence/p35/MEASUREMENTS.json")))
        self.assertIn("not a capacity claim", m["note"]); self.assertEqual(sorted(r["agents"] for r in m["runs"]), [1, 4, 8, 16])
        for r in m["runs"]: self.assertEqual(r["drop_rate"], 0.0); self.assertTrue(r["chain_ok"]); self.assertEqual(r["recorded"], r["attempted"])
class Timeline(unittest.TestCase):
    def test_multi_source_timeline_keeps_provenance(self):
        tl = C.timeline({"collector": {"authenticated": True, "clock_uncertainty_s": 0.001, "events": [{"t": 2.0, "what": "allow"}]}, "receiver": {"authenticated": True, "events": [{"t": 2.1, "what": "bytes"}]}, "agent_log": {"authenticated": False, "events": [{"t": 1.9, "what": "claimed call"}]}})
        self.assertEqual([e["source"] for e in tl], ["agent_log", "collector", "receiver"]); self.assertFalse(tl[0]["authenticated"]); self.assertEqual(tl[1]["clock_uncertainty_s"], 0.001)
class MG(unittest.TestCase):
    def test_mg_g9_doc(self):
        t = open(os.path.join(ROOT, "docs/evidence/p35/TRACES_CANNOT_PROVE_NEGATIVES.md")).read()
        for k in ("Uninstrumented paths", "Unsealed tail", "uncertain", "Collector compromise", "never supports"): self.assertIn(k, t)
if __name__ == "__main__": unittest.main()
