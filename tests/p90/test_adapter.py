import unittest
from horizon.frameworks import adapter as A
CTX = {"principal": "p", "run": "r", "task": "t", "tool_call": "c1", "artifact": "a"}
class Level(unittest.TestCase):
    def test_lineage(self):
        self.assertTrue(A.valid_call(CTX))
        for k in A.LINEAGE:
            self.assertFalse(A.valid_call({a: b for a, b in CTX.items() if a != k})); self.assertFalse(A.valid_call(dict(CTX, **{k: ""}))); self.assertFalse(A.valid_call(dict(CTX, **{k: 1})))
    def test_levels_vocabulary(self): self.assertEqual(set(A.LEVELS), {"NATIVE", "BRIDGED", "OBSERVE_ONLY", "PARTIAL", "UNSUPPORTED", "UNKNOWN"})
    def test_pinned_pass_keeps_claim(self):
        for l in A.LEVELS: self.assertEqual(A.effective_level(l, pinned="1", actual="1", conformance_passed=True), (l, ""))
    def test_version_drift_downgrades_enforcing(self):
        for l in A.ENFORCING: self.assertEqual(A.effective_level(l, pinned="1", actual="2", conformance_passed=True)[0], "UNKNOWN")
    def test_version_drift_does_not_touch_observe_only(self): self.assertEqual(A.effective_level("OBSERVE_ONLY", pinned="1", actual="2", conformance_passed=False)[0], "OBSERVE_ONLY")
    def test_failed_conformance_downgrades(self): self.assertEqual(A.effective_level("NATIVE", pinned="1", actual="1", conformance_passed=False), ("UNKNOWN", "conformance not passed"))
    def test_direct_paths_outside_coverage_unless_os_protected(self):
        for p in ("subprocess", "raw_network"):
            self.assertEqual(A.effective_level("NATIVE", pinned="1", actual="1", conformance_passed=True, path=p)[0], "UNSUPPORTED")
            self.assertEqual(A.effective_level("NATIVE", pinned="1", actual="1", conformance_passed=True, path=p, os_protected_paths=True)[0], "NATIVE")
        self.assertEqual(A.effective_level("OBSERVE_ONLY", pinned="1", actual="1", conformance_passed=True, path="subprocess")[0], "OBSERVE_ONLY")
    def test_unknown_level_rejected(self):
        with self.assertRaises(ValueError): A.effective_level("MAGIC", pinned="1", actual="1", conformance_passed=True)
    def test_matrix_generated_and_sorted(self):
        rs = [{"framework": "b", "version": "1", "path": "tool_call", "claimed": "NATIVE", "pinned": "1", "passed": True}, {"framework": "a", "version": "2", "path": "tool_call", "claimed": "BRIDGED", "pinned": "1", "passed": True},
              {"framework": "a", "version": "1", "path": "subprocess", "claimed": "NATIVE", "pinned": "1", "passed": True}]
        m = A.coverage_matrix(rs); self.assertEqual([(r["framework"], r["version"], r["path"], r["level"]) for r in m], [("a", "1", "subprocess", "UNSUPPORTED"), ("a", "2", "tool_call", "UNKNOWN"), ("b", "1", "tool_call", "NATIVE")])
        self.assertTrue(m[0]["reason"] and m[1]["reason"] and m[2]["reason"] == "")
class Queue(unittest.TestCase):
    def call(self, i, key=None): return {"ctx": dict(CTX, tool_call="c%d" % i), "idempotency_key": key}
    def test_backpressure(self):
        q = A.ToolCallQueue(2); self.assertEqual([q.submit(self.call(i)) for i in range(3)], ["QUEUED", "QUEUED", "REJECTED_BACKPRESSURE"])
    def test_no_lineage_rejected(self): self.assertEqual(A.ToolCallQueue(2).submit({"ctx": {"run": "r"}}), "REJECTED_NO_LINEAGE")
    def test_cancel_removes_and_blocks(self):
        q = A.ToolCallQueue(5); q.submit(self.call(1)); q.submit(self.call(2)); q.cancel("c1"); n = []; self.assertEqual(q.run_next(lambda c: n.append(1) or "ok"), "ok"); self.assertEqual(len(n), 1); self.assertIsNone(q.run_next(lambda c: "x"))
    def test_cancelled_before_submit_never_runs(self):
        q = A.ToolCallQueue(5); q.cancel("c1"); q.submit(self.call(1)); n = []; self.assertEqual(q.run_next(lambda c: n.append(1)), "CANCELLED"); self.assertEqual(n, [])
    def test_idempotent_retry_does_not_repeat_effect(self):
        q = A.ToolCallQueue(5); n = []; eff = lambda c: n.append(1) or len(n); q.submit(self.call(1, "k")); self.assertEqual(q.run_next(eff), 1)
        self.assertEqual(q.retry(self.call(2, "k")), "QUEUED"); self.assertEqual(q.run_next(eff), 1); self.assertEqual(len(n), 1)
    def test_non_idempotent_retry_refused(self): self.assertEqual(A.ToolCallQueue(5).retry(self.call(1)), "REFUSED_NON_IDEMPOTENT")
    def test_no_key_runs_every_time(self):
        q = A.ToolCallQueue(5); n = []; eff = lambda c: n.append(1) or len(n); q.submit(self.call(1)); q.submit(self.call(2)); self.assertEqual((q.run_next(eff), q.run_next(eff)), (1, 2))
    def test_fifo(self):
        q = A.ToolCallQueue(5); q.submit(self.call(1)); q.submit(self.call(2)); seen = []; q.run_next(lambda c: seen.append(c["ctx"]["tool_call"])); q.run_next(lambda c: seen.append(c["ctx"]["tool_call"])); self.assertEqual(seen, ["c1", "c2"])
    def test_empty(self): self.assertIsNone(A.ToolCallQueue(1).run_next(lambda c: 1))
if __name__ == "__main__": unittest.main()
