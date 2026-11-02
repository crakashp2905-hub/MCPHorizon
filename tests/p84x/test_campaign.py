import random, unittest
from orchestrator import campaign as C

class T:  # clock
    def __init__(s): s.t = 0.0
    def __call__(s): return s.t

class Retry(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(C.classify_failure("dns"), "transient"); self.assertEqual(C.classify_failure("x", 429), "rate_limited")
        self.assertEqual(C.classify_failure("x", 503), "transient"); self.assertEqual(C.classify_failure("x", 500), "transient"); self.assertEqual(C.classify_failure("x", 600), "permanent"); self.assertEqual(C.classify_failure("x", 404), "permanent")
        self.assertEqual(C.classify_failure("tamper"), "security_critical"); self.assertEqual(C.classify_failure("x", 401), "externally_authorized")
        self.assertEqual(C.classify_failure("timeout"), "transient"); self.assertEqual(C.classify_failure("interrupted_download"), "transient")
    def test_no_retry_for_permanent_security_external(self):
        for c in ("permanent", "security_critical", "externally_authorized"): self.assertIsNone(C.retry_delay(c, 0))
    def test_max_attempts(self):
        self.assertIsNotNone(C.retry_delay("transient", 4)); self.assertIsNone(C.retry_delay("transient", 5)); self.assertIsNone(C.retry_delay("transient", 9, max_attempts=5))
    def test_backoff_grows_and_caps_with_jitter(self):
        r = random.Random(1); d = [C.retry_delay("transient", a, rng=r, cap=10) for a in range(5)]
        self.assertTrue(all(0.5 * min(10, 2 ** a) <= x <= min(10, 2 ** a) for a, x in enumerate(d)))
        self.assertLessEqual(max(d), 10)
    def test_retry_after_is_floor(self):
        self.assertGreaterEqual(C.retry_delay("rate_limited", 0, retry_after=120), 120)
        self.assertLess(C.retry_delay("rate_limited", 0, retry_after=0.1), 2)
    def test_jitter_varies(self):
        self.assertNotEqual(C.retry_delay("transient", 2, rng=random.Random(1)), C.retry_delay("transient", 2, rng=random.Random(2)))

class Breaker(unittest.TestCase):
    def test_trip_half_open_recover(self):
        t = T(); b = C.Breaker(2, 10, t); self.assertTrue(b.allow()); b.failure(); self.assertTrue(b.allow()); b.failure()
        self.assertEqual(b.state, "open"); self.assertFalse(b.allow()); t.t = 9.9; self.assertFalse(b.allow())
        t.t = 10; self.assertTrue(b.allow()); self.assertEqual(b.state, "half_open"); self.assertFalse(b.allow())  # one probe only
        b.success(); self.assertEqual(b.state, "closed"); self.assertTrue(b.allow())
    def test_failed_probe_reopens(self):
        t = T(); b = C.Breaker(1, 5, t); b.failure(); t.t = 5; self.assertTrue(b.allow()); b.failure(); self.assertEqual(b.state, "open"); self.assertFalse(b.allow()); t.t = 9; self.assertFalse(b.allow())
    def test_success_resets_count(self):
        b = C.Breaker(3, 1, T()); b.failure(); b.failure(); b.success(); b.failure(); b.failure(); self.assertEqual(b.state, "closed")

class Ready(unittest.TestCase):
    def tasks(self):
        return {"A": {"status": "VERIFIED"}, "B": {"status": "PENDING", "depends_on": ["A"]}, "C": {"status": "PENDING", "depends_on": ["B"]},
                "D": {"status": "PENDING", "depends_on": ["A"], "external_dep": "reg"}, "P": {"status": "PENDING", "depends_on": ["A"], "gates": ["GATE:RC-R"]},
                "M": {"status": "PENDING", "depends_on": ["Z"]}, "R": {"status": "RUNNING"}}
    def test_ready(self): self.assertEqual(C.ready_set(self.tasks()), ["B", "D"])
    def test_rcr_requires_signature(self): self.assertEqual(C.ready_set(self.tasks(), rcr_signed=True), ["B", "D", "P"])
    def test_alternate_when_dependency_unavailable(self):
        self.assertEqual(C.ready_set(self.tasks(), breaker_open_deps=["reg"]), ["B"]); self.assertEqual(C.next_task(self.tasks(), breaker_open_deps=["reg"]), "B")
    def test_missing_prereq_never_ready(self): self.assertNotIn("M", C.ready_set(self.tasks()))
    def test_none_when_empty(self): self.assertIsNone(C.next_task({"A": {"status": "VERIFIED"}}))
    def test_unverified_dep_blocks(self):
        t = self.tasks(); t["A"]["status"] = "NEEDS_REVALIDATION"; self.assertEqual(C.ready_set(t), [])

class Budget(unittest.TestCase):
    def test_limits(self):
        b = C.Budget(5, 8); self.assertTrue(b.charge("t1", 5)); self.assertFalse(b.charge("t1", 0.1)); self.assertTrue(b.charge("t2", 3)); self.assertFalse(b.charge("t3", 0.1))
        self.assertEqual(b.total, 8); self.assertEqual(b.task["t1"], 5)
    def test_refusal_records_nothing(self):
        b = C.Budget(5, 100); b.charge("t", 4); b.charge("t", 2); self.assertEqual(b.task["t"], 4)
    def test_negative_refused(self):
        with self.assertRaises(ValueError): C.Budget(1, 1).charge("t", -1)

class Providers(unittest.TestCase):
    M = {"codex": {"data_classes": ["public", "internal"], "task_classes": ["CODE"]}, "claude": {"data_classes": ["public"], "task_classes": ["CODE", "EXPERIMENT"]}}
    def test_ok_and_rejections(self):
        self.assertTrue(C.provider_ok(self.M, "codex", {"data_class": "internal", "work_class": "CODE"})[0])
        self.assertFalse(C.provider_ok(self.M, "claude", {"data_class": "internal", "work_class": "CODE"})[0])
        self.assertFalse(C.provider_ok(self.M, "codex", {"data_class": "public", "work_class": "EXPERIMENT"})[0]); self.assertFalse(C.provider_ok(self.M, "x", {"data_class": "public", "work_class": "CODE"})[0])
    def test_fallback_respects_privacy(self):
        t = {"data_class": "internal", "work_class": "CODE"}; p, why = C.fallback(self.M, ["codex", "claude"], "codex", "transient", t); self.assertIsNone(p); self.assertIn("data class", why)
        p, _ = C.fallback(self.M, ["codex", "claude"], "codex", "transient", {"data_class": "public", "work_class": "CODE"}); self.assertEqual(p, "claude")
    def test_fallback_only_for_transient(self):
        t = {"data_class": "public", "work_class": "CODE"}
        for c in ("permanent", "security_critical", "externally_authorized"): self.assertIsNone(C.fallback(self.M, ["codex", "claude"], "codex", c, t)[0])
        self.assertEqual(C.fallback(self.M, ["codex", "claude"], "codex", "rate_limited", t)[0], "claude")
    def test_never_falls_back_to_same_provider(self):
        self.assertIsNone(C.fallback(self.M, ["claude"], "claude", "transient", {"data_class": "public", "work_class": "CODE"})[0])

class Approvals(unittest.TestCase):
    def test_scoped_single_use_expiring(self):
        t = T(); i = C.ApprovalInbox(t); op = {"cmd": "deploy", "target": "x"}; i.grant("owner", op, 10)
        self.assertFalse(i.consume({"cmd": "deploy", "target": "y"})); self.assertTrue(i.consume(op)); self.assertFalse(i.consume(op))
    def test_expiry(self):
        t = T(); i = C.ApprovalInbox(t); i.grant("o", {"a": 1}, 10); t.t = 10; self.assertFalse(i.consume({"a": 1}))
    def test_digest_order_independent(self): self.assertEqual(C.op_digest({"a": 1, "b": 2}), C.op_digest({"b": 2, "a": 1}))

class Paths(unittest.TestCase):
    def test_scope(self):
        a = ["horizon/plan/", "tests/p83/x.py"]
        self.assertEqual(C.out_of_scope(["horizon/plan/a.py", "tests/p83/x.py"], a), [])
        self.assertEqual(C.out_of_scope(["horizon/other.py"], a), ["horizon/other.py"])
    def test_protected_even_if_allowed(self):
        self.assertEqual(C.out_of_scope(["results/v2/x.json", "LICENSE", ".github/workflows/t.yml", "spec/plan.lock"], ["results/", "LICENSE", ".github/", "spec/"]), ["results/v2/x.json", "LICENSE", ".github/workflows/t.yml", "spec/plan.lock"])
    def test_traversal_and_absolute(self): self.assertEqual(C.out_of_scope(["../x", "/etc/passwd", "a/../b"], ["a/", "/etc/"]), ["../x", "/etc/passwd", "a/../b"])
    def test_allow_entry_without_slash_is_exact_file(self): self.assertEqual(C.out_of_scope(["horizon/planner.py", "horizon/plan/x.py"], ["horizon/plan"]), ["horizon/planner.py", "horizon/plan/x.py"])
    def test_prefix_not_substring(self): self.assertEqual(C.out_of_scope(["horizon/planner.py"], ["horizon/plan/"]), ["horizon/planner.py"])
    def test_conflicts(self):
        self.assertTrue(C.conflicts(["a/b.py"], ["a/b.py"])); self.assertTrue(C.conflicts(["a/"], ["a/b.py"])); self.assertTrue(C.conflicts(["a/b.py"], ["a/"]))
        self.assertFalse(C.conflicts(["a/b.py"], ["a/c.py"])); self.assertFalse(C.conflicts(["a"], ["ab"])); self.assertFalse(C.conflicts(["ab"], ["a"])); self.assertFalse(C.conflicts(["a/"], ["ab/c.py"]))

class Gates(unittest.TestCase):
    def test_external(self):
        self.assertTrue(C.external_gate("CODE", None)[0]); self.assertFalse(C.external_gate("EXTERNAL", None)[0])
        self.assertFalse(C.external_gate("EXTERNAL", {"synthetic": True, "party": "p", "signature": "s"})[0])
        self.assertFalse(C.external_gate("EXTERNAL", {"party": "p"})[0]); self.assertFalse(C.external_gate("EXTERNAL", {"signature": "s"})[0])
        self.assertTrue(C.external_gate("EXTERNAL", {"party": "p", "signature": "s"})[0])
    def test_coverage(self):
        self.assertEqual(C.coverage_verdict(["a"], ["a", "b"], []), "UNKNOWN"); self.assertEqual(C.coverage_verdict(["a", "b"], ["a", "b"], []), "PASS")
        self.assertEqual(C.coverage_verdict(["a", "b"], ["a", "b"], ["leak"]), "FAIL"); self.assertEqual(C.coverage_verdict(["a"], ["a", "b"], ["leak"]), "UNKNOWN")
    def test_negative_result_not_relabelled(self):
        r = {}; C.record_result(r, "t", "m", 0.1, False, "no effect")
        with self.assertRaises(ValueError): C.record_result(r, "t", "m", 0.9, True)
        C.record_result(r, "t", "m2", 1, True); self.assertEqual(r[("t", "m")]["ok"], False)
    def test_negative_can_be_confirmed_negative(self):
        r = {}; C.record_result(r, "t", "m", 1, False); C.record_result(r, "t", "m", 2, False); self.assertEqual(r[("t", "m")]["value"], 2)

class Counts(unittest.TestCase):
    def test_counts_honest(self):
        t = {"a": {"status": "VERIFIED"}, "b": {"status": "PENDING"}, "c": {"status": "WAITING_EXTERNAL"}, "d": {"status": "NEEDS_APPROVAL"}}
        c = C.counts(t); self.assertEqual((c["total"], c["verified"], c["blocked_or_waiting"]), (4, 1, 2)); self.assertEqual(c["verified_fraction"], 0.25); self.assertIsNone(c["claimed_percent_complete"])
        self.assertEqual(c["by_status"]["PENDING"], 1)
    def test_empty(self): self.assertEqual(C.counts({})["verified_fraction"], 0.0)
if __name__ == "__main__": unittest.main()
