import unittest
from horizon.research import design as D
KW = dict(hypothesis="h", primary_metric="asr", unit="scenario", success_threshold=0.1, direction="less", alpha=0.05, seed=1, config={"t": 1})
class Prereg(unittest.TestCase):
    def test_digest_stable(self): self.assertEqual(D.Prereg(**KW).digest, D.Prereg(**KW).digest); self.assertNotEqual(D.Prereg(**KW).digest, D.Prereg(**dict(KW, seed=2)).digest)
    def test_missing_and_bad(self):
        for k in D.REQUIRED:
            with self.assertRaises(ValueError): D.Prereg(**{a: b for a, b in KW.items() if a != k})
        for bad in (dict(KW, alpha=0), dict(KW, alpha=1), dict(KW, direction="up")):
            with self.assertRaises(ValueError): D.Prereg(**bad)
    def test_primary_change_after_data_refused(self):
        p = D.Prereg(**KW); p.see_data()
        for k, v in (("primary_metric", "x"), ("success_threshold", 0.5), ("direction", "greater"), ("unit", "u"), ("alpha", 0.1)):
            with self.assertRaises(PermissionError): p.amend(**{k: v})
    def test_amend_before_data_links_parent(self):
        p = D.Prereg(**KW); n = p.amend(success_threshold=0.2); self.assertEqual(n.parent, p.digest); self.assertNotEqual(n.digest, p.digest)
    def test_nonprimary_amend_after_data_allowed_as_new_record(self):
        p = D.Prereg(**KW); p.see_data(); self.assertEqual(p.amend(seed=9).f["seed"], 9)
class Stats(unittest.TestCase):
    def test_wilson(self):
        lo, hi = D.wilson(0, 10); self.assertEqual(lo, 0.0); self.assertAlmostEqual(hi, 0.2775, places=3); self.assertEqual(D.wilson(0, 0), (0.0, 1.0))
        lo, hi = D.wilson(5, 10); self.assertAlmostEqual(lo, 0.2366, places=3); self.assertAlmostEqual(hi, 0.7634, places=3)
    def test_n_for_halfwidth(self):
        n = D.n_for_halfwidth(0.5, 0.05); self.assertTrue(380 <= n <= 390)
        lo, hi = D.wilson(round(0.5 * n), n); self.assertLessEqual((hi - lo) / 2, 0.05)
        lo, hi = D.wilson(round(0.5 * (n - 1)), n - 1); self.assertGreater((hi - lo) / 2, 0.05)
        self.assertLess(D.n_for_halfwidth(0.02, 0.05), n)
        for a in ((1.5, 0.1), (0.5, 0), (0.5, 1), (-1, 0.1)):
            with self.assertRaises(ValueError): D.n_for_halfwidth(*a)
    def test_cluster_bootstrap_wider_than_row_bootstrap(self):
        vals = [1] * 10 + [0] * 10; cl = ["a"] * 10 + ["b"] * 10
        lo, hi = D.cluster_bootstrap(vals, cl, reps=500, seed=1); self.assertEqual((lo, hi), (0.0, 1.0))
        cl2 = list(range(20)); lo2, hi2 = D.cluster_bootstrap(vals, cl2, reps=500, seed=1); self.assertLess(hi2 - lo2, 1.0)
    def test_single_cluster_keeps_all_rows(self): self.assertAlmostEqual(D.cluster_bootstrap([0.2, 0.4], ["a", "a"], 50, 1)[0], 0.3)
    def test_percentile_not_extremes(self):
        lo, hi = D.cluster_bootstrap([1] * 10 + [0] * 10, list(range(20)), 2000, 1); self.assertGreaterEqual(lo, 0.25); self.assertLessEqual(hi, 0.8)
    def test_bootstrap_deterministic_and_ordered(self):
        v = [0, 1, 1, 0, 1, 0, 0, 1]; c = [1, 1, 2, 2, 3, 3, 4, 4]; a = D.cluster_bootstrap(v, c, 300, 5); self.assertEqual(a, D.cluster_bootstrap(v, c, 300, 5)); self.assertLessEqual(a[0], a[1])
    def test_holm(self):
        self.assertEqual(D.holm({"a": 0.01, "b": 0.04, "c": 0.03}), {"a": True, "c": False, "b": False})
        self.assertEqual(D.holm({"a": 0.001, "b": 0.01, "c": 0.02}), {"a": True, "b": True, "c": True}); self.assertEqual(D.holm({"a": 0.2}), {"a": False})
        self.assertEqual(D.holm({"a": 0.04, "b": 0.001}), {"b": True, "a": True})
    def test_mcnemar(self):
        self.assertEqual(D.mcnemar_exact(0, 0), 1.0); self.assertAlmostEqual(D.mcnemar_exact(0, 10), 2 / 1024, places=6); self.assertEqual(D.mcnemar_exact(5, 5), 1.0)
        self.assertEqual(D.mcnemar_exact(2, 8), D.mcnemar_exact(8, 2)); self.assertAlmostEqual(D.mcnemar_exact(1, 5), 2 * 7 / 64, places=6)
class Splits(unittest.TestCase):
    def test_audit(self):
        self.assertEqual(D.split_audit(["a", "b"], ["c"]), []); self.assertEqual(D.split_audit(["a", "b"], ["b", "c"]), ["id overlap: 1"])
        T = {"a": "t1", "b": "t2", "c": "t1"}; self.assertEqual(D.split_audit(["a", "b"], ["c"], T), ["template overlap: 1"]); self.assertEqual(D.split_audit(["b"], ["c"], T), [])
class Decide(unittest.TestCase):
    def test_greater(self):
        self.assertEqual(D.decide((0.5, 0.9), 0.4), "GO"); self.assertEqual(D.decide((0.1, 0.3), 0.4), "STOP"); self.assertEqual(D.decide((0.3, 0.6), 0.4), "REVISE"); self.assertEqual(D.decide((0.4, 0.6), 0.4), "GO"); self.assertEqual(D.decide((0.1, 0.4), 0.4), "REVISE")
    def test_less(self):
        self.assertEqual(D.decide((0.0, 0.05), 0.1, "less"), "GO"); self.assertEqual(D.decide((0.2, 0.3), 0.1, "less"), "STOP"); self.assertEqual(D.decide((0.05, 0.2), 0.1, "less"), "REVISE"); self.assertEqual(D.decide((0.0, 0.1), 0.1, "less"), "GO"); self.assertEqual(D.decide((0.1, 0.3), 0.1, "less"), "REVISE")
    def test_bad_execution_not_a_verdict(self): self.assertEqual(D.decide((0.9, 1.0), 0.1, executed_correctly=False), "REVISE_EXECUTION")
class Spend(unittest.TestCase):
    def test_caps_reserve_and_ceiling(self):
        s = D.Spend(100, 20, 50); self.assertTrue(s.worker_charge("a", 50)); self.assertFalse(s.worker_charge("a", 1)); self.assertTrue(s.worker_charge("b", 30)); self.assertFalse(s.worker_charge("c", 1))
        self.assertEqual(s.spent, 80); self.assertTrue(s.verifier_charge(20)); self.assertFalse(s.verifier_charge(0.1)); self.assertEqual(s.total(), 100); self.assertEqual(s.blocked_calls, 3)
    def test_workers_cannot_use_reserve(self):
        s = D.Spend(10, 5, 10); self.assertTrue(s.worker_charge("a", 5)); self.assertFalse(s.worker_charge("a", 0.01))
    def test_validation(self):
        with self.assertRaises(ValueError): D.Spend(10, 11, 5)
        for f in (lambda s: s.worker_charge("a", -1), lambda s: s.verifier_charge(-1)):
            with self.assertRaises(ValueError): f(D.Spend(10, 1, 5))
    def test_digest_reflects_cap(self): self.assertNotEqual(D.Spend(10, 1, 5).digest, D.Spend(11, 1, 5).digest); self.assertNotEqual(D.Spend(10, 1, 5).digest, D.Spend(10, 2, 5).digest); self.assertNotEqual(D.Spend(10, 1, 5).digest, D.Spend(10, 1, 6).digest)
    def test_failed_charge_records_nothing(self):
        s = D.Spend(10, 0, 5); s.worker_charge("a", 4); s.worker_charge("a", 4); self.assertEqual(s.by_task["a"], 4); self.assertEqual(s.spent, 4)
    def test_reconcile(self):
        self.assertEqual(D.reconcile(10, None), {"status": "UNKNOWN", "delta": None}); self.assertEqual(D.reconcile(10, 10.05)["status"], "OK"); self.assertEqual(D.reconcile(10, 12)["status"], "UNDER_REPORTED"); self.assertEqual(D.reconcile(12, 10)["status"], "OVER_REPORTED"); self.assertEqual(D.reconcile(10, 12)["delta"], 2)
    def test_variance(self): self.assertEqual(D.variance_report({"a": 10, "b": 5}, {"a": 12}), {"a": {"forecast": 10, "actual": 12, "variance": 2}, "b": {"forecast": 5, "actual": None, "variance": None}})
if __name__ == "__main__": unittest.main()
