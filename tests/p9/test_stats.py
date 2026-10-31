import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bench.p9 import stats as S


class StatsTests(unittest.TestCase):
    def test_mcnemar_known_values(self):
        self.assertEqual(S.mcnemar_exact(0, 0), 1.0); self.assertAlmostEqual(S.mcnemar_exact(0, 10), 2 / 1024, 9); self.assertEqual(S.mcnemar_exact(5, 5), 1.0); self.assertAlmostEqual(S.mcnemar_exact(1, 9), 2 * 11 / 1024, 9)
    def test_wilson(self):
        lo, hi = S.wilson(5, 10); self.assertTrue(abs(lo - 0.2366) < 1e-3 and abs(hi - 0.7634) < 1e-3); self.assertEqual(S.wilson(0, 0), None); self.assertEqual(S.wilson(10, 10)[1], 1.0); self.assertEqual(S.wilson(0, 10)[0], 0.0)
    def test_holm(self):
        self.assertEqual(S.holm([0.01, 0.04, 0.03]), [0.03, 0.06, 0.06]); self.assertEqual(S.holm([0.5]), [0.5]); self.assertTrue(all(0 <= p <= 1 for p in S.holm([0.9, 0.8, 0.99])))
    def test_cohens_h_sign_and_zero(self): self.assertEqual(S.cohens_h(0.5, 0.5), 0.0); self.assertGreater(S.cohens_h(1.0, 0.0), 3.0); self.assertLess(S.cohens_h(0.1, 0.9), 0)
    def test_paired_counts(self):
        a = {"x": 1, "y": 1, "z": 0, "w": 0}; b = {"x": 1, "y": 0, "z": 1, "w": 0}; r = S.paired(a, b)
        self.assertEqual((r["n"], r["discordant_a_only"], r["discordant_b_only"], r["risk_difference"]), (4, 1, 1, 0.0)); self.assertEqual(r["mcnemar_exact_p"], 1.0); self.assertEqual(S.paired({}, {"q": 1}), {"n": 0})
    def test_cluster_bootstrap_deterministic_and_contains_point(self):
        ids = [f"i{k}" for k in range(40)]; a = {i: 1 for i in ids}; b = {i: 0 if k % 2 else 1 for k, i in enumerate(ids)}; cl = {i: k % 8 for k, i in enumerate(ids)}
        r1 = S.cluster_bootstrap_rd(a, b, cl); r2 = S.cluster_bootstrap_rd(a, b, cl); self.assertEqual(r1, r2); self.assertTrue(r1[0] <= 0.5 <= r1[1]); self.assertIsNone(S.cluster_bootstrap_rd(a, b, {i: 0 for i in ids}))
    def test_cluster_bootstrap_wider_than_naive_when_clustered(self):
        ids = [f"i{k}" for k in range(40)]; cl = {i: k // 10 for k, i in enumerate(ids)}; a = {i: 1 for i in ids}; b = {i: 0 if cl[i] < 2 else 1 for i in ids}; lo, hi = S.cluster_bootstrap_rd(a, b, cl); self.assertGreater(hi - lo, 0.3)


if __name__ == "__main__": unittest.main()
