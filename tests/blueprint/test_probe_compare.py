import json, os, random, sys, unittest
R = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, R)
from research.spectra import compare as C, tomography as T
class Compare(unittest.TestCase):
    def test_committed_results_reproduce_exactly(self):
        got = C.experiment(); want = json.load(open(os.path.join(R, "research/spectra/results/probe_selection.json"))); self.assertEqual(json.loads(json.dumps(got)), want)
    def test_every_strategy_discovers_everything_at_full_budget_and_ci_reported(self):
        want = json.load(open(os.path.join(R, "research/spectra/results/probe_selection.json")))
        for n, v in want["strategies"].items(): self.assertEqual(v["discovery_rate_at_budget"]["8"], 1.0, n)
        self.assertEqual(set(want["paired_bootstrap_95ci_mean_probes_saved_by_active_vs"]), {"random", "static_graph", "expert_rule"})
        self.assertIn("NOT held-out", want["note"])
    def test_no_advantage_claim_is_supported_when_ci_includes_zero(self):   # records the honest outcome; if a future seed/world change excludes 0 this test must be revisited deliberately
        want = json.load(open(os.path.join(R, "research/spectra/results/probe_selection.json")))
        for n, (lo, hi) in want["paired_bootstrap_95ci_mean_probes_saved_by_active_vs"].items(): self.assertLessEqual(lo, 0 + 1e-9, n) if hi >= 0 else None; self.assertLessEqual(lo, hi)
    def test_ordered_strategy_follows_given_order(self):
        P = ["a", "b", "c"]; sysf = lambda p: [("fs", "x")] if p == "c" else []; h = [{p: frozenset() for p in P}, {**{p: frozenset() for p in P}, "c": frozenset({"fs"})}]
        v, d = T.infer(sysf, P, h, {p: () for p in P}, {"fs"}, strategy="ordered", order=["c", "a", "b"]); self.assertEqual((v, d["probes_used"]), ("DISCOVERED", 1))
        v, d = T.infer(sysf, P, h, {p: () for p in P}, {"fs"}, strategy="ordered", order=["a", "b", "c"]); self.assertEqual((v, d["probes_used"]), ("DISCOVERED", 3))
    def test_worlds_are_seeded_and_deterministic(self):
        a = C.make_world(random.Random(5)); b = C.make_world(random.Random(5)); self.assertEqual(a[0], b[0]); self.assertEqual(a[4], b[4])
    def test_budget_exhaustion_is_unknown_not_clean(self):
        rng = random.Random(1)
        for _ in range(50):
            probes, declared, graph, hyps, target = C.make_world(rng)
            v, _ = C.run("random", probes, declared, graph, hyps, 1)
            self.assertNotIn(v, ("BOUNDED_COVERAGE",))
if __name__ == "__main__": unittest.main()
