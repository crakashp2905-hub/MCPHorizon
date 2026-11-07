import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from horizon.forge import checker, pareto
from horizon.forge.ir import Task, Plan, CONTROLS, WITNESSES
ALL_C, ALL_W = tuple(CONTROLS), tuple(WITNESSES)
def T(**k):
    d = dict(data_label="SECRET", aggregate_ok=True, remote_trust="opaque", available_controls=ALL_C, available_witnesses=ALL_W); d.update(k); return Task(**d)

class Floor(unittest.TestCase):
    def test_floor0_with_no_controls_is_not_certifiable_and_denial_is_not_a_solution(self):
        t = T(available_controls=(), available_witnesses=())
        r = pareto.solve_with_floor(t, 0)
        self.assertEqual(r["result"], "NOT_CERTIFIABLE_UNDER_FLOOR"); self.assertFalse(r["deny_all"]["is_solution"]); self.assertEqual(r["deny_all"]["utility_loss"], pareto.FULL_LOSS)
        self.assertNotIn("plan", r); self.assertGreater(r["feasible_without_floor"], 0)
    def test_floor1_accepts_degraded_aggregate(self):
        t = T(available_controls=(), available_witnesses=())
        r = pareto.solve_with_floor(t, 1); self.assertEqual(r["result"], "FEASIBLE_AT_FLOOR"); self.assertEqual(r["plan"].form, "aggregate"); self.assertTrue(checker.check(t, r["plan"]))
    def test_floor0_picks_zero_loss_min_cost(self):
        t = T(); r = pareto.solve_with_floor(t, 0); self.assertEqual(r["utility_loss"], 0)
        self.assertEqual(r["cost"], min(p.cost() for p in pareto.feasible(t) if p.form == "raw"))
    def test_no_feasible_at_all(self):
        t = T(aggregate_ok=False, available_controls=("egress_contract_enforcer",))
        r = pareto.solve_with_floor(t, 1); self.assertEqual(r["result"], "NOT_CERTIFIABLE_UNDER_FLOOR"); self.assertEqual(r["feasible_without_floor"], 0)
    def test_bad_floor_rejected(self):
        for f in (-1, 2, True, "0", None):
            with self.assertRaises(ValueError): pareto.solve_with_floor(T(), f)
    def test_never_returns_plan_checker_rejects(self):
        for kw in ({}, dict(remote_trust="contracted"), dict(data_label="PUBLIC"), dict(aggregate_ok=False), dict(available_controls=("local_sandbox",))):
            t = T(**kw)
            for fl in (0, 1):
                r = pareto.solve_with_floor(t, fl)
                if "plan" in r: self.assertTrue(checker.check(t, r["plan"]))

class Frontier(unittest.TestCase):
    CASES = [{}, dict(remote_trust="contracted"), dict(data_label="PUBLIC"), dict(aggregate_ok=False), dict(available_controls=("local_sandbox",)), dict(available_controls=(), available_witnesses=()), dict(need_effect_witness=True)]
    def test_independent_verifier_accepts_frontier(self):
        for kw in self.CASES:
            t = T(**kw); self.assertTrue(pareto.verify_frontier(t, pareto.frontier(t)), kw)
    def test_frontier_is_nondominated_and_sorted_by_cost(self):
        t = T(); f = pareto.frontier(t); pts = [k for k, _ in f]
        self.assertEqual(pts, sorted(pts)); self.assertTrue(all(pts[i][1] > pts[i + 1][1] for i in range(len(pts) - 1)))
    def test_has_tradeoff_point_when_aggregate_cheaper(self):
        f = pareto.frontier(T()); self.assertGreaterEqual(len(f), 2)
        self.assertEqual({k[1] for k, _ in f}, {0, 1})
    def test_verifier_rejects_dominated_extra_point(self):
        t = T(); f = pareto.frontier(t); worse = Plan("remote", "aggregate", ("local_sandbox", "enclave_attestation"), ("network_tap",))
        self.assertTrue(checker.check(t, worse)); self.assertFalse(pareto.verify_frontier(t, f + [((worse.cost(), 1), worse)]))
    def test_verifier_rejects_missing_point(self):
        t = T(); f = pareto.frontier(t); self.assertGreaterEqual(len(f), 2); self.assertFalse(pareto.verify_frontier(t, f[:-1])); self.assertFalse(pareto.verify_frontier(t, f[1:]))
    def test_verifier_rejects_inadmissible_plan_and_wrong_label(self):
        t = T(available_controls=()); bad = Plan("local_sandbox", "raw", ("local_sandbox",), ())
        self.assertFalse(pareto.verify_frontier(t, [((bad.cost(), 0), bad)]))
        f = pareto.frontier(T()); k, p = f[0]; self.assertFalse(pareto.verify_frontier(T(), [((k[0], k[1] + 1), p)] + f[1:]))
    def test_verifier_rejects_duplicate_points(self):
        t = T(); f = pareto.frontier(t); self.assertFalse(pareto.verify_frontier(t, f + [f[0]]))
    def test_empty_frontier_only_when_nothing_feasible(self):
        t = T(aggregate_ok=False, available_controls=("egress_contract_enforcer",)); self.assertEqual(pareto.frontier(t), []); self.assertTrue(pareto.verify_frontier(t, []))
        self.assertFalse(pareto.verify_frontier(T(), []))
    def test_deterministic(self):
        self.assertEqual(pareto.frontier(T()), pareto.frontier(T()))
if __name__ == "__main__": unittest.main()
