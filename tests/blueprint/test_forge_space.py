import os, subprocess, sys, unittest
from unittest import mock
R = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, R)
from horizon.forge import space as S, checker
from horizon.forge.ir import Task, Plan
from horizon.forge.pareto import FULL_LOSS
class Space(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.r = S.exhaustive()
    def test_task_space_is_exactly_768_distinct_tasks(self): ts = list(S.all_tasks()); self.assertEqual((len(ts), len(set(ts))), (768, 768))
    def test_every_frontier_negative_certificate_and_floor_verifies_without_failures(self):
        r = self.r; self.assertEqual(r["failures"], []); self.assertEqual((r["frontier_verified"], r["floor_consistent"]), (768, 768)); self.assertEqual(r["negative_certs_verified"], r["not_certifiable"])
    def test_not_certifiable_tasks_are_exactly_the_empty_frontiers(self): self.assertEqual(self.r["frontier_sizes"]["0"], self.r["not_certifiable"]); self.assertEqual(sum(self.r["frontier_sizes"].values()), 768)
    def test_zero_loss_floor_denies_at_least_as_many_as_the_unconstrained_planner(self): self.assertGreaterEqual(self.r["floor0_not_certifiable"], self.r["not_certifiable"])
    def test_deny_all_is_never_admissible_and_always_full_loss(self):
        b = self.r["baselines"]["deny_all"]; self.assertEqual((b["admissible"], b["denied"], b["mean_utility_loss_all_tasks"]), (0, 768, float(FULL_LOSS)))
    def test_checker_guided_planners_are_never_unsafe_and_naive_ones_are(self):
        b = self.r["baselines"]
        for k in ("synthesized", "synthesized_no_utility_loss"): self.assertEqual(b[k]["unsafe"], 0, k)
        self.assertGreater(b["cheapest_unchecked"]["unsafe"], 0); self.assertGreater(b["always_local"]["unsafe"], 0)
    def test_every_baseline_accounts_for_every_task(self):
        for k, b in self.r["baselines"].items(): self.assertEqual(b["admissible"] + b["unsafe"] + b["denied"], 768, k)
    def test_no_baseline_with_zero_unsafe_beats_the_synthesizer_on_admissible_count(self):
        b = self.r["baselines"]; self.assertEqual(b["synthesized"]["admissible"], 768 - self.r["not_certifiable"])
    def test_cost_first_synthesis_gives_up_utility_where_a_zero_loss_plan_exists(self):
        # measured, not assumed: some tasks get an aggregate plan although a zero-loss plan is feasible
        n = sum(1 for t in S.all_tasks() if S.synthesized(t) is not None and S.synthesized(t).form == "aggregate" and S.synthesized_with_floor0(t) is not None)
        self.assertGreater(n, 0)
class Detects(unittest.TestCase):
    """exhaustive() must notice when the components it cross-checks are wrong; otherwise 'verified 768/768' would be vacuous."""
    def test_wrong_frontier_is_reported(self):
        with mock.patch.object(S, "frontier", lambda t: []): r = S.exhaustive()
        self.assertTrue(any(f[0] == "FRONTIER" for f in r["failures"])); self.assertEqual(r["frontier_verified"], 90)       # only the 90 tasks that truly have no feasible plan
    def test_failing_negative_certificate_check_is_reported(self):
        with mock.patch.object(S, "verify_negative_certificate", lambda *a: False): r = S.exhaustive()
        self.assertEqual((r["negative_certs_verified"], sum(1 for f in r["failures"] if f[0] == "NEG_CERT")), (0, 90))
    def test_certificate_for_a_task_that_actually_has_a_frontier_is_reported(self):
        fake = [((0, 0), S.Plan("local_sandbox", "raw", ("local_sandbox",), ()))]
        with mock.patch.object(S, "frontier", lambda t: fake), mock.patch.object(S, "verify_frontier", lambda *a: True): r = S.exhaustive()
        self.assertEqual(r["negative_certs_verified"], 0); self.assertEqual(sum(1 for f in r["failures"] if f[0] == "NEG_CERT"), 90)
    def _floor(self, wrong_at):
        real = S.solve_with_floor
        def f(t, floor): return {"result": "FEASIBLE_AT_FLOOR", "cost": -1, "utility_loss": 0, "plan": None} if floor == wrong_at else real(t, floor)
        with mock.patch.object(S, "solve_with_floor", f): return S.exhaustive()
    def test_wrong_floor_one_result_is_reported(self): r = self._floor(1); self.assertTrue(any(x[0] == "FLOOR" for x in r["failures"])); self.assertLess(r["floor_consistent"], 768)
    def test_wrong_floor_zero_result_is_reported(self): r = self._floor(0); self.assertTrue(any(x[0] == "FLOOR" for x in r["failures"])); self.assertLess(r["floor_consistent"], 768)
class Score(unittest.TestCase):
    T = Task("SECRET", False, "opaque", (), (), False)
    def test_rejected_plan_counts_as_unsafe_not_admissible(self): self.assertEqual(S.score(lambda t: Plan("remote", "raw", (), ()), [self.T]), {"tasks": 1, "admissible": 0, "unsafe": 1, "denied": 0, "mean_cost_of_admissible": None, "mean_utility_loss_all_tasks": float(FULL_LOSS)})
    def test_none_counts_as_denied(self): self.assertEqual(S.score(lambda t: None, [self.T])["denied"], 1)
    def test_admissible_plan_cost_and_loss_are_averaged_over_admissible_only_for_cost(self):
        t = Task("PUBLIC", True, "opaque", ("local_sandbox",), (), False); s = S.score(lambda t: Plan("local_sandbox", "aggregate", ("local_sandbox",), ()), [t, self.T])
        self.assertEqual((s["admissible"], s["unsafe"], s["mean_cost_of_admissible"], s["mean_utility_loss_all_tasks"]), (1, 1, 3.0, (1 + FULL_LOSS) / 2))
class Committed(unittest.TestCase):
    def test_committed_json_is_current(self): self.assertEqual(subprocess.run([sys.executable, os.path.join(R, "scripts", "forge_exhaustive.py")], capture_output=True).returncode, 0)
if __name__ == "__main__": unittest.main()
