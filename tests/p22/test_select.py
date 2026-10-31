import json, subprocess, sys, unittest
from horizon.select import selective as S
from bench.p22 import run as R


class T(unittest.TestCase):
    def test_prefilter(self):
        self.assertEqual(S.prefilter(set())["decision"], "ALLOW"); self.assertEqual(S.prefilter({"policy_denied", "unknown_target"})["decision"], "DENY")
        r = S.prefilter({"unknown_target", "stale_policy"}); self.assertEqual((r["decision"], r["prior"]), ("REVIEW", round(1 - .65 * .9, 4)))
        self.assertEqual(S.prefilter({"mystery"})["reason"], "UNKNOWN_UNCERTAINTY_TAG")        # fail closed on tags outside the taxonomy
    def test_verifier_can_only_restrict(self):
        rev = S.prefilter({"unknown_target"})
        self.assertEqual(S.combine(rev, 0.0, 0.5)["decision"], "REVIEW"); self.assertEqual(S.combine(rev, 0.99, 0.5)["decision"], "DENY"); self.assertEqual(S.combine(rev, None, 0.5)["decision"], "REVIEW")
        for score in (0.0, 0.5, 1.0): self.assertEqual(S.combine(S.prefilter({"policy_denied"}), score, 0.5)["decision"], "DENY"); self.assertEqual(S.combine(S.prefilter(set()), score, 0.5)["decision"], "ALLOW")      # hard-deny precedence; clean stays clean (no verifier call)
        self.assertEqual(S.combine(rev, 0.5, 0.5)["decision"], "DENY")      # boundary is inclusive
    def test_schedule_picks_highest_prior_within_budget_deterministically(self):
        p = [(1, .1), (2, .9), (3, .5), (4, .5)]; self.assertEqual(S.schedule(p, 2), {2, 4}); self.assertEqual(S.schedule(p, 0), set()); self.assertEqual(S.schedule(p, 10), {1, 2, 3, 4})
    def test_calibration(self):
        c = S.calibration([.9, .9, .1, .1], [1, 1, 0, 0]); self.assertAlmostEqual(c["ece"], .1, places=3); self.assertEqual(S.calibration([.5, .5], [1, 0])["ece"], 0.0)
    def test_simulation_is_deterministic_and_never_allows_harm_via_verifier(self):
        a = R.cases(500, 1); self.assertEqual([c["score"] for c in a], [c["score"] for c in R.cases(500, 1)])
        for pol in ("never", "always", "threshold", "selective"):
            m = R.evaluate(a, pol, 0.0, 0.0, 1.0)          # tau=0 => verifier denies everything it sees
            self.assertLessEqual(m["harm_landed_rate"], R.evaluate(a, "never", 1.01)["harm_landed_rate"] + 1e-9, pol)
    def test_never_has_zero_verifier_cost(self):
        m = R.evaluate(R.cases(300, 2), "never", 0.5); self.assertEqual((m["verifier_calls"], m["tokens"], m["usd"]), (0, 0, 0))
    def test_budget_respected(self):
        cs = R.cases(1000, 3); m = R.evaluate(cs, "selective", .5, 0.0, .05); self.assertLessEqual(m["verifier_calls"], 50)
    def test_auc(self): self.assertEqual(R.auc([.9, .8, .2, .1], [1, 1, 0, 0]), 1.0); self.assertEqual(R.auc([.1, .2, .8, .9], [1, 1, 0, 0]), 0.0)
    def test_results_and_drift_alarm_uses_auc_not_ece(self):
        d = json.load(open("results/v2/p22-selective/result.json")); self.assertTrue(d["drift_alarm"]); self.assertLess(d["calibration_drifted"], d["calibration_test"]); self.assertLess(d["auc_drifted"], d["auc_test"])
        for t, rows in d["targets"].items():
            for p, m in rows.items(): self.assertTrue(m["target_met_on_test"] or p == "never", (t, p))
        self.assertFalse(d["targets"]["0.01"]["never"]["target_met_on_test"])
    def test_generated_docs_current(self):
        for s in ("paper_tables.py", "coverage_matrix.py", "go_nogo.py"):
            r = subprocess.run([sys.executable, f"scripts/{s}", "--check"], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
    def test_go_nogo_never_claims_unmet_gate(self):
        t = open("docs/evidence/GO_NO_GO.md").read(); self.assertIn("NO-GO", t); self.assertNotIn("VERIFIED", t.replace("any VERIFIED claim", "").replace("claimed VERIFIED", ""))
        for g in ("GX1", "GX4", "GX8", "GX9"): self.assertIn(f"| {g}", t); self.assertRegex(t, rf"\| {g}[^|]*\| NOT MET")


if __name__ == "__main__": unittest.main()
