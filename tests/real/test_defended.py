"""Fixture tests (hand-written tiny runs) for the defended-vs-undefended comparison logic."""
import json, os, sys, tempfile, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, ROOT)
from bench.real import agentdojo as A, defended_runs as DR
from tests.real.test_agentdojo import mk

class T(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory(); r = self.r = self.t.name
        # base model m: 4 attacked runs, 2 attacks succeed; clean 2 runs, both utility
        for i, (u, s) in enumerate([(True, True), (False, True), (True, False), (True, False)]): mk(r, "m", "s", "u%d" % i, "important_instructions", "it%d" % i, "p", [], u, s)
        for i in range(2): mk(r, "m", "s", "c%d" % i, "none", "none", "p", [], True, False)
        # m-drift: 4 attacked, 0 succeed, 2 utility; clean 2 -> 1 utility
        for i, (u, s) in enumerate([(True, False), (True, False), (False, False), (False, False)]): mk(r, "m-drift", "s", "u%d" % i, "important_instructions", "it%d" % i, "p", [], u, s)
        for i, u in enumerate([True, False]): mk(r, "m-drift", "s", "c%d" % i, "none", "none", "p", [], u, False)
        # m-camel has no clean runs
        for i in range(2): mk(r, "m-camel", "s", "u%d" % i, "important_instructions", "it%d" % i, "p", [], False, False)
        mk(r, "z", "s", "c0", "none", "none", "p", [], True, False)   # clean-only pipeline: no row
        # a different attack must be ignored; an errored run must be ignored
        mk(r, "m", "s", "u9", "direct", "it9", "p", [], True, True)
        mk(r, "m", "s", "u8", "important_instructions", "it8", "p", [], True, True, error="x")
        self.rows = DR.table(list(A.iter_runs(r)))
    def tearDown(self): self.t.cleanup()
    def test_split(self):
        self.assertEqual(DR.split("gpt-4o-drift"), ("gpt-4o", "drift")); self.assertEqual(DR.split("gpt-4o"), ("gpt-4o", "none"))
        self.assertEqual(DR.split("a-b-spotlighting_with_delimiting"), ("a-b", "spotlighting_with_delimiting")); self.assertEqual(DR.split("drift-model"), ("drift-model", "none")); self.assertEqual(DR.split("xdrift"), ("xdrift", "none"))
    def test_table_counts(self):
        by = {(r["base_model"], r["defense"]): r for r in self.rows}
        m = by[("m", "none")]; self.assertEqual((m["asr"]["k"], m["asr"]["n"], m["utility_under_attack"]["k"], m["utility_clean"]["k"], m["utility_clean"]["n"]), (2, 4, 3, 2, 2))
        d = by[("m", "drift")]; self.assertEqual((d["asr"]["k"], d["utility_under_attack"]["k"], d["utility_clean"]["k"], d["utility_clean"]["n"]), (0, 2, 1, 2))
        self.assertIsNone(by[("m", "camel")]["utility_clean"])
    def test_clean_only_pipeline_has_no_row(self): self.assertNotIn("z", {r["base_model"] for r in self.rows})
    def test_paired_deltas(self):
        p = DR.paired(self.rows); self.assertAlmostEqual(p["drift"]["mean_asr_delta"], -0.5); self.assertAlmostEqual(p["drift"]["mean_utility_under_attack_delta"], 0.5 - 0.75); self.assertAlmostEqual(p["drift"]["mean_utility_clean_delta"], 0.5 - 1.0)
        self.assertIsNone(p["camel"]["mean_utility_clean_delta"]); self.assertNotIn("none", p)
    def test_paired_requires_matching_undefended_base(self):
        rows = [r for r in self.rows if not (r["base_model"] == "m" and r["defense"] == "none")]; self.assertEqual(DR.paired(rows), {})
    def test_pooled_sums_counts(self):
        p = DR.pooled(self.rows); self.assertEqual((p["none"]["asr"]["k"], p["none"]["asr"]["n"], p["drift"]["base_models"]), (2, 4, 1))
if __name__ == "__main__": unittest.main()
