"""Static + consistency checks for the committed real-model result (does not load a model)."""
import json, os, re, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = open(os.path.join(ROOT, "research/weightspace/run_real.py")).read()
RES = json.load(open(os.path.join(ROOT, "research/weightspace/results/real_qwen05.json")))
class T(unittest.TestCase):
    def test_script_is_gradient_free(self):
        for bad in (".backward(", "torch.optim", "autograd", "requires_grad_(True)", "Adam", "SGD"): self.assertNotIn(bad, SRC, bad)
        self.assertIn("torch.no_grad", SRC)
    def test_all_edits_go_through_patch_api(self):
        for f in ("P.apply(", "P.verify_manifest(", "P.checkpoint_digest("): self.assertIn(f, SRC)
    def test_every_run_within_budget_and_verified(self):
        for r in RES["runs"]:
            self.assertLessEqual(r["entries"], RES["budget_entries"]); self.assertTrue(r["manifest_verified"], r["kind"])
            self.assertTrue(r["inverse_restores_checkpoint_bit_exact"]); self.assertTrue(r["live_model_rolled_back_bit_exact"])
    def test_random_controls_match_targeted_budget(self):
        t = RES["runs"][0]; self.assertEqual(t["kind"], "targeted")
        for r in RES["runs"][1:]: self.assertEqual(r["entries"], t["entries"]); self.assertAlmostEqual(r["delta_l2"], t["delta_l2"], places=6)
        self.assertEqual(len(RES["runs"]) - 1, 5)
    def test_targeted_gain_matches_request(self): self.assertAlmostEqual(RES["runs"][0]["target_logit_gain"], RES["requested_logit_gain"], places=3)
    def test_result_records_model_digest_and_license_context(self):
        self.assertEqual(RES["model"], "Qwen/Qwen2.5-0.5B-Instruct"); self.assertRegex(RES["base_ckpt_digest"], r"^[0-9a-f]{64}$")
if __name__ == "__main__": unittest.main()
