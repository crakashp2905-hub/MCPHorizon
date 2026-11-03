import ast, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import numpy as np
from research.weightspace import patch as P
B = dict(max_entries=4, max_l2=1.0, allowed_tensors={"mlp.w", "mlp.b"})
class T(unittest.TestCase):
    def setUp(self):
        r = np.random.default_rng(0); self.base = {"mlp.w": r.standard_normal((4, 4)).astype(np.float32), "mlp.b": np.zeros(4, np.float32), "emb": r.standard_normal(8).astype(np.float32), "ids": np.arange(3)}
        self.snap = {k: v.copy() for k, v in self.base.items()}; self.d = P.checkpoint_digest(self.base)
    def prop(self, edits, **k): return dict({"base_digest": self.d, "hypothesis": "trust-origin confusion (synthetic)", "edits": edits}, **k)
    def e(self, t="mlp.b", i=0, v=0.5): return {"tensor": t, "index": i, "value": v}
    def code(self, p, **b):
        with self.assertRaises(P.PatchError) as c: P.apply(self.base, p, **dict(B, **b))
        return c.exception.code
    def test_apply_is_copy_on_write_and_exact(self):
        c, m, inv = P.apply(self.base, self.prop([self.e(), self.e("mlp.w", 5, 0.1)]), **B)
        for k in self.base: np.testing.assert_array_equal(self.base[k], self.snap[k])
        self.assertEqual(float(c["mlp.b"][0]), 0.5); self.assertAlmostEqual(float(c["mlp.w"].flat[5]), 0.1, places=6); self.assertEqual(m["num_entries"], 2); self.assertEqual(m["status"], "CANDIDATE"); self.assertIsNone(m["authorized_by"])
    def test_inverse_restores_base_digest(self):
        c, m, inv = P.apply(self.base, self.prop([self.e(), self.e("mlp.w", 3, -0.2)]), **B); r, _, _ = P.apply(c, inv, **dict(B, max_l2=10)); self.assertEqual(P.checkpoint_digest(r), self.d)
    def test_manifest_verifies_and_detects_undeclared_change(self):
        p = self.prop([self.e()]); c, m, _ = P.apply(self.base, p, **B); self.assertTrue(P.verify_manifest(self.base, c, p, m))
        c["mlp.w"].flat[0] += 1; self.assertFalse(P.verify_manifest(self.base, c, p, m))
    def test_manifest_tamper_rejected(self):
        p = self.prop([self.e()]); c, m, _ = P.apply(self.base, p, **B); self.assertFalse(P.verify_manifest(self.base, c, p, dict(m, num_entries=9))); self.assertFalse(P.verify_manifest(self.base, c, p, dict(m, status="VERIFIED")))
    def test_patch_id_content_addressed(self):
        _, a, _ = P.apply(self.base, self.prop([self.e(v=0.5)]), **B); _, b, _ = P.apply(self.base, self.prop([self.e(v=0.6)]), **B); self.assertNotEqual(a["patch_id"], b["patch_id"]); self.assertNotEqual(a["delta_digest"], b["delta_digest"])
    def test_budget_entries(self): self.assertEqual(self.code(self.prop([self.e(i=i, v=0.01) for i in range(4)]), max_entries=3), "BUDGET_ENTRIES")
    def test_budget_norm(self): self.assertEqual(self.code(self.prop([self.e(v=2.0)])), "BUDGET_NORM")
    def test_norm_counts_delta_not_value(self):
        v = float(self.base["mlp.w"].flat[0]) + 0.5; P.apply(self.base, self.prop([self.e("mlp.w", 0, v)]), **dict(B, max_l2=0.6))
    def test_nonfinite_rejected(self):
        for v in (float("nan"), float("inf")): self.assertEqual(self.code(self.prop([self.e(v=v)])), "NONFINITE")
    def test_disallowed_and_unknown_tensor(self): self.assertEqual(self.code(self.prop([self.e("emb")])), "TENSOR_NOT_ALLOWED"); self.assertEqual(self.code(self.prop([self.e("nope")])), "TENSOR_NOT_ALLOWED")
    def test_index_bounds(self):
        for i in (-1, 4, True, 1.0): self.assertEqual(self.code(self.prop([self.e(i=i)])), "INDEX_OUT_OF_RANGE")
    def test_integer_tensor_rejected(self): self.assertEqual(self.code(self.prop([self.e("ids", 0, 1.0)]), allowed_tensors={"ids"}), "DTYPE")
    def test_duplicate_index(self): self.assertEqual(self.code(self.prop([self.e(), self.e(v=0.1)])), "DUPLICATE_INDEX")
    def test_base_mismatch(self): self.assertEqual(self.code(self.prop([self.e()], base_digest="0" * 64)), "BASE_MISMATCH")
    def test_malformed_and_empty(self):
        self.assertEqual(self.code(self.prop([])), "EMPTY"); self.assertEqual(self.code(self.prop([dict(self.e(), extra=1)])), "MALFORMED"); self.assertEqual(self.code(dict(self.prop([self.e()]), x=1)), "MALFORMED")
        self.assertEqual(self.code(self.prop([self.e()], hypothesis=" ")), "NO_HYPOTHESIS")
    def test_digest_sensitive_to_value_name_dtype_shape(self):
        b = dict(self.base); b["mlp.b"] = self.base["mlp.b"].astype(np.float64); self.assertNotEqual(P.checkpoint_digest(b), self.d)
        b = dict(self.base); b["mlp.b"] = self.base["mlp.b"].reshape(2, 2); self.assertNotEqual(P.checkpoint_digest(b), self.d)
        b = dict(self.base); b["mlp.b"] = self.base["mlp.b"].view(np.int32); self.assertNotEqual(P.checkpoint_digest(b), self.d)
        b = {("x" + k): v for k, v in self.base.items()}; self.assertNotEqual(P.checkpoint_digest(b), self.d)
    def test_gradient_free_arm_has_no_optimizer_imports(self):
        tree = ast.parse(open(P.__file__).read()); names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names} | {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        self.assertFalse(names & {"torch", "jax", "tensorflow", "optax"}, names)
    def test_kernel_does_not_import_research(self):
        import re; root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); bad = []
        for d, _, fs in os.walk(os.path.join(root, "horizon")):
            bad += [f for f in fs if f.endswith(".py") and re.search(r"^\s*(from|import)\s+research\b", open(os.path.join(d, f), encoding="utf-8", errors="ignore").read(), re.M)]
        self.assertEqual(bad, [])
if __name__ == "__main__": unittest.main()
