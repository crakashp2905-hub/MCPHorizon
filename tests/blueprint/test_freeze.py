import copy, json, os, shutil, sys, tempfile, unittest, importlib.util
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
spec = importlib.util.spec_from_file_location("experiment_freeze", os.path.join(ROOT, "scripts", "experiment_freeze.py")); F = importlib.util.module_from_spec(spec); spec.loader.exec_module(F)
class Freeze(unittest.TestCase):
    @unittest.skipIf(os.environ.get("MUTATION_RUN"), "file-hash consistency would kill every mutant of a frozen file")
    def test_committed_manifest_matches_the_tree(self): self.assertEqual(F.main([]), 0)
    def test_manifest_covers_the_key_files(self):
        m = json.load(open(F.OUT))["files"]
        for f in ("horizon/effects/filesink.py", "horizon/effects/sinkproc.py", "horizon/assurance/durable.py", "horizon/authz/effect.py", "horizon/forge/pareto.py", "tests/blueprint/test_freeze.py", "research/spectra/results/probe_selection.json"): self.assertIn(f, m)
    def _m(self): return F.build()   # fresh from the tree: these tests tamper with it, and must not depend on the committed manifest being current
    def test_changed_file_hash_is_reported(self):
        m = self._m(); f = "horizon/forge/pareto.py"; m["files"][f] = "0" * 64; m["manifest_sha256"] = F.manifest_hash(m); self.assertEqual(F.problems(m), ["CHANGED:" + f])
    def test_edited_manifest_without_rehash_is_reported(self):
        m = self._m(); f = "horizon/forge/pareto.py"; m["files"][f] = "0" * 64; self.assertIn("MANIFEST_HASH", F.problems(m))
    def test_scope_edit_is_reported(self):
        m = self._m(); m["scope"] = "everything is trusted"; m["scope_sha256"] = __import__("hashlib").sha256(m["scope"].encode()).hexdigest(); m["manifest_sha256"] = F.manifest_hash(m); self.assertIn("SCOPE_CHANGED", F.problems(m))
    def test_new_unfrozen_file_in_scope_is_reported(self):
        m = self._m(); gone = "horizon/effects/ledger.py"; del m["files"][gone]; m["manifest_sha256"] = F.manifest_hash(m); self.assertEqual(F.problems(m), ["UNFROZEN_NEW:" + gone])
    def test_missing_file_is_reported(self):
        m = self._m(); m["files"]["horizon/effects/nope.py"] = "0" * 64; m["manifest_sha256"] = F.manifest_hash(m); self.assertIn("MISSING:horizon/effects/nope.py", F.problems(m))
    def test_llm_import_detected_by_ast_not_text(self):
        d = tempfile.mkdtemp(); open(os.path.join(d, "a.py"), "w").write("import anthropic\nfrom openai.types import X\nimport json\n"); open(os.path.join(d, "b.py"), "w").write("# import anthropic\ns = 'import openai'\nfrom . import anthropic_like\nfrom .anthropic import Y\nfrom ..openai import Z\nimport anthropics_not\n")
        self.assertEqual(F.llm_imports(["a.py", "b.py"], d), ["a.py:anthropic", "a.py:openai.types"]); shutil.rmtree(d)
    def test_real_frozen_code_calls_no_llm(self): self.assertEqual(F.llm_imports(F.frozen_files()), [])
if __name__ == "__main__": unittest.main()
