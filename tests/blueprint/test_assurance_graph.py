import os, sys, tempfile, unittest, importlib.util
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
spec = importlib.util.spec_from_file_location("assurance_graph", os.path.join(ROOT, "scripts", "assurance_graph.py")); AG = importlib.util.module_from_spec(spec); spec.loader.exec_module(AG)
def V(edges): return AG.violations({"edges": edges})
class Rules(unittest.TestCase):
    def test_cycle_is_caught(self): self.assertTrue(any(x.startswith("R1_CYCLE") for x in V({"horizon/a/x.py": ["horizon/a/y.py"], "horizon/a/y.py": ["horizon/a/x.py"]})))
    def test_acyclic_is_clean(self): self.assertEqual(V({"horizon/a/x.py": ["horizon/a/y.py"], "horizon/a/y.py": []}), [])
    def test_horizon_importing_research_is_caught(self): self.assertEqual(V({"horizon/effects/f.py": ["research/spectra/t.py"], "research/spectra/t.py": []}), ["R2:horizon/effects/f.py->research/spectra/t.py"])
    def test_sinkproc_importing_anything_is_caught(self): self.assertEqual(V({"horizon/effects/sinkproc.py": ["horizon/effects/ledger.py"], "horizon/effects/ledger.py": []}), ["R3:horizon/effects/sinkproc.py->horizon/effects/ledger.py"])
    def test_verifier_side_importing_effects_is_caught(self):
        self.assertEqual(V({"horizon/authz/effect.py": ["horizon/effects/ledger.py"], "horizon/effects/ledger.py": []}), ["R4:horizon/authz/effect.py->horizon/effects/ledger.py"])
        self.assertEqual(V({"horizon/ops/audience.py": ["horizon/forge/ir.py"], "horizon/forge/ir.py": []}), ["R4:horizon/ops/audience.py->horizon/forge/ir.py"])
    def test_coverage_importing_effects_is_caught(self): self.assertEqual(V({"horizon/coverage/s.py": ["horizon/assurance/d.py"], "horizon/assurance/d.py": []}), ["R5:horizon/coverage/s.py->horizon/assurance/d.py"])
    def test_allowed_downward_edge_is_clean(self): self.assertEqual(V({"horizon/effects/f.py": ["horizon/authz/g.py"], "horizon/authz/g.py": []}), [])
class Extraction(unittest.TestCase):
    def test_absolute_relative_and_package_imports_resolve(self):
        d = tempfile.mkdtemp()
        for p, s in {"horizon/p/__init__.py": "", "horizon/p/a.py": "from . import b\nfrom .c import f\nimport horizon.q.z\nimport json\n", "horizon/p/b.py": "", "horizon/p/c.py": "", "horizon/q/__init__.py": "", "horizon/q/z.py": ""}.items():
            os.makedirs(os.path.dirname(os.path.join(d, p)), exist_ok=True); open(os.path.join(d, p), "w").write(s)
        old = AG.ROOT; AG.ROOT = d
        try: self.assertEqual(sorted(AG._imports("horizon/p/a.py")), ["horizon/p/__init__.py", "horizon/p/b.py", "horizon/p/c.py", "horizon/q/z.py"])  # importing a package also runs its __init__
        finally: AG.ROOT = old
    def test_package_init_importing_its_siblings_is_not_a_self_edge(self):
        d = tempfile.mkdtemp()
        for p, t in {"horizon/p/__init__.py": "from . import b\n", "horizon/p/b.py": ""}.items():
            os.makedirs(os.path.dirname(os.path.join(d, p)), exist_ok=True); open(os.path.join(d, p), "w").write(t)
        old = AG.ROOT; AG.ROOT = d
        try: self.assertEqual(sorted(AG._imports("horizon/p/__init__.py")), ["horizon/p/b.py"])    # without the self-filter this is {__init__, b} and R1 reports a false cycle
        finally: AG.ROOT = old
class Real(unittest.TestCase):
    def test_committed_graph_is_current_and_clean(self): self.assertEqual(AG.main([]), 0)
    def test_real_graph_is_not_vacuous(self):
        g = AG.build(); E = g["edges"]
        self.assertIn("horizon/effects/filesink.py", E["horizon/effects/mcp_gateway.py"]); self.assertGreater(sum(len(v) for v in E.values()), 20); self.assertEqual(E["horizon/effects/sinkproc.py"], [])
if __name__ == "__main__": unittest.main()
