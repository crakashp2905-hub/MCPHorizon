import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from research.spectra import tomography as S
P = ["read", "summarize", "cancel", "retry", "reset", "delegate"]
DECL = {p: () for p in P} | {"delegate": ("queue",)}
def sysfrom(graph): return lambda probe: [(s, f"{probe}->{s}") for s in graph.get(probe, ())]
SAFE = {"delegate": ("queue",)}
HIDDEN_WRITE = {"delegate": ("queue",), "cancel": ("fs",)}            # side effect after cancellation to an instrumented sink
OFFHOST = {"delegate": ("queue",), "summarize": ("offhost",)}         # leak to a sink we cannot instrument
HYPS = [SAFE] + [dict(SAFE, **{p: (s,)}) for p in P if p != "delegate" for s in ("fs", "net", "offhost")]
INSTR = {"fs", "net", "queue"}
class T(unittest.TestCase):
    def test_discovers_hidden_write_with_sink_evidence(self):
        v, d = S.infer(sysfrom(HIDDEN_WRITE), P, HYPS, DECL, INSTR); self.assertEqual(v, "DISCOVERED"); self.assertEqual((d["probe"], d["undeclared_sinks"]), ("cancel", ["fs"])); self.assertIn(("fs", "cancel->fs"), d["evidence"])
    def test_blinded_witness_cannot_discover(self):   # SP-15
        v, _ = S.infer(sysfrom(HIDDEN_WRITE), P, HYPS, DECL, {"net", "queue"}); self.assertNotEqual(v, "DISCOVERED"); self.assertNotEqual(v, "BOUNDED_COVERAGE")
    def test_offhost_leak_is_unidentifiable_not_certified(self):
        v, d = S.infer(sysfrom(OFFHOST), P, HYPS, DECL, INSTR); self.assertEqual(v, "UNIDENTIFIABLE"); self.assertIn("offhost", sum(d["uninstrumented_effects_possible"].values(), []))
    def test_safe_system_is_also_unidentifiable_when_offhost_hypotheses_exist(self):   # identical observations to OFFHOST -> must not be certified
        a = S.infer(sysfrom(SAFE), P, HYPS, DECL, INSTR); b = S.infer(sysfrom(OFFHOST), P, HYPS, DECL, INSTR); self.assertEqual(a[0], b[0]); self.assertEqual(a[0], "UNIDENTIFIABLE")
    def test_bounded_coverage_only_when_class_has_no_hidden_alternatives(self):
        hyps = [SAFE] + [dict(SAFE, **{p: ("fs",)}) for p in P if p != "delegate"]; v, d = S.infer(sysfrom(SAFE), P, hyps, DECL, INSTR); self.assertEqual(v, "BOUNDED_COVERAGE"); self.assertIn("no claim outside", d["note"])
    def test_model_class_wrong_is_unknown(self):
        weird = lambda probe: [("net", "x")] if probe == "reset" else []; hyps = [SAFE]; decl = dict(DECL, reset=("net",)); v, _ = S.infer(weird, P, hyps, decl, INSTR); self.assertEqual(v, "UNKNOWN")
    def test_system_self_report_is_ignored(self):
        liar = lambda probe: [("fs", "x")] if probe == "retry" else []   # system "logs" nothing but really writes fs
        self.assertEqual(S.infer(liar, P, HYPS, DECL, INSTR)[0], "DISCOVERED")
    def test_budget_enforced(self):
        v, d = S.infer(sysfrom(SAFE), P, HYPS, DECL, INSTR, budget=2, strategy="random"); self.assertEqual(v, "UNKNOWN"); self.assertEqual(len(d["untried"]), 4)
        j = S.Journal(INSTR)
        with self.assertRaises(RuntimeError): S.run_probe(sysfrom(SAFE), "read", j, {"left": 0})
    def test_journal_ignores_uninstrumented_sinks(self):
        j = S.Journal({"fs"}); j.record("offhost", "x"); j.record("fs", "y"); self.assertEqual(j.rows, [("fs", "y")])
    def test_active_uses_no_more_probes_than_random_on_fixtures(self):   # fixture-only comparison, not a general efficiency claim
        tot_a = tot_r = 0
        for target in [dict(SAFE, **{p: ("fs",)}) for p in P if p != "delegate"] + [dict(SAFE, **{p: ("net",)}) for p in P if p != "delegate"]:
            tot_a += S.infer(sysfrom(target), P, HYPS, DECL, INSTR)[1]["probes_used"]
            tot_r += sum(S.infer(sysfrom(target), P, HYPS, DECL, INSTR, strategy="random", seed=s)[1]["probes_used"] for s in range(20)) / 20
        self.assertLessEqual(tot_a, tot_r)
    def test_early_single_hypothesis_does_not_certify_untried_probes(self):   # regression: found during development
        weird = lambda probe: [("net", "x")] if probe == "reset" else []; v, _ = S.infer(weird, P, [SAFE, dict(SAFE, read=("fs",))], DECL, INSTR); self.assertEqual(v, "DISCOVERED")
    def test_deterministic(self): self.assertEqual(S.infer(sysfrom(OFFHOST), P, HYPS, DECL, INSTR), S.infer(sysfrom(OFFHOST), P, HYPS, DECL, INSTR))
if __name__ == "__main__": unittest.main()
