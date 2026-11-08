import json, os, random, sys, tempfile, unittest
R = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, R)
from research.spectra import compare as C, sensitivity as SE
RES = os.path.join(R, "research", "spectra", "results")
class Generator(unittest.TestCase):
    def test_default_generator_still_reproduces_the_committed_result(self): self.assertEqual(C.experiment(), json.load(open(os.path.join(RES, "probe_selection.json"))))
    def test_kind_weights_control_the_probe_kinds(self):
        probes = C.make_world(random.Random(1), 40, kind_weights={"net": 1, "file": 0, "proc": 0, "local": 0})[0]; self.assertEqual({p.split("_")[0] for p in probes}, {"net"})
    def test_target_bias_moves_the_hidden_effect_to_the_biased_kind(self):
        hits = 0; n = 0
        for s in range(300):
            probes, declared, graph, hyps, target = C.make_world(random.Random(s), 8, target_bias={"net": 1000, "file": 0.0001, "proc": 0.0001, "local": 0.0001})
            if target is None or not any(p.startswith("net") for p in probes): continue
            n += 1; hits += target.startswith("net")
        self.assertGreater(n, 50); self.assertEqual(hits, n)
class Mix(unittest.TestCase):
    def test_mix_sums_to_one_and_is_net_heavy_for_the_real_server_list(self):
        m = SE.mcptox_mix(); self.assertAlmostEqual(sum(m.values()), 1.0); self.assertGreater(m["net"], 0.5)
    def test_unmapped_server_is_an_error_not_silently_dropped(self):
        p = os.path.join(tempfile.mkdtemp(), "t.json"); json.dump([{"A_1": {"server_name": "Brand New Server"}}], open(p, "w"))
        with self.assertRaises(ValueError): SE.mcptox_mix(p)
    def test_every_real_server_is_mapped(self):
        d = json.load(open(os.path.join(R, "MCPTox", "pure_tool.json"))); self.assertLessEqual({v["server_name"] for e in d for v in e.values()}, set(SE.SERVER_KIND))
class Committed(unittest.TestCase):
    def test_committed_sensitivity_json_reproduces(self): self.assertEqual(SE.run(), json.load(open(os.path.join(RES, "sensitivity.json"))))
    def test_ci_flag_matches_the_intervals(self):
        for name, c in json.load(open(os.path.join(RES, "sensitivity.json")))["conditions"].items():
            self.assertEqual(c["ci_excludes_zero_in_favour_of_active"], sorted(k for k, (lo, hi) in c["active_saves_vs_95ci"].items() if lo > 0), name)
    def test_no_condition_shows_an_advantage_over_random(self):
        for name, c in json.load(open(os.path.join(RES, "sensitivity.json")))["conditions"].items(): self.assertNotIn("random", c["ci_excludes_zero_in_favour_of_active"], name)
if __name__ == "__main__": unittest.main()
