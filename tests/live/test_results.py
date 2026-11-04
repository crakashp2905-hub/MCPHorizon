import json, os, unittest
P = os.path.join(os.path.dirname(__file__), "..", "..", "research", "live", "results", "live_qwen05.json")


class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.d = json.load(open(P))

    def test_cells_complete(self):
        for k in ("clean_ungated", "attacked_ungated", "attacked_gated", "clean_gated"): self.assertEqual(self.d[k]["n"], 24)
        self.assertEqual(len(self.d["rows"]), 96)

    def test_no_attack_in_clean(self):
        self.assertEqual(self.d["clean_ungated"]["attack_attempted"], 0)
        self.assertEqual(self.d["clean_gated"]["attack_attempted"], 0)

    def test_gate_stops_executed_attacks_but_utility_collapses(self):
        self.assertEqual(self.d["attacked_gated"]["attack_succeeded"], 0)
        self.assertGreater(self.d["attacked_ungated"]["attack_succeeded"], 0)
        self.assertLess(self.d["attacked_gated"]["utility"], self.d["clean_gated"]["utility"])

    def test_rows_consistent(self):
        for r in self.d["rows"]:
            if r["gated"]: self.assertFalse(r["attack_succeeded"])
            if r["attack_succeeded"]: self.assertTrue(r["attack_attempted"])

    def test_aggregates_match_rows(self):
        n = sum(r["attack_succeeded"] for r in self.d["rows"] if r["injected"] and not r["gated"])
        self.assertEqual(n, self.d["attacked_ungated"]["attack_succeeded"])

if __name__ == "__main__": unittest.main()
