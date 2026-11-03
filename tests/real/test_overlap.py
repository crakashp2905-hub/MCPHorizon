import os, sys, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, ROOT)
from bench.real import overlap as O
class T(unittest.TestCase):
    def test_norm(self): self.assertEqual(O.norm("  A\n b\t C "), "a b c")
    def test_overlaps_counts_and_order(self):
        r = O.overlaps({"a": {"1", "2", "3"}, "b": {"2", "3", "4"}, "c": {"3"}, "d": {"9"}})
        self.assertEqual([(x["a"], x["b"], x["shared_strings"]) for x in r], [("a", "b", 2), ("a", "c", 1), ("b", "c", 1)])
        self.assertAlmostEqual(r[0]["frac_of_smaller"], 2 / 3); self.assertAlmostEqual(r[1]["frac_of_smaller"], 1.0)
    def test_no_overlap_is_empty(self): self.assertEqual(O.overlaps({"a": {"1"}, "b": {"2"}}), [])
    def test_min_length_enforced(self):
        import tempfile, json
        with tempfile.TemporaryDirectory() as d:
            json.dump(["short", "x" * O.MIN, "y" * (O.MIN - 1)], open(os.path.join(d, "a.json"), "w"))
            self.assertEqual(len(O.hashes(d)), 1)
    def test_case_and_space_insensitive_hashing(self):
        import tempfile, json
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            json.dump(["Hello   World " + "z" * O.MIN], open(os.path.join(a, "a.json"), "w")); json.dump(["hello world " + "Z" * O.MIN], open(os.path.join(b, "b.json"), "w"))
            self.assertEqual(O.hashes(a), O.hashes(b))
    def test_skips_trajectory_dirs(self):
        import tempfile, json
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "runs")); json.dump(["q" * 100], open(os.path.join(d, "runs", "a.json"), "w")); self.assertEqual(O.hashes(d), set())
if __name__ == "__main__": unittest.main()
