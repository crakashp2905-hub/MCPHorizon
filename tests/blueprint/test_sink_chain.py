import json, os, sys, tempfile, unittest
R = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, R)
from horizon.effects.filesink import FileSink, SinkError
class Chain(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp()); self.root = os.path.join(self.d, "r"); self.j = os.path.join(self.d, "j.jsonl"); self.s = FileSink(self.root, self.j)
    def w(self, n): return self.s.write(os.path.join(self.root, f"f{n}"), b"x%d" % n, f"e{n}")
    def lines(self): return open(self.j).read().splitlines()
    def put(self, ls): open(self.j, "w").write("\n".join(ls) + ("\n" if ls else ""))
    def test_empty_and_growing_chain_verifies(self):
        self.assertEqual(self.s.verify_chain()[:2], (True, 0))
        for i in range(4): self.w(i)
        ok, n, h = self.s.verify_chain(); self.assertEqual((ok, n), (True, 4)); self.assertEqual(h, json.loads(self.lines()[-1])["h"])
    def test_fence_records_are_chained_too(self):
        self.w(0); self.s.fence_and_observe("e1"); self.w(2); ok, n, _ = self.s.verify_chain(); self.assertEqual((ok, n), (True, 3)); self.assertEqual(["fence" in json.loads(x) for x in self.lines()], [False, True, False])
        with self.assertRaises(SinkError): self.w(1)
    def test_editing_a_record_breaks_chain(self):
        for i in range(3): self.w(i)
        ls = self.lines(); r = json.loads(ls[1]); r["sha256"] = "0" * 64; ls[1] = json.dumps(r, sort_keys=True); self.put(ls); self.assertFalse(self.s.verify_chain()[0])
    def test_deleting_middle_record_breaks_chain(self):
        for i in range(3): self.w(i)
        ls = self.lines(); self.put([ls[0], ls[2]]); self.assertFalse(self.s.verify_chain()[0])
    def test_reordering_and_forged_hash_break_chain(self):
        for i in range(3): self.w(i)
        ls = self.lines(); self.put([ls[0], ls[2], ls[1]]); self.assertFalse(self.s.verify_chain()[0])
        r = json.loads(ls[1]); r["h"] = "f" * 64; self.put([ls[0], json.dumps(r), ls[2]]); self.assertFalse(self.s.verify_chain()[0])
    def test_delete_and_relink_prev_is_detected(self):        # attacker deletes a record and rewrites the next record's prev to bridge the gap
        for i in range(3): self.w(i)
        ls = self.lines(); r2 = json.loads(ls[2]); r2["prev"] = json.loads(ls[0])["h"]; self.put([ls[0], json.dumps(r2, sort_keys=True)]); self.assertFalse(self.s.verify_chain()[0])
    def test_unchained_legacy_record_rejected(self):
        self.put([json.dumps({"effect_id": "e0", "path": "p", "sha256": "0" * 64, "bytes": 1, "ts": 1})]); self.assertFalse(self.s.verify_chain()[0])
    def test_tail_truncation_not_detected_by_chain_but_by_anchor(self):
        for i in range(3): self.w(i)
        ok, n, h = self.s.verify_chain(); self.assertTrue(self.s.check_anchor(n, h)); self.put(self.lines()[:2])
        self.assertFalse(self.s.verify_chain()[0])                      # K2: the sink's own anchor now catches truncation without a caller-supplied anchor
        self.assertFalse(self.s.check_anchor(n, h))                     # external anchor catches rollback
    def test_anchor_rejects_wrong_head_and_overlong(self):
        for i in range(2): self.w(i)
        ok, n, h = self.s.verify_chain(); self.assertTrue(self.s.check_anchor(n, h)); self.assertFalse(self.s.check_anchor(n, "0" * 64)); self.assertFalse(self.s.check_anchor(n + 1, h)); self.assertTrue(self.s.check_anchor(1, json.loads(self.lines()[0])["h"]))
    def test_anchor_on_tampered_chain_false(self):
        for i in range(2): self.w(i)
        ok, n, h = self.s.verify_chain(); ls = self.lines(); r = json.loads(ls[0]); r["bytes"] = 99; self.put([json.dumps(r, sort_keys=True), ls[1]]); self.assertFalse(self.s.check_anchor(n, h))
    def test_anchor_zero_only_matches_empty_head(self):
        self.assertTrue(self.s.check_anchor(0, "0" * 64)); self.assertFalse(self.s.check_anchor(0, "1" * 64))
    def test_sink_anchor_detects_truncation_removal_corruption_and_outside_append(self):
        import os
        for i in range(3): self.w(i)
        full = self.lines(); self.assertEqual(self.s.verify_chain()[:2], (True, 3))
        for keep in (2, 1, 0): self.put(full[:keep]); self.assertFalse(self.s.verify_chain()[0], keep)
        self.put(full); self.assertTrue(self.s.verify_chain()[0])
        a = open(self.s.anchor).read(); os.remove(self.s.anchor); self.assertFalse(self.s.verify_chain()[0])           # journal content with no anchor cannot be vouched for
        open(self.s.anchor, "w").write("{not json"); self.assertFalse(self.s.verify_chain()[0]); open(self.s.anchor, "w").write(json.dumps({"n": 3, "head": "0" * 64})); self.assertFalse(self.s.verify_chain()[0])
        open(self.s.anchor, "w").write(a); self.assertTrue(self.s.verify_chain()[0])
        # a record appended by something other than the sink (anchor never saw it) is also refused
        self.s.journal, j = self.s.journal, self.s.journal; saved = self.s._write_anchor; self.s._write_anchor = lambda n, h: None
        try: self.w(9)
        finally: self.s._write_anchor = saved
        self.assertFalse(self.s.verify_chain()[0])
    def test_documented_limit_rewriting_journal_and_anchor_together_is_not_detected(self):
        for i in range(3): self.w(i)
        full = self.lines(); self.put(full[:2]); r = json.loads(full[1]); open(self.s.anchor, "w").write(json.dumps({"n": 2, "head": r["h"]}))
        self.assertTrue(self.s.verify_chain()[0])                       # honest limit: needs the anchor on a separate protected path or an external witness
if __name__ == "__main__": unittest.main()
