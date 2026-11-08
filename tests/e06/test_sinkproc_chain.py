import os, sys, tempfile, time, unittest, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from horizon.effects import sinkproc as S
SINK, GW = 2, 1
def _retry(sock, req):
    for _ in range(40):
        r = S.call(sock, req, as_uid=GW)
        if r.get("code") != "CLIENT_ERROR": return r
        time.sleep(0.05)
    return r
@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0, "needs root to switch uids")
class Chain(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); os.chmod(self.d, 0o755); self.proc, self.sock, self.data, self.jr = S.start_sink(self.d, SINK, GW)
    def tearDown(self):
        try: S.call(self.sock, {"op": "stop"}, as_uid=GW); self.proc.wait(timeout=10)
        except Exception: self.proc.kill()
    def _write(self, name, eid): return S.call(self.sock, S.write_req(os.path.join(self.data, name), b"x" + name.encode(), eid), as_uid=GW)
    def test_journal_is_chained_and_matches_live_head(self):
        self._write("a.txt", "e1"); S.call(self.sock, S.fence_req("e2"), as_uid=GW); self._write("b.txt", "e3")
        ok, n, h = S.verify_journal(self.jr); self.assertTrue(ok); self.assertEqual(n, 3)
        live = S.call(self.sock, S.head_req(), as_uid=GW); self.assertEqual((live["n"], live["head"]), (n, h))
    def test_edit_of_a_record_is_detected_offline(self):
        self._write("a.txt", "e1"); self._write("b.txt", "e3")
        L = open(self.jr).read().splitlines(); r = json.loads(L[0]); r["sha256"] = "0" * 64; L[0] = json.dumps(r, sort_keys=True); open(self.jr, "w").write("\n".join(L) + "\n")
        self.assertFalse(S.verify_journal(self.jr)[0])
    def test_editing_only_the_prev_field_is_detected(self):   # prev is not part of the hash input, so the explicit prev check is what catches this
        self._write("a.txt", "e1"); self._write("b.txt", "e2")
        L = open(self.jr).read().splitlines(); r = json.loads(L[1]); r["prev"] = "f" * 64; L[1] = json.dumps(r, sort_keys=True); open(self.jr, "w").write("\n".join(L) + "\n")
        self.assertFalse(S.verify_journal(self.jr)[0])
    def test_editing_only_the_prev_field_stops_a_restarted_sink(self):
        self._write("a.txt", "e1"); S.call(self.sock, {"op": "stop"}, as_uid=GW); self.proc.wait(timeout=10)
        r = json.loads(open(self.jr).read().splitlines()[0]); r["prev"] = "f" * 64; open(self.jr, "w").write(json.dumps(r, sort_keys=True) + "\n")
        os.unlink(self.sock + ".ready"); self.proc, self.sock, self.data, self.jr = S.start_sink(self.d, SINK, GW)
        self.assertEqual(_retry(self.sock, S.fence_req("x"))["code"], "JOURNAL_TAMPERED")
    def test_deleted_middle_record_is_detected(self):
        for i in range(3): self._write("f%d.txt" % i, "e%d" % i)
        L = open(self.jr).read().splitlines(); del L[1]; open(self.jr, "w").write("\n".join(L) + "\n")
        self.assertFalse(S.verify_journal(self.jr)[0])
    def test_unchained_legacy_line_is_rejected(self):
        open(self.jr, "a").write(json.dumps({"effect_id": "forged", "path": "/x"}) + "\n"); self.assertFalse(S.verify_journal(self.jr)[0])
    def test_tail_truncation_is_not_detected_by_chain_alone_but_by_anchor(self):
        for i in range(3): self._write("t%d.txt" % i, "e%d" % i)
        anchor = S.call(self.sock, S.head_req(), as_uid=GW)
        L = open(self.jr).read().splitlines(); open(self.jr, "w").write("\n".join(L[:2]) + "\n")
        ok, n, h = S.verify_journal(self.jr); self.assertTrue(ok)                          # documented limit: the chain alone still verifies
        self.assertNotEqual((n, h), (anchor["n"], anchor["head"]))                          # the external anchor exposes it
    def test_tampered_journal_makes_restarted_sink_fail_closed(self):
        self._write("a.txt", "e1"); S.call(self.sock, {"op": "stop"}, as_uid=GW); self.proc.wait(timeout=10)
        r = json.loads(open(self.jr).read().splitlines()[0]); r["path"] = "/etc/evil"; open(self.jr, "w").write(json.dumps(r, sort_keys=True) + "\n")
        os.unlink(self.sock + ".ready"); self.proc, self.sock, self.data, self.jr = S.start_sink(self.d, SINK, GW)
        self.assertEqual(_retry(self.sock, self._wr("b.txt", "e9"))["code"], "JOURNAL_TAMPERED")
        self.assertEqual(_retry(self.sock, S.fence_req("e9"))["code"], "JOURNAL_TAMPERED"); self.assertFalse(os.path.exists(os.path.join(self.data, "b.txt")))
    def _wr(self, name, eid): return S.write_req(os.path.join(self.data, name), b"y", eid)
    def test_chain_continues_across_restart(self):
        self._write("a.txt", "e1"); S.call(self.sock, {"op": "stop"}, as_uid=GW); self.proc.wait(timeout=10)
        os.unlink(self.sock + ".ready"); self.proc, self.sock, self.data, self.jr = S.start_sink(self.d, SINK, GW)
        self.assertTrue(_retry(self.sock, self._wr("b.txt", "e2"))["ok"]); ok, n, _ = S.verify_journal(self.jr); self.assertTrue(ok); self.assertEqual(n, 2)
if __name__ == "__main__": unittest.main()
