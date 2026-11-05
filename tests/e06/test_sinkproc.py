import os, subprocess, sys, tempfile, unittest, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from horizon.effects import sinkproc as S
SINK, GW, AGENT = 2, 1, 65534      # bin, daemon, nobody
@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0, "needs root to switch uids")
class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(); os.chmod(cls.d, 0o755); cls.proc, cls.sock, cls.data, cls.jr = S.start_sink(cls.d, SINK, GW)
    @classmethod
    def tearDownClass(cls):
        S.call(cls.sock, {"op": "stop"}, as_uid=GW); cls.proc.wait(timeout=10)
    def as_agent(self, code):
        def demote(): os.setgid(AGENT); os.setuid(AGENT)
        return subprocess.run([sys.executable, "-B", "-c", code], preexec_fn=demote, capture_output=True, timeout=20)
    def test_agent_cannot_write_data_dir_directly(self):
        r = self.as_agent(f"open({os.path.join(self.data, 'x.txt')!r}, 'w').write('TEST_CANARY_NOT_SECRET')"); self.assertNotEqual(r.returncode, 0); self.assertIn(b"PermissionError", r.stderr); self.assertFalse(os.path.exists(os.path.join(self.data, "x.txt")))
    def test_agent_cannot_list_or_read_data_dir(self):
        self.assertNotEqual(self.as_agent(f"import os; os.listdir({self.data!r})").returncode, 0)
    def test_agent_cannot_tamper_journal(self):
        self.assertNotEqual(self.as_agent(f"open({self.jr!r}, 'a').write('x')").returncode, 0)
    def test_agent_via_socket_is_refused_and_nothing_written(self):
        r = S.call(self.sock, S.write_req(os.path.join(self.data, "y.txt"), b"x", "e-agent"), as_uid=AGENT); self.assertEqual(r["code"], "PEER_NOT_GATEWAY")
        self.assertFalse(os.path.exists(os.path.join(self.data, "y.txt"))); self.assertNotIn("e-agent", open(self.jr).read())
    def test_root_gateway_uid_mismatch_refused(self):   # even root (uid 0) is not the configured gateway uid
        self.assertEqual(S.call(self.sock, S.write_req(os.path.join(self.data, "z.txt"), b"x", "e-root"))["code"], "PEER_NOT_GATEWAY")
    def test_gateway_write_succeeds_with_peer_uid_in_receipt(self):
        r = S.call(self.sock, S.write_req(os.path.join(self.data, "ok.txt"), b"hello", "e-ok"), as_uid=GW); self.assertTrue(r["ok"], r); self.assertEqual(r["receipt"]["uid_peer"], GW)
        st = os.stat(os.path.join(self.data, "ok.txt")); self.assertEqual(st.st_uid, SINK); self.assertEqual(open(os.path.join(self.data, "ok.txt"), "rb").read(), b"hello"); self.assertIn("e-ok", open(self.jr).read())
    def test_gateway_traversal_blocked_by_sink(self):
        r = S.call(self.sock, S.write_req(os.path.join(self.data, "..", "esc.txt"), b"x", "e-esc"), as_uid=GW); self.assertEqual(r["code"], "OUTSIDE_ROOT"); self.assertFalse(os.path.exists(os.path.join(self.d, "esc.txt")))
    def test_gateway_symlink_escape_blocked(self):
        outside = tempfile.mkdtemp(); os.chmod(outside, 0o777); subprocess.run(["ln", "-s", outside, os.path.join(self.data, "lnk")], preexec_fn=lambda: (os.setgid(SINK), os.setuid(SINK)), check=True)
        r = S.call(self.sock, S.write_req(os.path.join(self.data, "lnk", "s.txt"), b"x", "e-sym"), as_uid=GW); self.assertEqual(r["code"], "OUTSIDE_ROOT"); self.assertFalse(os.path.exists(os.path.join(outside, "s.txt")))
    def test_directory_target_blocked(self):
        self.assertEqual(S.call(self.sock, S.write_req(self.data, b"x", "e-dir"), as_uid=GW)["code"], "OUTSIDE_ROOT")
    def test_malformed_request_does_not_kill_sink(self):
        r = S.call(self.sock, {"op": "write"}, as_uid=GW); self.assertFalse(r["ok"]); self.assertTrue(S.call(self.sock, S.write_req(os.path.join(self.data, "after.txt"), b"1", "e-after"), as_uid=GW)["ok"])
    # ---- fence-and-observe at the OS-separated sink (model: research/commitproof)
    def test_fence_refuses_later_write_and_reports_prior_record(self):
        p = os.path.join(self.data, "f1.txt")
        self.assertIsNone(S.call(self.sock, S.fence_req("e-f1"), as_uid=GW)["observed"])
        r = S.call(self.sock, S.write_req(p, b"late", "e-f1"), as_uid=GW); self.assertEqual(r["code"], "FENCED"); self.assertFalse(os.path.exists(p))
        self.assertIn('"fence": "e-f1"', open(self.jr).read())
    def test_fence_after_write_returns_the_receipt(self):
        p = os.path.join(self.data, "f2.txt"); S.call(self.sock, S.write_req(p, b"x", "e-f2"), as_uid=GW)
        o = S.call(self.sock, S.fence_req("e-f2"), as_uid=GW)["observed"]; self.assertEqual(o["effect_id"], "e-f2"); self.assertEqual(S.call(self.sock, S.write_req(p, b"y", "e-f2"), as_uid=GW)["code"], "FENCED")
        self.assertEqual(open(p, "rb").read(), b"x")
    def test_duplicate_effect_id_refused_by_sink(self):
        p = os.path.join(self.data, "f3.txt"); self.assertTrue(S.call(self.sock, S.write_req(p, b"1", "e-f3"), as_uid=GW)["ok"])
        self.assertEqual(S.call(self.sock, S.write_req(p, b"2", "e-f3"), as_uid=GW)["code"], "ALREADY_WRITTEN"); self.assertEqual(open(p, "rb").read(), b"1")
    def test_agent_cannot_fence_or_observe(self):
        self.assertEqual(S.call(self.sock, S.fence_req("e-victim"), as_uid=AGENT)["code"], "PEER_NOT_GATEWAY"); self.assertEqual(S.call(self.sock, S.observe_req("e-victim"), as_uid=AGENT)["code"], "PEER_NOT_GATEWAY")
        p = os.path.join(self.data, "v.txt"); self.assertTrue(S.call(self.sock, S.write_req(p, b"ok", "e-victim"), as_uid=GW)["ok"])     # victim effect was not fenced by the refused agent
    def test_fences_survive_sink_restart(self):
        d = tempfile.mkdtemp(); os.chmod(d, 0o755); proc, sock, data, jr = S.start_sink(d, SINK, GW)
        try:
            S.call(sock, S.fence_req("e-r"), as_uid=GW); S.call(sock, {"op": "stop"}, as_uid=GW); proc.wait(timeout=10); os.unlink(sock + ".ready")
            proc, sock, data, jr = S.start_sink(d, SINK, GW); self.assertEqual(S.call(sock, S.write_req(os.path.join(data, "r.txt"), b"x", "e-r"), as_uid=GW)["code"], "FENCED")
        finally: S.call(sock, {"op": "stop"}, as_uid=GW); proc.wait(timeout=10)
    def test_observe_is_read_only(self):
        self.assertIsNone(S.call(self.sock, S.observe_req("e-never"), as_uid=GW)["observed"]); p = os.path.join(self.data, "n.txt")
        self.assertTrue(S.call(self.sock, S.write_req(p, b"x", "e-never"), as_uid=GW)["ok"])
if __name__ == "__main__": unittest.main()
