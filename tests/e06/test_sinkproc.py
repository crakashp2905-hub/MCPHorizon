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
if __name__ == "__main__": unittest.main()
