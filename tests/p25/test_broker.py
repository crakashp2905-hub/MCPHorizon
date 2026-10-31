import os, tempfile, unittest, json, time
from horizon.runtime import broker as B, sandbox as S
from horizon.runtime.receiver import Receiver
OK = os.geteuid() == 0 and S.landlock_abi() >= 4
P1, P2, P3 = 47411, 47412, 47413
def mk(res=None, **kw):
    rules = {"agent": [B.Rule("approved.test", (P1,), ("GET", "POST")), B.Rule("redir.test", (P1,), ("GET",))]}
    return B.Broker(rules, res or B.Resolver({"approved.test": ["127.0.0.1"], "redir.test": ["127.0.0.1"], "meta.test": ["169.254.169.254"], "other.test": ["127.0.0.1"]}), test_sinks={("127.0.0.1", P1)}, **kw)

class Snap:
    def __init__(self, rows): self._r = rows
    def rows(self, port=None): return [r for r in self._r if port is None or r["port"] == port]
    def bytes(self, port): return sum(r["bytes"] for r in self.rows(port))

class Classify(unittest.TestCase):
    def test_classes(self):
        for ip, c in [("169.254.169.254", "METADATA"), ("::ffff:169.254.169.254", "METADATA"), ("127.0.0.1", "LOOPBACK"), ("::1", "LOOPBACK"), ("10.1.2.3", "PRIVATE"), ("100.64.0.1", "CGNAT"), ("169.254.1.1", "LINK_LOCAL"), ("fe80::1", "LINK_LOCAL"), ("0.0.0.0", "UNSPECIFIED"), ("224.0.0.1", "MULTICAST"), ("8.8.8.8", "PUBLIC"), ("fd00:ec2::254", "METADATA")]:
            self.assertEqual(B.classify_ip(ip), c, ip)

class Policy(unittest.TestCase):
    def d(self, br, url, m="GET", body=b"", labels=()): return br.authorize("agent", m, url, body, labels)
    def test_allow_and_unknown_principal(self):
        br = mk(); self.assertTrue(self.d(br, f"http://approved.test:{P1}/x")["ok"]); self.assertEqual(br.authorize("evil", "GET", f"http://approved.test:{P1}/x")["code"], "DESTINATION_NOT_APPROVED")
    def test_denials(self):
        br = mk()
        for url, m, body, lab, code in [(f"http://other.test:{P1}/", "GET", b"", (), "DESTINATION_NOT_APPROVED"), (f"http://approved.test:{P2}/", "GET", b"", (), "PORT_NOT_APPROVED"), (f"http://approved.test:{P1}/", "DELETE", b"", (), "METHOD_NOT_APPROVED"),
                                        (f"http://approved.test:{P1}/", "POST", b"x" * 5000, (), "BODY_TOO_LARGE"), (f"http://approved.test:{P1}/", "POST", b"", ("SECRET",), "PAYLOAD_LABEL_NOT_ALLOWED"), (f"http://approved.test:{P1}/", "POST", b"TEST_CANARY_NOT_SECRET", (), "CANARY_IN_PAYLOAD"),
                                        (f"https://approved.test:{P1}/", "GET", b"", (), "UNSUPPORTED_TRANSPORT"), (f"ws://approved.test:{P1}/", "GET", b"", (), "UNSUPPORTED_TRANSPORT"), ("http://approved.test:%d/\x00" % P1, "GET", b"", (), None)]:
            r = self.d(br, url, m, body, lab); self.assertFalse(r["ok"], url)
            if code: self.assertEqual(r["code"], code)
    def test_metadata_and_private_denied_even_if_name_approved(self):
        br = mk(B.Resolver({"approved.test": ["169.254.169.254"]})); self.assertEqual(self.d(br, f"http://approved.test:{P1}/")["code"], "DESTINATION_CLASS_DENIED")
        br = mk(B.Resolver({"approved.test": ["10.0.0.5"]})); self.assertEqual(self.d(br, f"http://approved.test:{P1}/")["code"], "DESTINATION_CLASS_DENIED")
    def test_mixed_answers_and_ambiguity_denied(self):
        self.assertFalse(self.d(mk(B.Resolver({"approved.test": ["127.0.0.1", "169.254.169.254"]})), f"http://approved.test:{P1}/")["ok"])
        self.assertEqual(self.d(mk(B.Resolver({"approved.test": ["127.0.0.1", "127.0.0.2"]})), f"http://approved.test:{P1}/")["code"], "DESTINATION_CLASS_DENIED")
    def test_multiple_valid_answers_are_ambiguous(self):
        br = mk(B.Resolver({"approved.test": ["127.0.0.1", "127.0.0.2"]})); br.sinks.add(("127.0.0.2", P1)); self.assertEqual(self.d(br, f"http://approved.test:{P1}/")["code"], "AMBIGUOUS_RESOLUTION")
    def test_numeric_host_tricks_do_not_reach_metadata(self):
        br = mk()
        for h in ["2852039166", "0xa9fea9fe", "0251.0376.0251.0376", "[::ffff:a9fe:a9fe]", "169.254.169.254", "169.254.169.254.", "approved.test@169.254.169.254"]:
            r = self.d(br, f"http://{h}:{P1}/"); self.assertFalse(r["ok"], h)
    def test_fail_closed_on_policy_outage_and_error(self):
        self.assertEqual(self.d(mk(policy_ok=lambda: False), f"http://approved.test:{P1}/")["code"], "POLICY_UNAVAILABLE")
        def boom(): raise RuntimeError("x")
        self.assertEqual(self.d(mk(policy_ok=boom), f"http://approved.test:{P1}/")["code"], "POLICY_ERROR")
    def test_rate_limit(self):
        br = mk(rate_per_min=3); r = [self.d(br, f"http://approved.test:{P1}/")["ok"] for _ in range(5)]; self.assertEqual(r, [True, True, True, False, False])
    def test_no_resolution(self): self.assertEqual(self.d(mk(B.Resolver({})), f"http://approved.test:{P1}/")["code"], "NO_RESOLUTION")

@unittest.skipUnless(OK, "UNSUPPORTED environment: root + Landlock needed (HR-G2 not exercised)")
class Wire(unittest.TestCase):
    def run_(self, br, code, ports=(P1, P2, P3)):
        with tempfile.TemporaryDirectory() as d, Receiver(list(ports), d) as rc:
            r = S.launch(B.CLIENT + code, run_id="t", broker=br.session("agent")); self.assertIsNone(r.refused, r.refused); time.sleep(0.3); snap = Snap(rc.rows()); return r, snap, json.loads(r.stdout.strip().splitlines()[-1])
    def test_approved_lands_unapproved_does_not(self):
        r, rc, o = self.run_(mk(), f"import json;print(json.dumps([hz_fetch('POST','http://approved.test:{P1}/u','hello'), hz_fetch('POST','http://other.test:{P1}/u','x'), hz_fetch('GET','http://approved.test:{P2}/')]))")
        self.assertTrue(o[0]["ok"]); self.assertFalse(o[1]["ok"]); self.assertFalse(o[2]["ok"]); self.assertEqual(len(rc.rows(P1)), 1); self.assertEqual(rc.rows(P2), [])
        self.assertEqual([x["ok"] for x in r.broker_requests], [True, False, False]); self.assertTrue(all(x["run_id"] == "t" for x in r.broker_requests))
    def test_single_run_record_joins_sources(self):
        br = mk(); r, rc, o = self.run_(br, f"import json;print(json.dumps([hz_fetch('POST','http://approved.test:{P1}/u','hello'), hz_fetch('POST','http://other.test:{P1}/u','x')]))")
        rec = B.run_record(r, rc.rows(), br.log); self.assertEqual(rec["run_id"], "t"); self.assertEqual(rec["receiver_bytes_total"], rc.bytes(P1)); self.assertIsNone(rec["firewall_drops"]); self.assertTrue(rec["consistent"])
        self.assertEqual(sorted(x["decision"] for x in rec["broker_log"]), ["ALLOW", "DENY"])
    def test_canary_never_leaves(self):
        r, rc, o = self.run_(mk(), f"import json;print(json.dumps(hz_fetch('POST','http://approved.test:{P1}/u','TEST_CANARY_NOT_SECRET')))")
        self.assertEqual(o["code"], "CANARY_IN_PAYLOAD"); self.assertEqual(rc.rows(P1), []); self.assertEqual(rc.bytes(P1), 0)
    def test_redirect_to_unapproved_and_metadata_denied_per_hop(self):
        br = mk(); r, rc, o = self.run_(br, f"import json;print(json.dumps([hz_fetch('GET','http://redir.test:{P1}/redir?to=http://other.test:{P1}/x'), hz_fetch('GET','http://redir.test:{P1}/redir?to=http://meta.test:{P1}/latest'), hz_fetch('GET','http://redir.test:{P1}/redir?to=http://approved.test:{P1}/ok')]))")
        self.assertEqual(o[0]["code"], "REDIRECT_DESTINATION_NOT_APPROVED"); self.assertEqual(o[1]["code"], "REDIRECT_DESTINATION_NOT_APPROVED"); self.assertTrue(o[2]["ok"])
        paths = [x["sha256"] for x in rc.rows(P1)]; self.assertEqual(len(paths), 4)   # 3 redirectors + 1 approved target; none for other.test/meta.test
        self.assertTrue(any(l["decision"] == "DENY_AT_REDIRECT" for l in br.log))
    def test_redirect_loop_bounded(self):
        r, rc, o = self.run_(mk(), f"import json;print(json.dumps(hz_fetch('GET','http://redir.test:{P1}/redir?to=http://redir.test:{P1}/redir?to=http://redir.test:{P1}/redir?to=http://redir.test:{P1}/redir?to=http://redir.test:{P1}/')))")
        self.assertIn(o["code"], ("TOO_MANY_REDIRECTS", "CONNECT_FAILED", "BAD_REDIRECT")); self.assertLessEqual(len(rc.rows(P1)), 5)
    def test_dns_rebinding_pinned(self):
        # name resolves to a sink on first lookup and to metadata later; the connect must use the validated address and never re-resolve
        res = B.Resolver({}, {"approved.test": [["127.0.0.1"], ["169.254.169.254"]]}); br = mk(res)
        a = br.authorize("agent", "GET", f"http://approved.test:{P1}/x"); self.assertTrue(a["ok"]); self.assertEqual(a["ip"], "127.0.0.1")
        with tempfile.TemporaryDirectory() as d, Receiver([P1], d) as rc:
            r = br.execute("agent", "GET", f"http://approved.test:{P1}/x", b"", (), a); self.assertTrue(r["ok"]); time.sleep(0.3); self.assertEqual(len(rc.rows(P1)), 1)
        self.assertFalse(br.authorize("agent", "GET", f"http://approved.test:{P1}/x")["ok"])    # second lookup now points at metadata: denied
    def test_permit_bound_replay_and_expiry(self):
        br = mk(); a = br.authorize("agent", "POST", f"http://approved.test:{P1}/x", b"abc")
        with tempfile.TemporaryDirectory() as d, Receiver([P1], d) as rc:
            self.assertEqual(br.execute("agent", "POST", f"http://approved.test:{P1}/x", b"abd", (), a)["code"], "PERMIT_MISMATCH")      # args changed
            self.assertEqual(br.execute("agent", "POST", f"http://approved.test:{P1}/y", b"abc", (), a)["code"], "PERMIT_MISMATCH")
            self.assertTrue(br.execute("agent", "POST", f"http://approved.test:{P1}/x", b"abc", (), a)["ok"]); time.sleep(0.3)
            self.assertEqual(br.execute("agent", "POST", f"http://approved.test:{P1}/x", b"abc", (), a)["code"], "PERMIT_REPLAY"); self.assertEqual(len(rc.rows(P1)), 1)
        b2 = mk(); a2 = b2.authorize("agent", "GET", f"http://approved.test:{P1}/x", exp_s=-1); self.assertEqual(b2.execute("agent", "GET", f"http://approved.test:{P1}/x", b"", (), a2)["code"], "PERMIT_EXPIRED")
        a3 = dict(a); a3["permit"] = dict(a["permit"], mac="0" * 64); self.assertEqual(mk().execute("agent", "POST", f"http://approved.test:{P1}/x", b"abc", (), a3)["code"], "PERMIT_MISMATCH")
    def test_malformed_frames_do_not_crash_broker(self):
        r, rc, o = self.run_(mk(), "import socket,struct,json\ns=socket.socket(fileno=3);s.sendall(struct.pack('>I',5)+b'notjs');h=s.recv(4);n=struct.unpack('>I',h)[0];print(json.dumps(json.loads(s.recv(n))))")
        self.assertEqual(o["code"], "BAD_JSON")
    def test_sandbox_cannot_bypass_broker(self):
        r, rc, o = self.run_(mk(), f"import socket,json\nres=[]\nfor p in ({P1},{P3}):\n  try: socket.create_connection(('127.0.0.1',p),timeout=1); res.append('connected')\n  except OSError as e: res.append(e.errno)\nprint(json.dumps(res))")
        self.assertNotIn("connected", o); self.assertEqual(rc.bytes(P1) + rc.bytes(P3), 0)
if __name__ == "__main__": unittest.main()
