import dataclasses, hashlib, json, os, sys, threading, time, unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
R = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, R)
from tests.e05 import test_filesink as e05
from tests.blueprint import test_durable as TD
from horizon.assurance import durable as D
from horizon.assurance.registry import AssuranceClaim
from horizon.effects.canonical import CanonicalEffect
from horizon.effects.httpsink import HttpSink, ProtectedHttpWriter
class Recv:
    def __init__(self):
        self.hits, self.mode, outer = [], "ok", self
        class H(BaseHTTPRequestHandler):
            def do_POST(s):
                n = int(s.headers.get("Content-Length", 0)); body = s.rfile.read(n); outer.hits.append((s.path, s.headers.get("Idempotency-Key"), body))
                if outer.mode == "sleep": time.sleep(1.5)
                code = {"ok": 200, "redir": 302, "reject": 403, "boom": 500, "sleep": 200}[outer.mode]
                s.send_response(code)
                if code == 302: s.send_header("Location", "http://127.0.0.1:1/elsewhere")
                s.send_header("Content-Length", "0"); s.end_headers()
            def log_message(s, *a): pass
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H); self.port = self.srv.server_address[1]; threading.Thread(target=self.srv.serve_forever, daemon=True).start()
    def close(self): self.srv.shutdown(); self.srv.server_close()
class T(unittest.TestCase):
    setUp0, tearDown0 = e05.T.setUp, e05.T.tearDown
    def tok(self, ce, **o): return e05.T.tok(self, ce, **o)
    def setUp(self):
        self.setUp0(); self.rx = Recv(); self.body = b"TEST_CANARY_NOT_SECRET payload"; self.url = f"http://127.0.0.1:{self.rx.port}/hook?x=1"
        self.sink = HttpSink(self.rx.port, os.path.join(self.d, "http.jsonl"), timeout=0.5)
        self.ce = CanonicalEffect("t1", "srv1", "sess1", "agent-a", "send", "url", self.url, {"sha256": hashlib.sha256(self.body).hexdigest()})
        sg, _, _, _, ts = TD.mk(); self.reg = D.DurableRegistry(os.path.join(self.d, "a.db"), ts, lambda: 100)
        self.reg.set_node("adapter:http", "d1"); self.reg.issue(D.sign_claim(AssuranceClaim("c:h", ("http",), 5, 200, ("adapter:http",), (("adapter:http", "d1"),)), TD.BIND, sg))
        self.w = ProtectedHttpWriter(self.v, self.L, self.sink, gate=lambda: self.reg.permit("c:h", 5))
    def tearDown(self): self.rx.close(); self.tearDown0()
    def send(self, eid="e1", ce=None, body=None, w=None): ce = ce or self.ce; return (w or self.w).send(self.tok(ce), ce, body if body is not None else self.body, eid)
    def test_valid_claim_posts_once_with_idempotency_key(self):
        r = self.send(); self.assertEqual(r["status"], "ALLOW_COMMITTED"); self.assertEqual(self.rx.hits, [("/hook?x=1", "e1", self.body)]); self.assertEqual(self.L.state("e1"), "COMMITTED")
    def test_gate_denial_sends_nothing(self):
        self.reg.invalidate("adapter:http", "adapter_changed"); r = self.send(); self.assertEqual((r["status"], r["code"]), ("BLOCKED", "ASSURANCE_DENIED")); self.assertEqual(self.rx.hits, []); self.assertEqual(self.L.state("e1"), "BLOCKED")
        self.assertFalse(os.path.exists(self.sink.journal))
    def test_gate_exception_and_malformed_verdicts_fail_closed(self):
        def boom(): raise RuntimeError("x")
        for i, g in enumerate((boom, lambda: (1, ""), lambda: ("yes", ""), lambda: (None,), lambda: (False, "no"))):
            self.assertEqual(self.send("g%d" % i, w=ProtectedHttpWriter(self.v, self.L, self.sink, gate=g))["code"], "ASSURANCE_DENIED")
        self.assertEqual(self.rx.hits, [])
    def test_restoration_resumes(self):
        self.reg.invalidate("adapter:http", "journal_lost"); self.assertEqual(self.send("e1")["code"], "ASSURANCE_DENIED"); self.reg.restore("adapter:http", "ok"); self.assertEqual(self.send("e2")["status"], "ALLOW_COMMITTED"); self.assertEqual(len(self.rx.hits), 1)
    def test_no_gate_is_backward_compatible(self): self.assertEqual(self.send(w=ProtectedHttpWriter(self.v, self.L, self.sink))["status"], "ALLOW_COMMITTED")
    def test_gate_never_grants_without_valid_permit(self):
        r = self.w.send("garbage", self.ce, self.body, "e1"); self.assertEqual(r["status"], "BLOCKED"); self.assertNotEqual(r.get("code"), "ASSURANCE_DENIED"); self.assertEqual(self.rx.hits, [])
    def test_targets_outside_the_configured_receiver_are_refused_before_any_permit_is_spent(self):
        p = self.rx.port
        for i, u in enumerate((f"http://127.0.0.1:{p + 1}/x", f"http://127.0.0.2:{p}/x", f"http://localhost:{p}/x", f"https://127.0.0.1:{p}/x", f"http://127.0.0.1:{p}@evil.example/x", f"http://user:pw@127.0.0.1:{p}/x",
                                f"http://127.0.0.1.evil.example:{p}/x", f"http://evil.example:{p}/x", f"http://127.0.0.1:{p}/x\\y", f"http://127.0.0.1:{p}/x y", f"http://127.0.0.1:{p}")):
            ce = dataclasses.replace(self.ce, target_raw=u)
            try: tk = self.tok(ce)
            except ValueError: tk = "unmintable"      # the normalizer already refuses some of these (credentials in the URL), so no permit can even be minted
            r = self.w.send(tk, ce, self.body, "t%d" % i); self.assertEqual(r["status"], "BLOCKED", u); self.assertIn(r["code"], ("OUTSIDE_ALLOWED_TARGET", "BAD_URL", "UNSUPPORTED_EFFECT", "MALFORMED"), u)
            self.assertIsNone(self.L.state("t%d" % i), u)
        self.assertEqual(self.rx.hits, [])
    def test_body_not_matching_permit_args_is_blocked(self): self.assertEqual(self.send(body=b"other")["code"], "DATA_NOT_BOUND_TO_PERMIT"); self.assertEqual(self.rx.hits, [])
    def test_wrong_effect_type_is_unsupported(self):
        ce = dataclasses.replace(self.ce, effect="write"); self.assertEqual(self.send(ce=ce)["code"], "UNSUPPORTED_EFFECT"); self.assertEqual(self.rx.hits, [])
    def test_permit_replay_and_duplicate_effect_id(self):
        t = self.tok(self.ce); self.assertEqual(self.w.send(t, self.ce, self.body, "e1")["status"], "ALLOW_COMMITTED")
        self.assertEqual(self.w.send(t, self.ce, self.body, "e2")["code"], "REPLAY"); self.assertEqual(self.send("e1")["status"], "DUPLICATE"); self.assertEqual(len(self.rx.hits), 1)
    def test_redirect_is_not_followed_and_is_not_reported_committed(self):
        self.rx.mode = "redir"; r = self.send(); self.assertEqual((r["status"], r["code"]), ("UNKNOWN", "HTTP_AMBIGUOUS")); self.assertEqual(len(self.rx.hits), 1)
    def test_receiver_rejection_is_blocked_and_server_error_is_unknown(self):
        self.rx.mode = "reject"; self.assertEqual(self.send("a")["code"], "HTTP_REJECTED"); self.assertEqual(self.L.state("a"), "BLOCKED")
        self.rx.mode = "boom"; self.assertEqual((self.send("b")["status"], self.L.state("b")), ("UNKNOWN", "UNKNOWN"))
    def test_connection_refused_is_blocked_because_nothing_was_sent(self):
        dead = Recv(); port = dead.port; dead.close(); sink = HttpSink(port, os.path.join(self.d, "dead.jsonl"), timeout=0.5); w = ProtectedHttpWriter(self.v, self.L, sink)
        ce = dataclasses.replace(self.ce, target_raw=f"http://127.0.0.1:{port}/hook"); r = w.send(self.tok(ce), ce, self.body, "r1")
        self.assertEqual((r["status"], r["code"], self.L.state("r1")), ("BLOCKED", "CONNECTION_REFUSED", "BLOCKED")); self.assertEqual(sink.fence_and_observe("r1")["state"], "refused")
    def test_timeout_after_send_is_unknown_and_reconcile_does_not_guess(self):
        self.rx.mode = "sleep"; r = self.send(); self.assertEqual((r["status"], r["code"]), ("UNKNOWN", "UPSTREAM_FAILED")); self.assertEqual(self.L.state("e1"), "UNKNOWN")
        self.assertEqual(self.w.reconcile("e1"), "UNKNOWN")       # sent, no response recorded: genuinely ambiguous, left alone
        self.assertEqual(self.sink.fence_and_observe("e1")["state"], "ambiguous")
    def test_fenced_effect_is_refused_by_the_sink(self):
        self.sink.fence_and_observe("f1"); from horizon.effects.httpsink import HttpSinkError
        with self.assertRaises(HttpSinkError) as c: self.sink.post(self.url, self.body, "f1")
        self.assertEqual(c.exception.code, "FENCED"); self.assertEqual(self.rx.hits, [])
    def test_sink_refuses_a_second_post_for_the_same_effect_id_even_without_the_ledger(self):
        from horizon.effects.httpsink import HttpSinkError
        self.sink.post(self.url, self.body, "d1")
        with self.assertRaises(HttpSinkError) as c: self.sink.post(self.url, self.body, "d1")
        self.assertEqual(c.exception.code, "ALREADY_SENT"); self.assertEqual(len(self.rx.hits), 1)
    def test_reconcile_never_reports_a_server_error_as_committed(self):
        self.rx.mode = "boom"; self.assertEqual(self.send("b")["status"], "UNKNOWN"); self.assertEqual(self.w.reconcile("b"), "RECONCILED_BLOCKED")
        self.rx.mode = "ok"; self.assertEqual(self.send("c")["status"], "ALLOW_COMMITTED")
    def test_reconcile_of_a_never_sent_unknown_resolves_to_blocked(self):
        # ledger says UNKNOWN (e.g. crash between begin and post); the sink never saw it -> fence + resolve not-committed
        self.L.request("u1", {"target": self.url}); self.L.authorize("u1", "n1"); self.L.begin("u1"); self.L.finish("u1", "UNKNOWN", {}); self.assertEqual(self.w.reconcile("u1"), "RECONCILED_BLOCKED")
    def test_journal_chain_detects_edit_and_ordering(self):
        self.send("a"); self.send("b"); ok, n, h = self.sink.verify_chain(); self.assertTrue(ok); self.assertEqual(n, 4)
        L = open(self.sink.journal).read().splitlines(); r = json.loads(L[1]); r["status"] = 500; L[1] = json.dumps(r, sort_keys=True); open(self.sink.journal, "w").write("\n".join(L) + "\n"); self.assertFalse(self.sink.verify_chain()[0])
    def test_journal_deleted_record_and_prev_only_edit_detected(self):
        self.send("a"); self.send("b"); L = open(self.sink.journal).read().splitlines(); open(self.sink.journal, "w").write("\n".join(L[:1] + L[2:]) + "\n"); self.assertFalse(self.sink.verify_chain()[0])
    def test_prev_field_edit_alone_is_detected(self):
        self.send("a"); self.send("b"); L = open(self.sink.journal).read().splitlines(); r = json.loads(L[1]); r["prev"] = "f" * 64; L[1] = json.dumps(r, sort_keys=True); open(self.sink.journal, "w").write("\n".join(L) + "\n"); self.assertFalse(self.sink.verify_chain()[0])
    def test_only_loopback_ipv4_sink_can_be_built(self):
        with self.assertRaises(ValueError): HttpSink(80, "/tmp/x", host="example.com")
if __name__ == "__main__": unittest.main()
