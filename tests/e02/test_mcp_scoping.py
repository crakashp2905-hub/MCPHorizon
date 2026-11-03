"""ENG-PR02 / E02-01..04, E02-11: request cache, cancellation and idempotency are scoped to tenant+server+session+principal+typed id."""
import dataclasses, sys, os, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from tests.p4.test_mcp_adapter import GateBase, PRINC, W, hdr, body_mod, ToolPolicy
class Scoping(GateBase):
    def setUp(self):
        super().setUp()
        self.reg.add("s2", "get_doc", ToolPolicy("doc.read", "read", default_conf="INTERNAL")); self.reg.add("s2", "publish", ToolPolicy("http.send", "send", target_arg="url", target_kind="url", sink_zone="registry"))
        self.reg.install(); self.tr.observe("s2", self.tools); self.tr.approve("s2", [t["name"] for t in self.tools], "alice")
        self.bodies = []; orig = self.gate.decide; self.gate.decide = lambda b: (self.bodies.append(b), orig(b))[1]
    def r(self, rid=7, name="get_doc", args=None, sess=None):
        q = W.decode_modern(hdr("tools/call", name), body_mod("tools/call", {"name": name, "arguments": args or {"id": "1"}}, rid=rid), PRINC); return dataclasses.replace(q, session_id=sess) if sess else q
    def test_same_id_on_two_servers_executes_twice(self):
        a = self.gate.handle("s1", self.r()); b = self.gate.handle("s2", self.r()); self.assertEqual(len(self.forwards), 2); self.assertIsNone(a.get("error")); self.assertIsNone(b.get("error"))
    def test_same_id_on_two_sessions_executes_twice(self):
        self.gate.handle("s1", self.r(sess="A")); self.gate.handle("s1", self.r(sess="B")); self.assertEqual(len(self.forwards), 2)
    def test_true_duplicate_in_same_scope_is_still_cached(self):
        self.gate.handle("s1", self.r(sess="A")); self.gate.handle("s1", self.r(sess="A")); self.assertEqual(len(self.forwards), 1)
    def test_same_scope_different_params_is_refused(self):
        self.gate.handle("s1", self.r(sess="A")); self.assertIn("error", self.gate.handle("s1", self.r(sess="A", args={"id": "2"})))
        self.assertEqual(len(self.forwards), 1)
    def test_cancel_on_one_server_does_not_discard_other_servers_result(self):
        self.gate.cancel(PRINC, 7, server_id="s1", session_id=None); self.assertIsNotNone(self.gate.handle("s2", self.r())); self.assertEqual(len(self.forwards), 1)
        self.assertEqual(self.gate.handle("s1", self.r())["error"]["message"], "cancelled before execution")
    def test_cancel_on_one_session_does_not_hit_another(self):
        self.gate.cancel(PRINC, 7, server_id="s1", session_id="A"); self.assertIsNotNone(self.gate.handle("s1", self.r(sess="B"))); self.assertIn("error", self.gate.handle("s1", self.r(sess="A")))
    def test_cancel_notification_is_scoped_by_server_and_session(self):
        n = W.decode_modern(hdr("notifications/cancelled"), body_mod("notifications/cancelled", {"requestId": 7}, rid=None), PRINC); n = dataclasses.replace(n, session_id="A")
        self.assertIsNone(self.gate.handle("s1", n)); self.assertIsNotNone(self.gate.handle("s2", self.r(sess="A"))); self.assertIsNotNone(self.gate.handle("s1", self.r(sess="B"))); self.assertIn("error", self.gate.handle("s1", self.r(sess="A")))
    def test_integer_and_string_ids_are_different_requests(self):
        self.gate.handle("s1", self.r(rid=1)); self.gate.handle("s1", self.r(rid="1")); self.assertEqual(len(self.forwards), 2)
        self.gate.cancel(PRINC, 1, server_id="s1"); self.assertIsNotNone(self.gate.handle("s1", self.r(rid="1", args={"id": "3"}))); 
    def test_idempotency_keys_and_event_ids_are_scoped(self):
        for srv, sess in (("s1", "A"), ("s1", "B"), ("s2", "A")): self.gate.handle(srv, self.r(sess=sess))
        self.assertEqual(len({b["idempotency_key"] for b in self.bodies}), 3); self.assertEqual(len({b["event_id"] for b in self.bodies}), 3)
        self.assertTrue(all("T1" in b["event_id"] for b in self.bodies))
    def test_idempotency_key_is_stable_for_a_true_retry(self):
        self.gate.handle("s1", self.r(sess="A")); k = self.bodies[-1]["idempotency_key"]; self.gate.done.clear(); self.gate.handle("s1", self.r(sess="A")); self.assertEqual(self.bodies[-1]["idempotency_key"], k)
    def test_unresolved_uncertain_state_is_never_evicted(self):
        self.gate.cache_size = 2; self.forward_result = TimeoutError("down")
        r = self.gate.handle("s1", self.r(rid=100, name="publish", args={"url": "https://x.example/a"})); self.assertEqual(r["error"]["data"]["reason_codes"], ["UNCERTAIN_EXECUTION"])
        self.forward_result = {"result": {"content": [{"type": "text", "text": "ok"}]}}
        for i in range(10): self.gate.handle("s1", self.r(rid=200 + i, args={"id": str(i)}))
        n = len(self.forwards); again = self.gate.handle("s1", self.r(rid=100, name="publish", args={"url": "https://x.example/a"}))
        self.assertEqual(again["error"]["code"], -32002); self.assertEqual(len(self.forwards), n)
    def test_resolved_entries_are_still_bounded(self):
        self.gate.cache_size = 3
        for i in range(10): self.gate.handle("s1", self.r(rid=300 + i, args={"id": str(i)}))
        self.assertLessEqual(len(self.gate.done), 3)
if __name__ == "__main__": unittest.main()
