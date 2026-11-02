import unittest
from horizon.approvalui import broker as B
class Clk:
    t = 0.0
    def __call__(s): return s.t
OP = {"tool": "send_email", "target": "bob@x.test", "args": {"body": "hi", "attach": "a.txt"}}
def mk():
    c = Clk(); b = B.Broker(c); b.register_approver("alice", "S1"); b.register_agent("agent1"); return c, b
def approve(b, op=OP, dest="smtp.local", ttl=60, approver="alice"):
    rid, _ = b.request(op, dest, ttl); st, tok = b.decide(rid, approver, "S1", "https://ui.test", b.new_csrf(approver), True); return rid, st, tok

class Approvals(unittest.TestCase):
    def test_happy_path_and_single_use(self):
        c, b = mk(); rid, st, tok = approve(b); self.assertEqual(st, "APPROVED")
        self.assertEqual(b.consume(tok, OP, "smtp.local"), ("APPROVED", "")); self.assertEqual(b.consume(tok, OP, "smtp.local"), ("DENIED", "replay"))
    def test_changed_arguments_denied(self):
        c, b = mk(); _, _, tok = approve(b); op2 = dict(OP, args={"body": "hi", "attach": "secret.txt"}); self.assertEqual(b.consume(tok, op2, "smtp.local")[1], "operation changed since approval")
    def test_changed_target_and_tool_denied(self):
        c, b = mk(); _, _, tok = approve(b)
        self.assertFalse(b.consume(tok, dict(OP, target="eve@x.test"), "smtp.local")[0] == "APPROVED"); self.assertFalse(b.consume(tok, dict(OP, tool="delete"), "smtp.local")[0] == "APPROVED")
    def test_changed_destination_denied(self):
        c, b = mk(); _, _, tok = approve(b); self.assertEqual(b.consume(tok, OP, "evil.test")[1], "destination changed")
    def test_expiry(self):
        c, b = mk(); _, _, tok = approve(b, ttl=10); c.t = 10; self.assertEqual(b.consume(tok, OP, "smtp.local")[1], "expired")
    def test_expiry_at_decision(self):
        c, b = mk(); rid, _ = b.request(OP, "d", 5); c.t = 5; self.assertEqual(b.decide(rid, "alice", "S1", "https://ui.test", b.new_csrf("alice"), True)[1], "expired")
    def test_forged_token_denied(self):
        c, b = mk(); _, _, tok = approve(b); bad = dict(tok, digest=B.op_digest(dict(OP, target="eve"))); self.assertEqual(b.consume(bad, dict(OP, target="eve"), "smtp.local")[1], "bad signature")
        self.assertEqual(b.consume(dict(tok, sig="00"), OP, "smtp.local")[1], "bad signature"); self.assertEqual(b.consume({k: v for k, v in tok.items() if k != "sig"}, OP, "smtp.local")[1], "bad signature")
    def test_stale_policy_revision(self):
        c, b = mk(); _, _, tok = approve(b); b.rev = 2; self.assertEqual(b.consume(tok, OP, "smtp.local")[1], "stale policy revision")
    def test_stale_policy_at_decision(self):
        c, b = mk(); rid, _ = b.request(OP, "d"); b.rev = 2; self.assertEqual(b.decide(rid, "alice", "S1", "https://ui.test", b.new_csrf("alice"), True)[1], "stale policy revision")
    def test_revocation_race(self):
        c, b = mk(); rid, _, tok = approve(b); b.revoke(rid); self.assertEqual(b.consume(tok, OP, "smtp.local"), ("DENIED", "revoked"))
    def test_agent_cannot_approve(self):
        c, b = mk(); b.approvers["agent1"] = "S1"; rid, _ = b.request(OP, "d"); self.assertEqual(b.decide(rid, "agent1", "S1", "https://ui.test", b.new_csrf("agent1"), True)[1], "agents cannot approve")
    def test_unknown_approver_and_wrong_session(self):
        c, b = mk(); rid, _ = b.request(OP, "d")
        self.assertEqual(b.decide(rid, "mallory", "S1", "https://ui.test", b.new_csrf("mallory"), True)[1], "unauthenticated approver")
        self.assertEqual(b.decide(rid, "alice", "STOLEN", "https://ui.test", b.new_csrf("alice"), True)[1], "unauthenticated approver")
    def test_origin_check(self):
        c, b = mk(); rid, _ = b.request(OP, "d"); self.assertEqual(b.decide(rid, "alice", "S1", "https://evil.test", b.new_csrf("alice"), True)[1], "bad origin")
    def test_csrf_required_single_use_and_bound(self):
        c, b = mk(); rid, _ = b.request(OP, "d"); self.assertEqual(b.decide(rid, "alice", "S1", "https://ui.test", "nope", True)[1], "bad or reused csrf")
        b.register_approver("bob", "S2"); n = b.new_csrf("bob"); self.assertEqual(b.decide(rid, "alice", "S1", "https://ui.test", n, True)[1], "bad or reused csrf")
    def test_duplicate_submission_rejected(self):
        c, b = mk(); rid, st, _ = approve(b); self.assertEqual(st, "APPROVED"); self.assertEqual(b.decide(rid, "alice", "S1", "https://ui.test", b.new_csrf("alice"), True)[1], "unknown or already decided")
    def test_deny_yields_no_token(self):
        c, b = mk(); rid, _ = b.request(OP, "d"); self.assertEqual(b.decide(rid, "alice", "S1", "https://ui.test", b.new_csrf("alice"), False), ("DENIED", ""))
    def test_unknown_request(self): self.assertEqual(mk()[1].decide("zz", "alice", "S1", "https://ui.test", "x", True)[0], "REJECT")
    def test_token_from_other_broker_denied(self):
        c, b = mk(); _, _, tok = approve(b); c2, b2 = mk(); self.assertEqual(b2.consume(tok, OP, "smtp.local")[1], "bad signature")

class Summary(unittest.TestCase):
    def test_server_summary_shows_everything(self):
        s = B.effect_summary(OP); self.assertIn("bob@x.test", s); self.assertIn("attach='a.txt'", s); self.assertIn("send_email", s)
    def test_request_returns_server_summary(self):
        c, b = mk(); _, s = b.request(OP, "d"); self.assertEqual(s, B.effect_summary(OP))
    def test_misleading_agent_text_flagged(self):
        self.assertTrue(B.summary_mismatch("Send a friendly note", OP)); self.assertTrue(B.summary_mismatch("send to bob@x.test: hi", OP))
        self.assertFalse(B.summary_mismatch("send to bob@x.test body hi attach a.txt", OP)); self.assertTrue(B.summary_mismatch(None, OP))
    def test_target_hidden_flagged(self): self.assertTrue(B.summary_mismatch("hi a.txt", OP)); self.assertFalse(B.summary_mismatch("bob@x.test hi a.txt", OP))
    def test_no_args_summary(self): self.assertTrue(B.effect_summary({"tool": "t", "target": "x"}).endswith("no arguments"))

class UiAndStreams(unittest.TestCase):
    def test_optimistic_ui_is_not_a_decision(self):
        self.assertEqual(B.ui_decision("approved"), "UNKNOWN"); self.assertEqual(B.ui_decision("approved", {"sig": "x"}), "APPROVED"); self.assertEqual(B.ui_decision("pending", {"sig": "x"}), "UNKNOWN")
    def test_empty_token_is_not_a_decision(self): self.assertEqual(B.ui_decision("approved", {}), "UNKNOWN")
    def test_digest_independent_of_key_order(self): self.assertEqual(B.op_digest({"a": 1, "b": {"x": 1, "y": 2}}), B.op_digest({"b": {"y": 2, "x": 1}, "a": 1}))
    def test_states_vocabulary(self): self.assertEqual(set(B.STATES), {"NEEDS_APPROVAL", "APPROVED", "DENIED", "UNKNOWN", "INCOMPLETE"})
    def test_ordering(self):
        s = B.StreamVerifier(); self.assertEqual([s.feed("r", i, "E") for i in range(3)], ["OK"] * 3)
        self.assertEqual(s.feed("r", 1, "E"), "DUPLICATE"); self.assertEqual(s.feed("r", 5, "E"), "GAP_OR_REORDER"); self.assertEqual(s.feed("r", 3, "E"), "OK")
    def test_runs_independent(self):
        s = B.StreamVerifier(); s.feed("a", 0, "E"); self.assertEqual(s.feed("b", 0, "E"), "OK"); self.assertEqual(s.feed("b", 1, "E"), "OK")
    def test_after_cancel_nothing_accepted(self):
        s = B.StreamVerifier(); s.feed("r", 0, "E"); s.feed("r", 1, "CANCELLED"); self.assertEqual(s.feed("r", 2, "APPROVED"), "AFTER_CLOSE"); self.assertEqual(s.state("r"), "CANCELLED")
    def test_interrupted_stream_incomplete(self):
        s = B.StreamVerifier(); s.feed("r", 0, "E"); self.assertEqual(s.state("r"), "INCOMPLETE"); s.feed("r", 1, "DONE"); self.assertEqual(s.state("r"), "COMPLETE"); self.assertEqual(s.state("zz"), "UNKNOWN")
    def test_reorder_not_recorded(self):
        s = B.StreamVerifier(); s.feed("r", 5, "E"); self.assertEqual(s.feed("r", 0, "E"), "OK")
if __name__ == "__main__": unittest.main()
