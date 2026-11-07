import os, sys, unittest
R = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, R)
from tests.e05 import test_filesink as e05
from tests.blueprint import test_durable as TD
from horizon.assurance import durable as D
from horizon.assurance.registry import AssuranceClaim
from horizon.effects.filesink import ProtectedFileWriter
class Wired(unittest.TestCase):
    setUp0, tok, tearDown0 = e05.T.setUp, e05.T.tok, e05.T.tearDown
    def setUp(self):
        self.setUp0(); sg, _, _, _, ts = TD.mk(); self.reg = D.DurableRegistry(os.path.join(self.d, "a.db"), ts, lambda: 100)
        self.reg.set_node("adapter:fs", "d1"); self.reg.issue(D.sign_claim(AssuranceClaim("c:1", ("fs",), 5, 200, ("adapter:fs",), (("adapter:fs", "d1"),)), TD.BIND, sg))
        self.w = ProtectedFileWriter(self.v, self.L, self.sink, gate=lambda: self.reg.permit("c:1", 5))
    def tearDown(self): self.tearDown0()
    def test_valid_claim_allows(self): self.assertEqual(self.w.write(self.tok(), self.ce, self.data, "e1")["status"], "ALLOW_COMMITTED")
    def test_change_after_issue_refuses_next_effect_automatically_and_nothing_written(self):
        self.assertEqual(self.w.write(self.tok(), self.ce, self.data, "e1")["status"], "ALLOW_COMMITTED"); self.reg.set_node("adapter:fs", "d2")
        import dataclasses; ce2 = dataclasses.replace(self.ce, target_raw=os.path.join(self.root, "b.txt")); r = self.w.write(self.tok(ce2), ce2, self.data, "e2")
        self.assertEqual((r["status"], r["code"]), ("BLOCKED", "ASSURANCE_DENIED")); self.assertFalse(os.path.exists(ce2.target_raw)); self.assertIsNone(self.sink.observed("e2")); self.assertEqual(self.L.state("e2"), "BLOCKED")
    def test_denied_effect_burns_the_permit_and_needs_a_fresh_one(self):   # documented behaviour: the verifier consumes the nonce before the gate runs (gate only logs PERMIT for already-verified permits)
        self.reg.invalidate("adapter:fs", "adapter_changed"); t = self.tok(); self.assertEqual(self.w.write(t, self.ce, self.data, "e1")["code"], "ASSURANCE_DENIED")
        self.reg.restore("adapter:fs", "reviewed"); r = self.w.write(t, self.ce, self.data, "e2"); self.assertEqual((r["status"], r["code"]), ("BLOCKED", "REPLAY"))
        self.assertEqual(self.w.write(self.tok(), self.ce, self.data, "e4")["status"], "ALLOW_COMMITTED")
    def test_restoration_resumes(self):
        self.reg.invalidate("adapter:fs", "journal_lost"); self.assertEqual(self.w.write(self.tok(), self.ce, self.data, "e1")["code"], "ASSURANCE_DENIED"); self.reg.restore("adapter:fs", "fixed")
        self.assertEqual(self.w.write(self.tok(), self.ce, self.data, "e3")["status"], "ALLOW_COMMITTED")
    def test_gate_exception_and_malformed_verdicts_fail_closed(self):
        def boom(): raise RuntimeError("x")
        for g in (boom, lambda: (1, ""), lambda: ("yes", ""), lambda: (None,), lambda: (False, "no")):
            w = ProtectedFileWriter(self.v, self.L, self.sink, gate=g); i = "g%d" % id(g); self.assertEqual(w.write(self.tok(), self.ce, self.data, i)["code"], "ASSURANCE_DENIED"); self.assertFalse(os.path.exists(self.ce.target_raw))
    def test_tampered_assurance_log_blocks(self):
        import sqlite3; con = sqlite3.connect(os.path.join(self.d, "a.db")); con.execute("UPDATE ev SET data='{}' WHERE seq=1"); con.commit(); con.close()
        r = self.w.write(self.tok(), self.ce, self.data, "e1"); self.assertEqual(r["code"], "ASSURANCE_DENIED"); self.assertIn("LOG_TAMPERED", r["why"])
    def test_gate_never_grants_without_valid_permit(self):
        r = self.w.write("garbage", self.ce, self.data, "e1"); self.assertEqual(r["status"], "BLOCKED"); self.assertNotEqual(r.get("code"), "ASSURANCE_DENIED")
    def test_no_gate_is_backward_compatible(self):
        w = ProtectedFileWriter(self.v, self.L, self.sink); self.assertEqual(w.write(self.tok(), self.ce, self.data, "n1")["status"], "ALLOW_COMMITTED")
if __name__ == "__main__": unittest.main()
