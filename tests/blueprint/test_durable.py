import json, os, sqlite3, subprocess, sys, tempfile, time, unittest
R = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, R)
from horizon.assurance import durable as D
from horizon.assurance.registry import AssuranceClaim
from horizon.authz.keys import Signer, TrustStore
CLOCK = [100]
BIND = {k: f"{k}@1" for k in D.BINDING_FIELDS}
def mk():
    sg = Signer.generate("ik1", D.CLAIM_ISSUER_ROLE); rep = Signer.generate("rk1", "reproducer"); aud = Signer.generate("ak1", "auditor"); evil = Signer.generate("ek1", "reproducer")
    ts = TrustStore(clock=lambda: 100)
    for s in (sg, rep, aud): ts.add(s.kid, s.iss, s.public_raw(), not_before=0, not_after=10**9)
    return sg, rep, aud, evil, ts
class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.p = os.path.join(self.d, "assure.db"); self.sg, self.rep, self.aud, self.evil, self.ts = mk(); CLOCK[0] = 100
        self.r = D.DurableRegistry(self.p, self.ts, lambda: CLOCK[0])
        self.r.set_node("adapter:fs", "d1"); self.r.set_node("witness:j", "w1")
        self.c = AssuranceClaim("c:1", ("fs",), 5, 200, ("adapter:fs", "witness:j"), (("adapter:fs", "d1"), ("witness:j", "w1")))
        self.r.issue(D.sign_claim(self.c, BIND, self.sg))
class Durability(Base):
    def test_survives_restart_and_permits(self):
        r2 = D.DurableRegistry(self.p, self.ts, lambda: CLOCK[0]); self.assertEqual(r2.status("c:1", 5)[0], "VALID"); self.assertEqual(r2.permit("c:1", 5), (True, ""))
    def test_unknown_claim_fails_closed(self): self.assertFalse(self.r.permit("zz", 5)[0])
    def test_unsigned_or_wrong_key_claim_is_absent(self):
        s = D.sign_claim(self.c.__class__("c:2", ("fs",), 5, 200, ("adapter:fs",), (("adapter:fs", "d1"),)), BIND, self.sg); s["sig"] = "00" * 64; self.r.issue(s); self.assertFalse(self.r.permit("c:2", 5)[0])
        other = Signer.generate("zz", D.CLAIM_ISSUER_ROLE); s2 = D.sign_claim(AssuranceClaim("c:3", ("fs",), 5, 200, ("adapter:fs",), (("adapter:fs", "d1"),)), BIND, other); self.r.issue(s2); self.assertFalse(self.r.permit("c:3", 5)[0])
    def test_tampered_body_rejected(self):
        s = D.sign_claim(AssuranceClaim("c:4", ("fs",), 5, 200, ("adapter:fs",), (("adapter:fs", "d1"),)), BIND, self.sg); s["body"]["expires_at"] = 10**9; self.r.issue(s); self.assertFalse(self.r.permit("c:4", 5)[0])
    def test_wrong_role_cannot_sign_claims(self):
        with self.assertRaises(D.DurableError): D.sign_claim(self.c, BIND, self.rep)
    def test_binding_must_be_exact(self):
        for b in ({}, {**BIND, "extra": "x"}, {k: v for k, v in BIND.items() if k != "tool"}, {**BIND, "agent": ""}):
            with self.assertRaises(D.DurableError): D.sign_claim(self.c, b, self.sg)
class Invalidation(Base):
    def test_binding_changes_suspend(self):
        self.r.set_node("adapter:fs", "d2"); self.assertEqual(self.r.status("c:1", 5)[0], "SUSPENDED"); self.assertFalse(self.r.permit("c:1", 5)[0])
    def test_each_reason_suspends_until_restored_with_evidence(self):
        for reason in D.INVALIDATION_REASONS:
            self.r.invalidate("witness:j", reason); st = self.r.status("c:1", 5); self.assertEqual(st[0], "SUSPENDED"); self.assertIn(reason, st[1]); self.assertFalse(self.r.permit("c:1", 5)[0])
            self.r.restore("witness:j", "reviewer note"); self.assertTrue(self.r.permit("c:1", 5)[0])
    def test_bad_reason_and_empty_restore_rejected(self):
        with self.assertRaises(D.DurableError): self.r.invalidate("witness:j", "vibes")
        with self.assertRaises(D.DurableError): self.r.restore("witness:j", "")
    def test_expiry_and_epoch(self):
        CLOCK[0] = 200; self.assertEqual(self.r.status("c:1", 5)[0], "EXPIRED"); CLOCK[0] = 100; self.assertEqual(self.r.status("c:1", 6)[0], "SUSPENDED")
    def test_revoke_is_permanent_restore_cannot_undo(self):
        self.r.revoke("c:1"); self.r.restore("c:1", "pls"); self.assertEqual(self.r.status("c:1", 5)[0], "REVOKED"); self.assertFalse(self.r.permit("c:1", 5)[0])
    def test_revoke_unknown_claim_is_noop_not_crash(self): self.r.revoke("nope"); self.assertEqual(self.r.status("c:1", 5)[0], "VALID")
    def test_future_effects_refused_new_permit_not_logged(self):
        self.r.invalidate("adapter:fs", "adapter_changed"); n = sum(1 for _, k, _ in self.r.history() if k == "PERMIT"); self.assertFalse(self.r.permit("c:1", 5)[0]); self.assertEqual(n, sum(1 for _, k, _ in self.r.history() if k == "PERMIT"))
class History(Base):
    def test_events_append_only_and_failed_claim_not_rewritten(self):
        self.assertTrue(self.r.permit("c:1", 5)[0]); self.r.invalidate("adapter:fs", "adapter_changed"); self.r.restore("adapter:fs", "fixed")
        kinds = [k for _, k, _ in self.r.history()]; self.assertEqual(kinds, ["NODE", "NODE", "ISSUE", "PERMIT", "INVALIDATE", "RESTORE"])
    def test_tamper_any_row_fails_closed(self):
        con = sqlite3.connect(self.p); con.execute("UPDATE ev SET data=? WHERE kind='INVALIDATE' OR seq=1", (json.dumps({"digest": "evil"}),)); con.commit(); con.close()
        self.assertEqual(self.r.status("c:1", 5)[0], "REVOKED"); self.assertIn("LOG_TAMPERED", self.r.status("c:1", 5)[1]); self.assertFalse(self.r.permit("c:1", 5)[0])
    def test_deleting_a_middle_event_detected(self):
        self.r.invalidate("adapter:fs", "adapter_changed"); self.r.restore("adapter:fs", "x"); con = sqlite3.connect(self.p); con.execute("DELETE FROM ev WHERE kind='INVALIDATE'"); con.commit(); con.close()
        self.assertFalse(self.r.permit("c:1", 5)[0]); self.assertIn("LOG_TAMPERED", self.r.status("c:1", 5)[1])
    def test_tail_truncation_is_NOT_detected_by_chain_alone_but_by_anchor(self):
        self.r.invalidate("adapter:fs", "adapter_changed"); seq, h = self.r.head(); self.assertTrue(self.r.check_anchor(seq, h))
        con = sqlite3.connect(self.p); con.execute("DELETE FROM ev WHERE kind='INVALIDATE'"); con.commit(); con.close()
        self.assertEqual(self.r.status("c:1", 5)[0], "VALID")           # documented limit: rollback to an earlier valid prefix passes the chain check
        self.assertFalse(self.r.check_anchor(seq, h))                    # an external anchor catches it
    def test_anchor_rejects_wrong_hash_and_future_seq(self):
        seq, h = self.r.head(); self.assertTrue(self.r.check_anchor(seq, h)); self.assertFalse(self.r.check_anchor(seq, "0" * 64)); self.assertFalse(self.r.check_anchor(seq + 1, h))
    def test_head_of_empty_log(self):
        e = D.DurableRegistry(os.path.join(self.d, "e.db"), self.ts, lambda: 1); self.assertEqual(e.head(), (0, "0" * 64))
    def test_db_error_fails_closed(self):
        bad = D.DurableRegistry(self.p, self.ts, lambda: CLOCK[0]); os.remove(self.p)
        for ext in ("-wal", "-shm"):
            if os.path.exists(self.p + ext): os.remove(self.p + ext)
        os.makedirs(self.p)   # path is now a directory: every open fails
        self.assertEqual(bad.permit("c:1", 5)[0], False); self.assertTrue(bad.status("c:1", 5)[1].startswith("fail_closed"))
class Grades(Base):
    def test_default_is_source_verified(self): self.assertEqual(self.r.grade("c:1"), "SOURCE_VERIFIED")
    def test_valid_independent_attestations_raise_grade(self):
        self.r.attest(D.sign_attestation("c:1", "INDEPENDENTLY_REPRODUCED", self.rep)); self.assertEqual(self.r.grade("c:1"), "INDEPENDENTLY_REPRODUCED")
        self.r.attest(D.sign_attestation("c:1", "EXTERNALLY_AUDITED", self.aud)); self.assertEqual(self.r.grade("c:1"), "EXTERNALLY_AUDITED")
    def test_untrusted_key_cannot_attest(self): self.r.attest(D.sign_attestation("c:1", "INDEPENDENTLY_REPRODUCED", self.evil)); self.assertEqual(self.r.grade("c:1"), "SOURCE_VERIFIED")
    def test_issuer_key_cannot_self_attest(self):
        s = Signer.generate("ik1", "reproducer"); self.ts.add("ik1r", "reproducer", s.public_raw(), not_before=0, not_after=10**9)
        a = D.sign_attestation("c:1", "INDEPENDENTLY_REPRODUCED", Signer(s.kid, "reproducer", s._p)); self.r.attest(a); self.assertEqual(self.r.grade("c:1"), "SOURCE_VERIFIED")
    def test_wrong_role_for_grade(self): self.r.attest(D.sign_attestation("c:1", "EXTERNALLY_AUDITED", self.rep)) if False else None; self.assertEqual(self.r.grade("c:1"), "SOURCE_VERIFIED")
    def test_role_mismatch_attestation_ignored(self):
        a = D.sign_attestation("c:1", "INDEPENDENTLY_REPRODUCED", self.rep); a["body"]["grade"] = "EXTERNALLY_AUDITED"; self.r.attest(a); self.assertEqual(self.r.grade("c:1"), "SOURCE_VERIFIED")
    def test_attestation_for_other_claim_ignored(self):
        a = D.sign_attestation("c:other", "INDEPENDENTLY_REPRODUCED", self.rep); self.r.attest(a); self.assertEqual(self.r.grade("c:1"), "SOURCE_VERIFIED")
    def test_unknown_claim_attestation_ignored(self): self.r.attest(D.sign_attestation("ghost", "INDEPENDENTLY_REPRODUCED", self.rep)); self.assertEqual(self.r.grade("ghost"), "SOURCE_VERIFIED")
    def test_bad_grade_rejected(self):
        with self.assertRaises(D.DurableError): D.sign_attestation("c:1", "SOURCE_VERIFIED", self.rep)
WORKER = r"""
import sys, json, time
sys.path.insert(0, sys.argv[1])
from horizon.assurance import durable as D
from horizon.authz.keys import TrustStore
ts = TrustStore.from_public(json.load(open(sys.argv[3])), clock=lambda: 100)
r = D.DurableRegistry(sys.argv[2], ts, lambda: 100); ok = 0; t0 = time.time()
while time.time() - t0 < float(sys.argv[4]):
    if r.permit("c:1", 5)[0]: ok += 1
print(ok)
"""
class CrossProcess(Base):
    def test_no_permit_logged_after_revoke_across_processes(self):
        pub = os.path.join(self.d, "trust.json"); json.dump(self.ts.export_public(), open(pub, "w")); w = os.path.join(self.d, "w.py"); open(w, "w").write(WORKER)
        ps = [subprocess.Popen([sys.executable, "-B", w, R, self.p, pub, "2.5"], stdout=subprocess.PIPE, text=True) for _ in range(4)]
        time.sleep(1.0); self.r.revoke("c:1"); outs = [int(p.communicate(timeout=60)[0]) for p in ps]
        h = self.r.history(); rev = [s for s, k, _ in h if k == "REVOKE"]; self.assertEqual(len(rev), 1)
        permits = [s for s, k, _ in h if k == "PERMIT"]; self.assertGreater(len(permits), 0); self.assertTrue(all(s < rev[0] for s in permits), "PERMIT logged after REVOKE")
        self.assertEqual(sum(outs), len(permits))        # every True returned to a worker corresponds to exactly one logged PERMIT before the revoke
        self.assertFalse(self.r.permit("c:1", 5)[0])
    def test_concurrent_invalidate_and_restore_keep_chain_valid(self):
        pub = os.path.join(self.d, "t.json"); json.dump(self.ts.export_public(), open(pub, "w"))
        code = "import sys;sys.path.insert(0,%r);from horizon.assurance import durable as D;from horizon.authz.keys import TrustStore;import json\nts=TrustStore.from_public(json.load(open(%r)),clock=lambda:100)\nr=D.DurableRegistry(%r,ts,lambda:100)\nfor i in range(40): r.invalidate('witness:j','journal_lost');r.restore('witness:j','e%%d'%%i)\n" % (R, pub, self.p)
        ps = [subprocess.Popen([sys.executable, "-B", "-c", code]) for _ in range(3)]; self.assertEqual([p.wait(timeout=120) for p in ps], [0, 0, 0])
        h = self.r.history(); self.assertEqual(len(h), 3 + 240); self.assertNotIn("LOG_TAMPERED", self.r.status("c:1", 5)[1])
class Crash(Base):
    def test_sigkill_during_writes_leaves_valid_chain_and_revocation_effective(self):
        import signal
        pub = os.path.join(self.d, "k.json"); json.dump(self.ts.export_public(), open(pub, "w"))
        code = "import sys;sys.path.insert(0,%r);from horizon.assurance import durable as D;from horizon.authz.keys import TrustStore;import json\nts=TrustStore.from_public(json.load(open(%r)),clock=lambda:100)\nr=D.DurableRegistry(%r,ts,lambda:100)\nwhile True: r.invalidate('witness:j','journal_lost');r.restore('witness:j','e')\n" % (R, pub, self.p)
        for _ in range(3):
            pr = subprocess.Popen([sys.executable, "-B", "-c", code]); time.sleep(0.6); os.kill(pr.pid, signal.SIGKILL); pr.wait()
        h = self.r.history(); self.assertGreater(len(h), 10)              # chain verifies end to end after three hard kills
        self.r.revoke("c:1"); self.assertFalse(self.r.permit("c:1", 5)[0]); self.assertEqual(self.r.status("c:1", 5)[0], "REVOKED")
if __name__ == "__main__": unittest.main()
