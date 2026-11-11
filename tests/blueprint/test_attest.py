import os, shutil, sys, tempfile, time, unittest
from horizon.assurance import durable as D
from horizon.assurance import attest as A
from horizon.assurance.registry import AssuranceClaim
from horizon.authz.keys import Signer, TrustStore
BIND = {k: f"{k}@1" for k in D.BINDING_FIELDS}
NOW = [1000.0]


class T(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True); self.root = os.path.join(self.d, "code"); os.mkdir(self.root)
        for n, t in (("broker.py", "A=1\n"), ("sandbox.py", "B=2\n")): open(os.path.join(self.root, n), "w").write(t)
        self.inst = Signer.generate("in1", D.INSTALLER_ROLE); self.iss = Signer.generate("ik1", D.CLAIM_ISSUER_ROLE); self.rogue = Signer.generate("rg1", "reproducer"); self.ts = TrustStore(clock=lambda: NOW[0])
        for s in (self.inst, self.iss, self.rogue): self.ts.add(s.kid, s.iss, s.public_raw(), not_before=0, not_after=10 ** 9)
        self.controls = [A.Control("control:broker", "broker", ("broker.py",), {"allow": ["x"]}), A.Control("control:sandbox", "sandbox", ("sandbox.py",), None)]
        self.epoch = [5]; NOW[0] = 1000.0; self.reg = D.DurableRegistry(os.path.join(self.d, "a.db"), self.ts, lambda: NOW[0], attested_nodes_only=True)

    def att(self, **kw): return A.sign_control_attestation(self.controls, self.root, host_id="h1", epoch=5, issued_at=900, expires_at=2000, signer=kw.pop("signer", self.inst), **kw)
    def claim(self, att, cid="c:1"):
        for c in self.controls: self.reg.set_node_attested(att, c.control_id)
        cl = AssuranceClaim(cid, ("fs",), 5, 3000, tuple(c.control_id for c in self.controls), tuple((c.control_id, att["body"]["controls"][c.control_id]) for c in self.controls)); self.reg.issue(D.sign_claim(cl, BIND, self.iss)); return cid
    def gate(self, att, cid, **kw): return A.make_gate(self.reg, cid, att, self.ts, self.controls, self.root, epoch_now=lambda: self.epoch[0], clock=lambda: NOW[0], **kw)

    # --- measurement ------------------------------------------------------------------------------------------------------------------------------------
    def test_measure_is_deterministic_and_sensitive_to_every_input(self):
        a = A.measure(self.controls, self.root); self.assertEqual(a, A.measure(self.controls, self.root))
        open(os.path.join(self.root, "broker.py"), "a").write("#"); b = A.measure(self.controls, self.root); self.assertNotEqual(a["control:broker"], b["control:broker"]); self.assertEqual(a["control:sandbox"], b["control:sandbox"])
        c = A.Control("control:broker", "broker", ("broker.py",), {"allow": ["y"]}); self.assertNotEqual(A.measure_one(c, self.root), b["control:broker"])        # config change
        k = A.Control("control:broker", "gate", ("broker.py",), {"allow": ["x"]}); self.assertNotEqual(A.measure_one(k, self.root), A.measure_one(self.controls[0], self.root))   # kind change

    def test_unmeasurable_inputs(self):
        for c in (A.Control("control:m", "broker", ("nope.py",)), A.Control("control:e", "broker", ("../escape.py",)), A.Control("control:j", "policy", (), object())): self.assertEqual(A.measure_one(c, self.root), A.UNMEASURABLE)
        os.symlink("/etc/passwd", os.path.join(self.root, "ln.py")); self.assertEqual(A.measure_one(A.Control("control:l", "broker", ("ln.py",)), self.root), A.UNMEASURABLE)

    # --- attestation ------------------------------------------------------------------------------------------------------------------------------------
    def test_installer_role_only_and_refusals(self):
        with self.assertRaises(A.AttestError) as c: self.att(signer=self.rogue)
        self.assertEqual(c.exception.code, "WRONG_ISSUER_ROLE")
        for bad in ([], [A.Control("control:x", "broker", ("missing.py",))], [A.Control("noprefix", "broker", ("broker.py",))], [self.controls[0], self.controls[0]]):
            with self.assertRaises(A.AttestError): A.sign_control_attestation(bad, self.root, host_id="h", epoch=1, issued_at=1, expires_at=2, signer=self.inst)
        with self.assertRaises(A.AttestError): A.sign_control_attestation(self.controls, self.root, host_id="h", epoch=1, issued_at=5, expires_at=5, signer=self.inst)

    def test_verify_rejects_forgery_tamper_expiry_epoch_host(self):
        a = self.att(); self.assertEqual(A.verify_control_attestation(a, self.ts, 1000, epoch_now=5, host_id="h1")["host_id"], "h1")
        import copy
        t = copy.deepcopy(a); t["body"]["controls"]["control:broker"] = "sha256:" + "0" * 64
        for bad, now, kw in ((t, 1000, {}), ({**a, "sig": "00" * 64}, 1000, {}), (a, 899, {}), (a, 2000, {}), (a, 1000, {"epoch_now": 6}), (a, 1000, {"host_id": "h2"})):
            with self.assertRaises(A.AttestError): A.verify_control_attestation(bad, self.ts, now, **kw)
        r = Signer.generate("in2", D.INSTALLER_ROLE)      # right role, key not in the trust store
        fa = A.sign_control_attestation(self.controls, self.root, host_id="h1", epoch=5, issued_at=900, expires_at=2000, signer=r)
        with self.assertRaises(A.AttestError): A.verify_control_attestation(fa, self.ts, 1000)
        ra = A.sign_control_attestation(self.controls, self.root, host_id="h1", epoch=5, issued_at=900, expires_at=2000, signer=self.inst); self.ts.revoke("in1")
        with self.assertRaises(A.AttestError): A.verify_control_attestation(ra, self.ts, 1000)

    def test_validly_signed_attestation_containing_unmeasurable_is_rejected(self):
        body = {"kind": "control-attestation", "host_id": "h1", "epoch": 5, "issued_at": 900, "expires_at": 2000, "controls": {"control:broker": A.UNMEASURABLE}}
        att = {"body": body, "kid": self.inst.kid, "sig": self.inst.sign(A._canon(body)).hex()}
        with self.assertRaises(A.AttestError) as c: A.verify_control_attestation(att, self.ts, 1000)
        self.assertEqual(c.exception.code, "BAD_ATTESTATION")

    # --- registry binding -------------------------------------------------------------------------------------------------------------------------------
    def test_unattested_set_node_is_inert_in_attested_mode(self):
        a = self.att(); cid = self.claim(a); self.assertEqual(self.reg.status(cid, 5)[0], "VALID")
        self.reg.set_node("control:broker", "sha256:forged"); self.assertEqual(self.reg.status(cid, 5)[0], "VALID")           # forged unsigned write ignored, still the attested digest
        reg2 = D.DurableRegistry(os.path.join(self.d, "b.db"), self.ts, lambda: NOW[0], attested_nodes_only=True); reg2.set_node("control:broker", "x")
        cl = AssuranceClaim("c:9", ("fs",), 5, 3000, ("control:broker",), (("control:broker", "x"),)); reg2.issue(D.sign_claim(cl, BIND, self.iss)); self.assertNotEqual(reg2.status("c:9", 5)[0], "VALID")   # an unsigned node can never make a claim valid

    def test_default_mode_still_accepts_plain_nodes(self):
        r = D.DurableRegistry(os.path.join(self.d, "c.db"), self.ts, lambda: NOW[0]); r.set_node("control:broker", "x")
        r.issue(D.sign_claim(AssuranceClaim("c:8", ("fs",), 5, 3000, ("control:broker",), (("control:broker", "x"),)), BIND, self.iss)); self.assertEqual(r.status("c:8", 5)[0], "VALID")

    def test_attestation_for_a_different_digest_or_by_wrong_role_does_not_set_the_node(self):
        a = self.att(); self.reg._write("NODE", "control:broker", {"digest": "sha256:other", "att": a}); self.reg._write("NODE", "control:sandbox", {"digest": a["body"]["controls"]["control:sandbox"], "att": {**a, "kid": "rg1"}})
        cl = AssuranceClaim("c:7", ("fs",), 5, 3000, ("control:broker", "control:sandbox"), (("control:broker", a["body"]["controls"]["control:broker"]), ("control:sandbox", a["body"]["controls"]["control:sandbox"]))); self.reg.issue(D.sign_claim(cl, BIND, self.iss))
        self.assertNotEqual(self.reg.status("c:7", 5)[0], "VALID")
        for k in ("kind", "controls"):                      # attestation body of the wrong kind / controls missing the subject
            bad = {**a, "body": {**a["body"], k: "x" if k == "kind" else {}}}; self.reg._write("NODE", "control:broker", {"digest": a["body"]["controls"]["control:broker"], "att": bad})
        self.assertNotEqual(self.reg.status("c:7", 5)[0], "VALID")

    def test_node_digest_must_equal_the_attested_digest_and_kind_must_match(self):
        a = self.att(); real = a["body"]["controls"]["control:broker"]
        def valid_with(node_digest, att):           # claim bound to exactly the digest written into the node: only the registry's own checks can make it non-VALID
            r = D.DurableRegistry(os.path.join(self.d, f"n{abs(hash((node_digest, str(att['body']['kind']))))}.db"), self.ts, lambda: NOW[0], attested_nodes_only=True)
            r._write("NODE", "control:broker", {"digest": node_digest, "att": att})
            r.issue(D.sign_claim(AssuranceClaim("c:n", ("fs",), 5, 3000, ("control:broker",), (("control:broker", node_digest),)), BIND, self.iss)); return r.status("c:n", 5)[0] == "VALID"
        self.assertTrue(valid_with(real, a))                                              # control: the honest path works
        self.assertFalse(valid_with("sha256:" + "1" * 64, a))                             # node digest not the one the installer signed for this control
        body = {**a["body"], "kind": "something-else"}; other = {"body": body, "kid": self.inst.kid, "sig": self.inst.sign(A._canon(body)).hex()}
        self.assertFalse(valid_with(real, other))                                         # right signature and digests, wrong attestation kind

    # --- gate -------------------------------------------------------------------------------------------------------------------------------------------
    def test_gate_allows_when_installed_matches_attested(self):
        a = self.att(); cid = self.claim(a); self.assertEqual(self.gate(a, cid)(), (True, ""))

    def test_gate_denies_and_invalidates_on_drift(self):
        a = self.att(); cid = self.claim(a); g = self.gate(a, cid); open(os.path.join(self.root, "broker.py"), "w").write("A=999\n")
        ok, why = g(); self.assertFalse(ok); self.assertEqual(why, "CONTROL_DRIFT:control:broker")
        self.assertNotEqual(self.reg.status(cid, 5)[0], "VALID")                              # the claim is now invalid for every other process too
        open(os.path.join(self.root, "broker.py"), "w").write("A=1\n"); self.assertFalse(g()[0])      # reverting the file does NOT silently restore: invalidation needs explicit restore with evidence

    def test_gate_denies_deleted_control_expired_stale_epoch_wrong_host(self):
        a = self.att(); cid = self.claim(a); os.unlink(os.path.join(self.root, "sandbox.py")); self.assertEqual(self.gate(a, cid)()[1], "CONTROL_DRIFT:control:sandbox")
        open(os.path.join(self.root, "sandbox.py"), "w").write("B=2\n"); self.reg.restore("control:sandbox", "operator re-checked")
        NOW[0] = 2500; self.assertEqual(self.gate(a, cid)(), (False, "ATTESTATION_EXPIRED")); NOW[0] = 1000; self.epoch[0] = 6; self.assertEqual(self.gate(a, cid)(), (False, "STALE_EPOCH")); self.epoch[0] = 5
        self.assertEqual(self.gate(a, cid, host_id="other")(), (False, "WRONG_HOST"))

    def test_gate_denies_unknown_or_revoked_claim_and_swallows_errors(self):
        a = self.att(); cid = self.claim(a); self.assertFalse(self.gate(a, "c:none")()[0]); self.reg.revoke(cid); self.assertFalse(self.gate(a, cid)()[0])
        g = A.make_gate(self.reg, cid, {"junk": 1}, self.ts, self.controls, self.root, epoch_now=lambda: 5, clock=lambda: NOW[0]); self.assertEqual(g(), (False, "BAD_ATTESTATION"))
        g = A.make_gate(self.reg, cid, a, self.ts, self.controls, self.root, epoch_now=lambda: 1 / 0, clock=lambda: NOW[0]); self.assertEqual(g(), (False, "GATE_ERROR:ZeroDivisionError"))

    def test_gate_with_missing_control_in_supplied_set_is_drift(self):
        a = self.att(); cid = self.claim(a); g = A.make_gate(self.reg, cid, a, self.ts, self.controls[:1], self.root, epoch_now=lambda: 5, clock=lambda: NOW[0]); self.assertEqual(g(), (False, "CONTROL_DRIFT:control:sandbox"))

    def test_gate_plugs_into_the_kernel_and_blocks_before_the_effect(self):
        from horizon.authz.gateway import NonceStore, Verifier
        from horizon.authz.issuer import LocalIssuer
        from horizon.effects.filesink import FileSink
        from horizon.effects.kernel import EffectKernel, FileAdapter
        from horizon.effects.ledger import EffectLedger
        a = self.att(); cid = self.claim(a); iss = LocalIssuer(lambda ce: True); v = Verifier(iss.trust_store(), NonceStore(), issuer="iss", audience="gw", contract_version="c1", policy_version=lambda: "p1")
        out = os.path.join(self.d, "out"); os.mkdir(out); k = EffectKernel(v, EffectLedger(os.path.join(self.d, "l.db")), {"file": FileAdapter(FileSink(os.path.realpath(out), os.path.join(self.d, "j")))}, gate=self.gate(a, cid))
        def go(name, eid):
            p = {"path": os.path.join(os.path.realpath(out), name), "data": b"x"}; ce = k.effect_for("file", p, tenant="t", server_id="s", session_id="x", principal="p"); return k.execute(iss.mint(ce), "file", ce, p, eid)
        self.assertEqual(go("ok.txt", "e1")["status"], "ALLOW_COMMITTED")
        open(os.path.join(self.root, "broker.py"), "w").write("tampered\n"); r = go("no.txt", "e2")
        self.assertEqual((r["status"], r["code"], r["effect"]), ("BLOCKED", "ASSURANCE_DENIED", "DID_NOT_HAPPEN")); self.assertIn("CONTROL_DRIFT", r["why"]); self.assertFalse(os.path.exists(os.path.join(out, "no.txt")))
if __name__ == "__main__": unittest.main()
