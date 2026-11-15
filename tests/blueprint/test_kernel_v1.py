import os, shutil, sys, tempfile, unittest
from horizon.authz.gateway import NonceStore, Verifier
from horizon.authz.issuer import IssuerDenied, LocalIssuer, ProcessIssuer
from horizon.authz.keys import Signer, TrustStore
from horizon.contracts.v1 import ContractError, EMPTY_CHAIN
from horizon.effects import netbroker as N, procbroker as Pr
from horizon.effects.filesink import FileSink
from horizon.effects.kernel import Context, EffectKernel, FileAdapter, IdentityError, NetAdapter, ProcAdapter, make_enforcer_signer, verify_receipt
from horizon.effects.ledger import EffectLedger
from horizon.effects.mcp_gateway import Gateway
from tests.blueprint.test_exec_brokers import H, serve

NOW = [1_000_000.0]
LINEAGE = ("sha256:" + "a" * 64,)


class K(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.srv = serve(H); cls.port = cls.srv.server_address[1]
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()

    def setUp(self):
        H.hits.clear(); NOW[0] = 1_000_000.0; self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.root = os.path.realpath(os.path.join(self.d, "r")); os.mkdir(self.root)
        self.iss = LocalIssuer(lambda ce: True, require_v1=True); self.v = Verifier(self.iss.trust_store(), NonceStore(), issuer="iss", audience="gw", contract_version="c1", policy_version=lambda: "p1")
        self.ledger = EffectLedger(os.path.join(self.d, "l.db")); self.rs = make_enforcer_signer(); self.seen = {}
        self.nb = N.NetBroker([N.Allow("http", "svc.test", self.port, allow_private=True)], resolver=lambda h, p: ["127.0.0.1"], timeout=3)
        self.pb = Pr.ProcBroker((Pr.Rule(sys.executable, (r"-V",), timeout=5), Pr.Rule("/bin/sleep", (r"5",), timeout=0.4)))
        self.k = EffectKernel(self.v, self.ledger, {"file": FileAdapter(FileSink(self.root, os.path.join(self.d, "j"))), "net": NetAdapter(self.nb, witness=lambda e: self.seen.get(e)), "proc": ProcAdapter(self.pb, witness=lambda e: self.seen.get(e))},
                              receipt_signer=self.rs, clock=lambda: NOW[0])
        self.et = TrustStore(); self.et.add(self.rs.kid, "enforcer", self.rs.public_raw(), not_before=0, not_after=2 ** 40)

    def ctx(self, eid, **kw):
        base = dict(effect_id=eid, tenant_id="t1", agent_id="a1", session_id="s1", principal_id="p1", tool_server_id="srv", tool_id="tool", transport="mcp-stdio", purpose="task", policy_digest="sha256:" + "b" * 64, policy_epoch=3,
                    deadline=int(NOW[0]) + 30, nonce="n-" + eid, trace_id="tr-" + eid, assurance_claim_id="claim:1", assurance_epoch=7, artifact_lineage_digests=LINEAGE)
        base.update(kw); return Context(**base)
    def go(self, kind, payload, eid, **kw):
        prep = self.k.prepare(kind, payload, self.ctx(eid, **kw)); return prep, self.k.execute_v1(self.iss.mint(prep.ce, prep.v1), kind, prep, payload)
    def f(self, name="a.txt", data=b"x"): return {"path": os.path.join(self.root, name), "data": data}
    def url(self, p="/a"): return f"http://svc.test:{self.port}{p}"

    # --- receipts: consistent across sinks -------------------------------------------------------------------------------------------------------------
    def test_receipts_are_signed_complete_and_consistent_across_file_net_proc(self):
        outs = {"file": self.go("file", self.f(), "f1"), "net": self.go("net", {"method": "GET", "url": self.url()}, "n1"), "proc": self.go("proc", {"argv": [sys.executable, "-V"]}, "p1")}
        keysets = set()
        for kind, (prep, out) in outs.items():
            self.assertEqual(out["status"], "ALLOW_COMMITTED", kind); b = verify_receipt(out["receipt_v1"], self.et); keysets.add(tuple(sorted(b)))
            self.assertEqual((b["state"], b["effect_digest"], b["tenant_id"], b["assurance_claim_id"], b["assurance_epoch"], b["policy_epoch"], b["idempotency_key"], b["trace_id"]), ("COMMITTED", prep.v1.digest(), "t1", "claim:1", 7, 3, prep.v1.effect_id, "tr-" + prep.v1.effect_id))
        self.assertEqual(len(keysets), 1)                                                                    # identical metadata shape for every supported effect
        self.assertEqual([verify_receipt(o["receipt_v1"], self.et)["witness_kind"] for _, o in outs.values()], ["sink-journal", "broker-report", "broker-report"])

    def test_only_sink_journal_or_receiver_witnesses_count_as_independent(self):
        from horizon.contracts.v1 import EffectReceiptV1, EffectState
        h = "sha256:" + "c" * 64
        for kind, ind in (("sink-journal", True), ("receiver", True), ("broker-report", False), ("caller-supplied", False), (None, False)): self.assertEqual(EffectReceiptV1("e", h, EffectState.COMMITTED, "w", None, kind).is_independent_evidence(), ind, kind)
        with self.assertRaises(ContractError): EffectReceiptV1("e", h, EffectState.COMMITTED, "w", None, "bogus").validate()

    def test_unknown_receipt_has_no_witness_and_reconcile_witness_is_not_independent_unless_declared(self):
        prep, out = self.go("net", {"method": "GET", "url": self.url("/redir")}, "n2"); b = verify_receipt(out["receipt_v1"], self.et)
        self.assertEqual((out["status"], b["state"], b["witness"], b["witness_kind"]), ("UNKNOWN", "UNKNOWN", None, None))
        self.assertEqual(self.k.reconcile_v1("net", prep)["status"], "UNKNOWN")                              # no witness answer: still no receipt of a resolution
        self.seen["n2"] = True; r = self.k.reconcile_v1("net", prep); b = verify_receipt(r["receipt_v1"], self.et)
        self.assertEqual((r["status"], b["state"], b["witness_kind"]), ("RECONCILED_COMMITTED", "RECONCILED_COMMITTED", "caller-supplied"))
        from horizon.contracts.v1 import EffectReceiptV1, EffectState
        self.assertFalse(EffectReceiptV1("e", b["effect_digest"], EffectState.RECONCILED_COMMITTED, b["witness"], None, b["witness_kind"]).is_independent_evidence())

    def test_file_reconcile_witness_is_the_sink_journal(self):
        prep, out = self.go("file", self.f(), "f2", )
        self.assertEqual(out["status"], "ALLOW_COMMITTED"); self.ledger.finish if False else None
        k2 = self.k; k2.ledger._tx(lambda: k2.ledger._move("f2", "UNKNOWN", {"t": 1})) if self.ledger.state("f2") == "COMMITTED" and False else None
        # drive a real UNKNOWN: fault after begin for a file effect, then reconcile from the sink observation
        p2 = self.f("b.txt"); prep2 = self.k.prepare("file", p2, self.ctx("f3")); o2 = self.k.execute_v1(self.iss.mint(prep2.ce, prep2.v1), "file", prep2, p2, fault=lambda: (_ for _ in ()).throw(OSError("x")))
        self.assertEqual(o2["status"], "UNKNOWN"); r = self.k.reconcile_v1("file", prep2); b = verify_receipt(r["receipt_v1"], self.et)
        self.assertEqual((r["status"], b["witness_kind"]), ("RECONCILED_BLOCKED", "sink-journal")); self.assertFalse(os.path.exists(p2["path"]))

    def test_duplicate_call_returns_no_second_receipt(self):
        prep, out = self.go("file", self.f("d.txt"), "d1"); again = self.k.execute_v1(self.iss.mint(prep.ce, prep.v1), "file", prep, self.f("d.txt")); self.assertEqual((again["status"], "receipt_v1" in again), ("DUPLICATE", False))

    def test_receipt_tamper_wrong_role_and_unknown_key_fail_verification(self):
        _, out = self.go("file", self.f("t.txt"), "t1"); rec = out["receipt_v1"]; verify_receipt(rec, self.et)
        import copy
        t = copy.deepcopy(rec); t["body"]["state"] = "BLOCKED"
        for bad in (t, {**rec, "sig": "00" * 64}, {**rec, "kid": "zz"}, {"body": {}}, {}):
            with self.assertRaises(ContractError): verify_receipt(bad, self.et)
        wrong = TrustStore(); wrong.add(self.rs.kid, "assurance-issuer", self.rs.public_raw(), not_before=0, not_after=2 ** 40)
        with self.assertRaises(ContractError): verify_receipt(rec, wrong)                                      # key registered under another role

    # --- identity separation ---------------------------------------------------------------------------------------------------------------------------
    def test_enforcement_identity_must_differ_from_the_permit_issuer(self):
        issuer_key = Signer(self.iss.kid, "enforcer", self.iss._s._p)                                          # same private key relabelled with the enforcer role
        k = EffectKernel(self.v, self.ledger, {"file": FileAdapter(FileSink(self.root, os.path.join(self.d, "j2")))}, receipt_signer=issuer_key)
        prep = k.prepare("file", self.f(), self.ctx("i1"))
        with self.assertRaises(IdentityError): k.execute_v1(self.iss.mint(prep.ce, prep.v1), "file", prep, self.f())
        for bad in (None, Signer.generate("x", "iss")):
            k2 = EffectKernel(self.v, self.ledger, {"file": FileAdapter(FileSink(self.root, os.path.join(self.d, "j3")))}, receipt_signer=bad)
            with self.assertRaises(IdentityError): k2.execute_v1("t", "file", prep, self.f())
        self.assertFalse(os.path.exists(self.f()["path"]))                                                     # refused before anything ran

    def test_gateway_refuses_to_start_with_a_shared_identity(self):
        li = LocalIssuer(lambda ce: True, require_v1=True)
        with self.assertRaises(IdentityError): Gateway(self.root, os.path.join(self.d, "jj"), os.path.join(self.d, "ll.db"), issuer=li, receipt_signer=Signer(li.kid, "enforcer", li._s._p))

    # --- V1 binding -------------------------------------------------------------------------------------------------------------------------------------
    def test_v1_binding_checks(self):
        prep = self.k.prepare("file", self.f("v.txt"), self.ctx("v1")); tok = self.iss.mint(prep.ce, prep.v1)
        self.assertEqual(self.k.execute_v1(tok, "file", prep, self.f("other.txt"))["code"], "V1_BINDING_MISMATCH")                                              # payload differs from V1 target
        self.assertEqual(self.k.execute_v1(tok, "file", prep, self.f("v.txt", b"changed"))["code"], "V1_BINDING_MISMATCH")                                      # payload differs from V1 arguments digest
        from horizon.effects.canonical import CanonicalEffect
        stripped = type(prep)(CanonicalEffect(prep.ce.tenant, prep.ce.server_id, prep.ce.session_id, prep.ce.principal, prep.ce.effect, prep.ce.target_kind, prep.ce.target_raw, {"sha256": prep.ce.args["sha256"]}), prep.v1)
        self.assertEqual(self.k.execute_v1(self.iss.mint(prep.ce, prep.v1), "file", stripped, self.f("v.txt"))["code"], "V1_BINDING_MISMATCH")                    # legacy ce without the V1 digest
        self.assertEqual(self.k.execute_v1(tok, "file", prep, self.f("v.txt"))["status"], "ALLOW_COMMITTED")                                                      # control: the honest call works

    def test_deadline_is_enforced_before_the_effect(self):
        prep = self.k.prepare("file", self.f("dl.txt"), self.ctx("dl1")); tok = self.iss.mint(prep.ce, prep.v1); NOW[0] += 31
        r = self.k.execute_v1(tok, "file", prep, self.f("dl.txt")); self.assertEqual((r["status"], r["code"], r["effect"]), ("BLOCKED", "DEADLINE_EXCEEDED", "DID_NOT_HAPPEN")); self.assertFalse(os.path.exists(self.f("dl.txt")["path"]))

    def test_prepare_rejects_invalid_v1_inputs(self):
        for kind, payload, kw in (("file", self.f(), {"assurance_claim_id": None, "assurance_epoch": None}), ("file", self.f(), {"idempotency_key": ""}), ("net", {"method": "GET", "url": self.url()}, {"artifact_lineage_digests": None}),
                                  ("file", self.f(), {"transport": "carrier-pigeon"}), ("file", self.f(), {"policy_digest": "nope"})):
            with self.assertRaises(ContractError, msg=str((kind, kw))): self.k.prepare(kind, payload, self.ctx("x1", **kw))

    def test_require_v1_issuer_refuses_missing_mismatched_or_invalid_v1(self):
        prep = self.k.prepare("file", self.f(), self.ctx("r1"))
        for v1 in (None, "x"):
            with self.assertRaises(IssuerDenied) as c: self.iss.mint(prep.ce, v1)
            self.assertEqual(str(c.exception), "V1_REQUIRED")
        other = self.k.prepare("file", self.f("zz.txt"), self.ctx("r1")).v1
        with self.assertRaises(IssuerDenied) as c: self.iss.mint(prep.ce, other)
        self.assertEqual(str(c.exception), "V1_BINDING_MISMATCH")
        import dataclasses
        bad = dataclasses.replace(prep.v1, tenant_id="t2"); ce2 = type(prep.ce)(prep.ce.tenant, prep.ce.server_id, prep.ce.session_id, prep.ce.principal, prep.ce.effect, prep.ce.target_kind, prep.ce.target_raw, {**prep.ce.args, "v1": bad.digest()})
        with self.assertRaises(IssuerDenied) as c: self.iss.mint(ce2, bad)
        self.assertEqual(str(c.exception), "V1_BINDING_MISMATCH")
        inv = dataclasses.replace(prep.v1, assurance_claim_id=None, assurance_epoch=None)
        with self.assertRaises(IssuerDenied) as c: self.iss.mint(prep.ce, inv)
        self.assertEqual(str(c.exception), "V1_INVALID")

    def test_process_issuer_enforces_v1_end_to_end(self):
        pi = ProcessIssuer(self.root, require_v1=True); self.addCleanup(pi.close)
        v = Verifier(pi.trust_store(), NonceStore(), issuer="iss", audience="gw", contract_version="c1", policy_version=lambda: "p1")
        k = EffectKernel(v, EffectLedger(os.path.join(self.d, "pl.db")), {"file": FileAdapter(FileSink(self.root, os.path.join(self.d, "pj")))}, receipt_signer=make_enforcer_signer(), clock=lambda: NOW[0])
        p = self.f("pi.txt"); prep = k.prepare("file", p, self.ctx("pi1")); self.assertEqual(k.execute_v1(pi.mint(prep.ce, prep.v1), "file", prep, p)["status"], "ALLOW_COMMITTED")
        with self.assertRaises(IssuerDenied) as c: pi.mint(prep.ce, None)
        self.assertEqual(str(c.exception), "V1_REQUIRED")

    # --- gateway on the kernel --------------------------------------------------------------------------------------------------------------------------
    def test_gateway_uses_the_kernel_and_returns_a_verifiable_receipt(self):
        src = open(os.path.join(os.path.dirname(__file__), "..", "..", "horizon", "effects", "mcp_gateway.py")).read()
        self.assertNotIn("ProtectedFileWriter", src); self.assertIn("kernel.execute_v1", src); self.assertNotIn("Signer.generate", src)
        g = Gateway(self.root, os.path.join(self.d, "gj"), os.path.join(self.d, "gl.db"), assurance_claim=("claim:test", 4))
        r = g.call_write({"path": "gw.txt", "content": "hi", "effect_id": "g1"}); self.assertFalse(r["isError"])
        b = verify_receipt(r["structuredContent"]["receipt_v1"], g.enforcer_trust); self.assertEqual((b["assurance_claim_id"], b["assurance_epoch"], b["witness_kind"], b["tool_server_id"]), ("claim:test", 4, "sink-journal", "srv-files"))
        r2 = g.call_write({"path": "../x.txt", "content": "hi", "effect_id": "g2"}); self.assertEqual(r2["structuredContent"]["code"], "POLICY_DENIED")
if __name__ == "__main__": unittest.main()
