import os, shutil, sys, tempfile, threading, unittest
from horizon.authz.gateway import NonceStore, Verifier
from horizon.authz.issuer import LocalIssuer
from horizon.effects import netbroker as N, procbroker as Pr
from horizon.effects.filesink import FileSink, ProtectedFileWriter
from horizon.effects.kernel import EffectKernel, FileAdapter, NetAdapter, ProcAdapter, Outcome
from horizon.effects.ledger import EffectLedger
from tests.blueprint.test_exec_brokers import serve, H


class K(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.srv = serve(H); cls.port = cls.srv.server_address[1]
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()

    def setUp(self):
        H.hits.clear(); self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.root = os.path.realpath(os.path.join(self.d, "r")); os.mkdir(self.root)
        self.iss = LocalIssuer(lambda ce: True)            # the issuer's own policy is tested in test_issuer; here every permit is mintable so the KERNEL's checks are what is exercised
        self.v = Verifier(self.iss.trust_store(), NonceStore(), issuer="iss", audience="gw", contract_version="c1", policy_version=lambda: "p1")
        self.ledger = EffectLedger(os.path.join(self.d, "l.db")); self.sink = FileSink(self.root, os.path.join(self.d, "j"))
        self.seen = {}; self.gate_ok = True
        self.nb = N.NetBroker([N.Allow("http", "svc.test", self.port, allow_private=True)], resolver=lambda h, p: ["127.0.0.1"], timeout=3)
        self.pb = Pr.ProcBroker((Pr.Rule(sys.executable, (r"-V",), cwd_root=self.root, timeout=5), Pr.Rule("/bin/sleep", (r"5",), timeout=0.4)))
        self.k = EffectKernel(self.v, self.ledger, {"file": FileAdapter(self.sink), "net": NetAdapter(self.nb, witness=lambda e: self.seen.get(e)), "proc": ProcAdapter(self.pb, witness=lambda e: self.seen.get(e))}, gate=lambda: (self.gate_ok, "g"))

    def ce(self, kind, p): return self.k.effect_for(kind, p, tenant="t1", server_id="s", session_id="x", principal="p")
    def run_(self, kind, p, eid, **kw):
        ce = self.ce(kind, p); return self.k.execute(self.iss.mint(ce), kind, ce, p, eid, **kw)
    def url(self, path="/a"): return f"http://svc.test:{self.port}{path}"

    # --- file -------------------------------------------------------------------------------------------------------------------------------------------
    def test_file_commit_duplicate_and_replay(self):
        p = {"path": os.path.join(self.root, "a.txt"), "data": b"hello"}; r = self.run_("file", p, "e1")
        self.assertEqual((r["status"], r["effect"]), ("ALLOW_COMMITTED", "HAPPENED")); self.assertEqual(open(p["path"], "rb").read(), b"hello"); self.assertEqual(self.ledger.state("e1"), "COMMITTED")
        ce = self.ce("file", p); tok = self.iss.mint(ce); self.assertEqual(self.k.execute(tok, "file", ce, p, "e1")["status"], "DUPLICATE")
        self.assertEqual(self.k.execute(tok, "file", ce, {**p, "path": os.path.join(self.root, "b.txt")}, "e2")["code"], "DATA_NOT_BOUND_TO_PERMIT")
        p2 = {"path": os.path.join(self.root, "c.txt"), "data": b"z"}; ce2 = self.ce("file", p2); t2 = self.iss.mint(ce2)
        self.assertEqual(self.k.execute(t2, "file", ce2, p2, "e3")["status"], "ALLOW_COMMITTED"); r = self.k.execute(t2, "file", ce2, p2, "e4")
        self.assertEqual((r["status"], r["effect"]), ("BLOCKED", "DID_NOT_HAPPEN")); self.assertIn(r["code"], ("REPLAY", "NONCE_REUSE"))

    def test_file_parity_with_the_legacy_writer_on_the_same_cases(self):
        w = ProtectedFileWriter(self.v, EffectLedger(os.path.join(self.d, "l2.db")), FileSink(self.root, os.path.join(self.d, "j2")), gate=lambda: (self.gate_ok, "g")); pairs = []
        for i, (name, data, gate) in enumerate((("p1.txt", b"x", True), ("p2.txt", b"y", False), ("nodir/p3.txt", b"z", True))):
            self.gate_ok = gate; p = {"path": os.path.join(self.root, name), "data": data}; ce = self.ce("file", p)
            old = w.write(self.iss.mint(ce), ce, data, f"o{i}"); new = self.k.execute(self.iss.mint(ce), "file", ce, p, f"n{i}")
            pairs.append(((old["status"], old.get("code")), (new["status"], new["code"] or None)))
        for old, new in pairs: self.assertEqual(old[0], new[0]); self.assertEqual(old[1] or None, new[1])
        # documented, pre-existing conservative behaviour: a write into a missing subdirectory is UNKNOWN (generic upstream failure), not BLOCKED
        self.assertEqual([o[0] for o, _ in pairs], ["ALLOW_COMMITTED", "BLOCKED", "UNKNOWN"])

    # --- network ----------------------------------------------------------------------------------------------------------------------------------------
    def test_net_commit_and_receipt(self):
        r = self.run_("net", {"method": "GET", "url": self.url()}, "n1")
        self.assertEqual((r["status"], r["receipt"]["http_status"]), ("ALLOW_COMMITTED", 200)); self.assertEqual(len(H.hits), 1)

    def test_net_payload_must_match_the_permit(self):
        p = {"method": "POST", "url": self.url("/a"), "body": b"one"}; ce = self.ce("net", p); tok = self.iss.mint(ce)
        for bad in ({**p, "body": b"two"}, {**p, "url": self.url("/b")}, {**p, "method": "GET"}, {**p, "headers": {"X": "1"}}):
            self.assertEqual(self.k.execute(tok, "net", ce, bad, "x")["code"], "DATA_NOT_BOUND_TO_PERMIT")
        self.assertEqual(H.hits, [])

    def test_net_policy_refusal_before_send_is_blocked_and_nothing_is_sent(self):
        r = self.run_("net", {"method": "GET", "url": f"http://other.test:{self.port}/a"}, "n2")
        self.assertEqual((r["status"], r["effect"], r["code"]), ("BLOCKED", "DID_NOT_HAPPEN", "OUTSIDE_ALLOWED_TARGETS")); self.assertEqual(H.hits, []); self.assertEqual(self.ledger.state("n2"), "BLOCKED")

    def test_net_redirect_refusal_is_unknown_because_the_request_completed(self):
        r = self.run_("net", {"method": "GET", "url": self.url("/redir")}, "n3")
        self.assertEqual((r["status"], r["code"], r["effect"]), ("UNKNOWN", "REDIRECT_REFUSED", "UNDETERMINED")); self.assertEqual(len(H.hits), 1); self.assertEqual(self.ledger.state("n3"), "UNKNOWN")

    def test_reconcile_only_from_a_witness_and_none_leaves_unknown(self):
        self.run_("net", {"method": "GET", "url": self.url("/redir")}, "n4")
        self.assertEqual(self.k.reconcile("net", "n4"), "UNKNOWN")                                  # witness returns None (no record): never coerced
        self.seen["n4"] = False; self.assertEqual(self.k.reconcile("net", "n4"), "RECONCILED_BLOCKED")
        self.run_("net", {"method": "GET", "url": self.url("/redir")}, "n5"); self.seen["n5"] = True; self.assertEqual(self.k.reconcile("net", "n5"), "RECONCILED_COMMITTED")
        self.assertEqual(self.k.reconcile("net", "n5"), "RECONCILED_COMMITTED")                     # idempotent: a resolved effect is not re-resolved

    def test_no_witness_adapter_never_resolves(self):
        k = EffectKernel(self.v, self.ledger, {"net": NetAdapter(self.nb)}); p = {"method": "GET", "url": self.url("/redir")}
        ce = k.effect_for("net", p, tenant="t1", server_id="s", session_id="x", principal="p"); k.execute(self.iss.mint(ce), "net", ce, p, "n6"); self.assertEqual(k.reconcile("net", "n6"), "UNKNOWN")

    def test_witness_that_raises_leaves_unknown(self):
        def boom(e): raise RuntimeError("x")
        k = EffectKernel(self.v, self.ledger, {"net": NetAdapter(self.nb, witness=boom)}); p = {"method": "GET", "url": self.url("/redir")}
        ce = k.effect_for("net", p, tenant="t1", server_id="s", session_id="x", principal="p"); k.execute(self.iss.mint(ce), "net", ce, p, "n7"); self.assertEqual(k.reconcile("net", "n7"), "UNKNOWN")

    # --- process ----------------------------------------------------------------------------------------------------------------------------------------
    def test_proc_commit_with_receipt_and_disallowed_program_blocked(self):
        r = self.run_("proc", {"argv": [sys.executable, "-V"]}, "p1"); self.assertEqual((r["status"], r["receipt"]["exit"]), ("ALLOW_COMMITTED", 0))
        r = self.run_("proc", {"argv": ["/bin/true"]}, "p2"); self.assertEqual((r["status"], r["code"], r["effect"]), ("BLOCKED", "PROGRAM_NOT_ALLOWED", "DID_NOT_HAPPEN")); self.assertEqual(self.ledger.state("p2"), "BLOCKED")
        r = self.run_("proc", {"argv": [sys.executable, "-c", "print(1)"]}, "p3"); self.assertEqual(r["code"], "ARG_NOT_ALLOWED")

    def test_proc_timeout_is_unknown_not_blocked(self):
        r = self.run_("proc", {"argv": ["/bin/sleep", "5"]}, "p4"); self.assertEqual((r["status"], r["code"], r["effect"]), ("UNKNOWN", "TIMEOUT", "UNDETERMINED")); self.assertEqual(self.ledger.state("p4"), "UNKNOWN")

    def test_proc_target_is_part_of_the_permit(self):
        p = {"argv": [sys.executable, "-V"]}; ce = self.ce("proc", p); tok = self.iss.mint(ce)
        self.assertEqual(self.k.execute(tok, "proc", ce, {"argv": ["/bin/sleep", "5"]}, "p5")["code"], "DATA_NOT_BOUND_TO_PERMIT")

    # --- gate / faults / structure ----------------------------------------------------------------------------------------------------------------------
    def test_gate_denies_every_sink_before_anything_is_performed(self):
        self.gate_ok = False
        for kind, p in (("net", {"method": "GET", "url": self.url()}), ("proc", {"argv": [sys.executable, "-V"]}), ("file", {"path": os.path.join(self.root, "g.txt"), "data": b"x"})):
            r = self.run_(kind, p, "g-" + kind); self.assertEqual((r["status"], r["code"], r["effect"]), ("BLOCKED", "ASSURANCE_DENIED", "DID_NOT_HAPPEN"))
        self.assertEqual(H.hits, []); self.assertFalse(os.path.exists(os.path.join(self.root, "g.txt")))

    def test_gate_error_and_malformed_verdict_fail_closed(self):
        for g in (lambda: 1 / 0, lambda: ("yes", "x"), lambda: (1, "x"), lambda: None):
            self.k.gate = g; self.assertEqual(self.run_("net", {"method": "GET", "url": self.url()}, f"ge{id(g)}")["code"], "ASSURANCE_DENIED")
        self.assertEqual(H.hits, [])

    def test_fault_after_begin_is_unknown(self):
        def f(): raise OSError("boom")
        r = self.run_("net", {"method": "GET", "url": self.url()}, "f1", fault=f); self.assertEqual((r["status"], r["code"], r["effect"]), ("UNKNOWN", "UPSTREAM_FAILED", "UNDETERMINED")); self.assertEqual(H.hits, [])

    def test_forged_or_mismatched_permit_is_blocked(self):
        p = {"method": "GET", "url": self.url()}; other = self.ce("net", {"method": "GET", "url": self.url("/other")}); ce = self.ce("net", p)
        r = self.k.execute(self.iss.mint(other), "net", ce, p, "m1"); self.assertEqual((r["status"], r["effect"]), ("BLOCKED", "DID_NOT_HAPPEN")); self.assertEqual(H.hits, [])
        r = self.k.execute("not.a.token", "net", ce, p, "m2"); self.assertEqual(r["status"], "BLOCKED")

    def test_unknown_kind_and_effect_kind_mismatch(self):
        p = {"method": "GET", "url": self.url()}; ce = self.ce("net", p)
        self.assertEqual(self.k.execute(self.iss.mint(ce), "zzz", ce, p, "u1")["code"], "UNSUPPORTED_EFFECT")
        self.assertEqual(self.k.execute(self.iss.mint(ce), "proc", ce, {"argv": ["/x"]}, "u2")["code"], "UNSUPPORTED_EFFECT")

    def test_every_outcome_code_is_in_the_contract_table(self):
        from horizon.contracts.v1 import errors as ER
        for c in ("DATA_NOT_BOUND_TO_PERMIT", "UNSUPPORTED_EFFECT", "ASSURANCE_DENIED", "NONCE_REUSE", "UPSTREAM_FAILED", "LEDGER_MOVED_ON", "DUPLICATE", "OUTSIDE_ALLOWED_TARGETS", "REDIRECT_REFUSED", "TIMEOUT", "PROGRAM_NOT_ALLOWED", "ARG_NOT_ALLOWED"): self.assertNotEqual(ER.lookup(c).category, "UNKNOWN_ERROR_CODE", c)

    def test_concurrent_same_effect_id_performs_once(self):
        p = {"method": "GET", "url": self.url()}; res = []
        def go():
            ce = self.ce("net", p); res.append(self.k.execute(self.iss.mint(ce), "net", ce, p, "c1")["status"])
        ts = [threading.Thread(target=go) for _ in range(6)]; [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(res.count("ALLOW_COMMITTED"), 1); self.assertEqual(len(H.hits), 1)

    def test_outcome_make_table_wins_for_ambiguous_blocked_codes(self):
        self.assertEqual(Outcome.make("BLOCKED", "TIMEOUT")["effect"], "UNDETERMINED"); self.assertEqual(Outcome.make("BLOCKED", "POLICY_DENIED")["effect"], "DID_NOT_HAPPEN")
if __name__ == "__main__": unittest.main()
