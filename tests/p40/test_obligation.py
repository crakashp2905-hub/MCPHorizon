import copy, json, os, re, subprocess, sys, tempfile, unittest
from horizon.hpolicy import HorizonPolicy
from horizon.hpolicy.authority import EvidenceError
from horizon.authz.effect import args_digest
from horizon.obligation import terms as T, engine as E, infer as I, diff as D, scenarios as SC, ref as R, services as S
from horizon.obligation.catalog import catalog
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); RES = json.load(open(os.path.join(ROOT, "results/v2/p40-obligation/result.json")))
ART = "sha256:" + "ab" * 32; ARGS = {"env": "prod", "region": "r1"}


class Fx:
    def __init__(self):
        self.t = [1000]; self.a = HorizonPolicy("pol-1", clock=lambda: self.t[0]); self.ci = self.a.register_issuer("ci", {"TEST_STATUS", "SMOKE_TEST"}); self.ap = self.a.register_issuer("approver", {"APPROVAL"}, issuer_id="bob")
        self.sg = self.a.register_issuer("signer", {"SIGNATURE"}); self.eng = E.Engine(self.a, catalog("pol-1"), lambda: self.t[0]); self.task = self.eng.new_task("t", "alice", ART)
    def full(self, ttl=600, args=ARGS):
        self.eng.evidence(self.task, self.ci.issue("TEST_STATUS", principal="alice", artifact=ART, object_version=1, ttl=ttl, claim={"result": "pass"}))
        self.eng.evidence(self.task, self.sg.issue("SIGNATURE", principal="alice", artifact=ART, object_version=1, ttl=ttl))
        self.eng.evidence(self.task, self.ap.issue("APPROVAL", principal="alice", artifact=ART, args_digest=args_digest(args), object_version=1, ttl=ttl))


class Schema(unittest.TestCase):
    base = dict(id="x", kind="PRE", action="a", evidence_kind="APPROVAL", roles=["r"], bind_args=True, distinct_from_requester=False, consume=False, order_after=[], deadline_s=None, claim_equals=[], policy_version="pol-1", valid_from=0, valid_until=100, issuer="o")
    def p(self, **k): d = dict(self.base); d.update(k); return T.parse(d, policy_version="pol-1", now=10)
    def test_strict_fields_and_types(self):
        self.p()
        for bad in (dict(extra=1), dict(kind="MAYBE"), dict(roles=[]), dict(valid_until=0), dict(deadline_s=5), dict(bind_args="yes"), dict(id="")):
            with self.assertRaises(T.ObligationError, msg=str(bad)): self.p(**bad)
        d = dict(self.base); del d["issuer"]
        with self.assertRaises(T.ObligationError): T.parse(d, policy_version="pol-1", now=10)
    def test_post_needs_deadline(self):
        with self.assertRaises(T.ObligationError): self.p(kind="POST")
        self.assertEqual(self.p(kind="POST", deadline_s=60).deadline_s, 60)
    def test_policy_version_binding_and_expiry(self):
        with self.assertRaises(T.ObligationError) as c: self.p(policy_version="pol-0")
        self.assertEqual(c.exception.code, "POLICY_VERSION")
        with self.assertRaises(T.ObligationError) as c: T.parse(dict(self.base), policy_version="pol-1", now=100)
        self.assertEqual(c.exception.code, "EXPIRED")
    def test_operators_table_pinned(self):
        t = open(os.path.join(ROOT, "docs/evidence/p40/OPERATORS_AND_LIMITS.md")).read()
        for k in T.OPERATORS: self.assertIn("`%s`" % k, t)
        self.assertEqual(len(T.OPERATORS), 5)


class Structure(unittest.TestCase):
    def test_enforcement_modules_cannot_sign(self):
        for f in ("engine.py", "infer.py", "terms.py"):
            src = open(os.path.join(ROOT, "horizon/obligation", f)).read()
            self.assertNotRegex(src, r"\bSigner\b|\bIssuer\b|\.issue\(|register_issuer", f)
    def test_verifier_has_no_private_material(self):
        v = HorizonPolicy().verifier(); self.assertFalse(any(hasattr(v, a) for a in ("sign", "issue", "_s", "_env")))
    def test_issuer_role_enforced(self):
        a = HorizonPolicy(); ci = a.register_issuer("ci", {"TEST_STATUS"})
        with self.assertRaises(EvidenceError) as c: ci.issue("APPROVAL", principal="p", artifact="a")
        self.assertEqual(c.exception.code, "ROLE_NOT_ALLOWED")
    def test_token_checks(self):
        f = Fx(); tok = f.ci.issue("TEST_STATUS", principal="p", artifact=ART, claim={"result": "pass"}); v = f.a.verifier()
        v.verify(tok)
        h, p, s = tok.split("."); self.assertEqual(self._code(v, h + "." + p + "." + s[:-2] + "AA"), "BAD_SIGNATURE")
        f.t[0] += 601; self.assertEqual(self._code(v, tok), "EXPIRED")
        other = HorizonPolicy("pol-1", clock=lambda: 1000); other.register_issuer("ci", {"TEST_STATUS"}); o = other.register_issuer("ci", {"TEST_STATUS"})        # different kid from anything in f.a
        self.assertEqual(self._code(f.a.verifier(), o.issue("TEST_STATUS", principal="p", artifact=ART, now=1000)), "UNTRUSTED_ISSUER")
        same_kid = HorizonPolicy("pol-1", clock=lambda: 1000).register_issuer("ci", {"TEST_STATUS"}); self.assertEqual(self._code(f.a.verifier(), same_kid.issue("TEST_STATUS", principal="p", artifact=ART, now=1000)), "BAD_SIGNATURE")      # reuses a trusted kid: signature cannot verify
        fresh = f.ci.issue("TEST_STATUS", principal="p", artifact=ART, now=f.t[0]); f.a.version = "pol-2"; self.assertEqual(self._code(f.a.verifier(), fresh), "POLICY_VERSION")
    def _code(self, v, tok):
        try: v.verify(tok); return None
        except EvidenceError as e: return e.code


class Engine(unittest.TestCase):
    def deny(self, f, **k): d = f.eng.request(f.task, "deploy_prod", k.pop("args", ARGS), op_id=k.pop("op", "o"), **k); self.assertEqual(d.verdict, "DENY"); return d.reasons
    def test_allow_with_full_evidence_then_post_opened(self):
        f = Fx(); f.full(); d = f.eng.request(f.task, "deploy_prod", ARGS, op_id="o"); self.assertTrue(d); self.assertIn("prod.smoke", f.task.pending_post)
    def test_each_missing_prerequisite_denies(self):
        for drop in range(3):
            f = Fx(); toks = [f.ci.issue("TEST_STATUS", principal="alice", artifact=ART, object_version=1, claim={"result": "pass"}), f.sg.issue("SIGNATURE", principal="alice", artifact=ART, object_version=1)]
            ap = f.ap.issue("APPROVAL", principal="alice", artifact=ART, args_digest=args_digest(ARGS), object_version=1)
            for i, t in enumerate([toks[0], toks[1], ap]):
                if i != drop: f.eng.evidence(f.task, t)
            self.assertFalse(f.eng.request(f.task, "deploy_prod", ARGS, op_id="o"), drop)
    def test_args_binding_exact(self):
        f = Fx(); f.full(); r = self.deny(f, args={"env": "prod", "region": "r2"}); self.assertIn("ARGS_MISMATCH:prod.approval", r)
    def test_artifact_binding(self):
        f = Fx(); f.full(); f.task.artifact = "sha256:" + "ee" * 32; self.assertTrue(any(x.startswith("ARTIFACT_MISMATCH") for x in self.deny(f)))
    def test_expiry_checked_at_action_time(self):
        f = Fx(); f.full(ttl=100); f.t[0] += 101; self.assertTrue(any("EXPIRED" in x for x in self.deny(f)))
    def test_self_approval_rejected_even_with_valid_token(self):
        f = Fx(); f.task.requester = "bob"; f.full(); self.assertIn("REJECTED:SELF_APPROVAL:prod.approval", self.deny(f))
    def test_order_violation(self):
        f = Fx(); f.eng.evidence(f.task, f.ap.issue("APPROVAL", principal="alice", artifact=ART, args_digest=args_digest(ARGS), object_version=1))
        self.assertEqual(f.task.rejected[-1][0], "ORDER_VIOLATION")
    def test_failing_test_claim_not_accepted(self):
        f = Fx(); self.assertEqual(f.eng.evidence(f.task, f.ci.issue("TEST_STATUS", principal="alice", artifact=ART, object_version=1, claim={"result": "fail"})), []); self.assertEqual(f.task.rejected[-1][0], "CLAIM_MISMATCH")
    def test_stale_version(self):
        f = Fx(); f.full(); self.assertIn("STALE_VERSION", self.deny(f, object_version=2))
    def test_approval_single_use_across_branches(self):
        f = Fx(); f.full(); b = f.eng.fork(f.task, "b2"); self.assertTrue(f.eng.request(f.task, "deploy_prod", ARGS, op_id="o1")); d = f.eng.request(b, "deploy_prod", ARGS, op_id="o2"); self.assertIn("REPLAY", d.reasons)
    def test_idempotent_retry(self):
        f = Fx(); f.full(); a = f.eng.request(f.task, "deploy_prod", ARGS, op_id="o"); b = f.eng.request(f.task, "deploy_prod", ARGS, op_id="o"); self.assertTrue(a and b); self.assertIn("IDEMPOTENT_REPLAY", b.reasons)
    def test_cancellation_and_branch_isolation(self):
        f = Fx(); f.full(); b = f.eng.fork(f.task, "b2"); f.eng.cancel(f.task); self.assertIn("CANCELLED", self.deny(f)); self.assertTrue(f.eng.request(b, "deploy_prod", ARGS, op_id="ob"))
    def test_post_obligation_deadline_freezes(self):
        f = Fx(); f.full(ttl=3600); self.assertTrue(f.eng.request(f.task, "deploy_prod", ARGS, op_id="o1")); f.t[0] += 601; self.assertEqual(f.eng.tick(f.task), ["prod.smoke"])
        f.eng.evidence(f.task, f.ap.issue("APPROVAL", principal="alice", artifact=ART, args_digest=args_digest(ARGS), object_version=1, ttl=3600)); self.assertIn("FROZEN_POST_OBLIGATION", self.deny(f, op="o2"))
    def test_post_obligation_met_in_time(self):
        f = Fx(); f.full(ttl=3600); f.eng.request(f.task, "deploy_prod", ARGS, op_id="o1"); f.t[0] += 300
        self.assertEqual(f.eng.evidence(f.task, f.ci.issue("SMOKE_TEST", principal="alice", artifact=ART, object_version=1, claim={"result": "pass"})), ["prod.smoke"]); f.t[0] += 400; self.assertEqual(f.eng.tick(f.task), [])
    def test_unknown_action_denied_unguarded_allowed(self):
        f = Fx(); self.assertEqual(f.eng.request(f.task, "deploy_production", {}, op_id="u").reasons, ["UNKNOWN_ACTION"]); self.assertTrue(f.eng.request(f.task, "read_logs", {}, op_id="r"))
    def test_handoff_preserves_and_detects_tamper(self):
        f = Fx(); f.full(); sealed = f.eng.export(f.task)
        for carrier, back in ((E.to_mcp_meta, E.from_mcp_meta), (E.to_http_headers, E.from_http_headers)):
            t2 = f.eng.import_(back(carrier(sealed))); self.assertEqual(set(t2.satisfied), set(f.task.satisfied)); self.assertTrue(f.eng.request(t2, "deploy_prod", ARGS, op_id="h" + carrier.__name__))
            f.eng.ver.seen.clear()
        with self.assertRaises(EvidenceError): f.eng.import_(sealed[:-3] + "AAA")
        body, sig = sealed.split("."); import base64
        forged = base64.urlsafe_b64encode(json.dumps({"x": 1}).encode()).rstrip(b"=").decode() + "." + sig
        with self.assertRaises(EvidenceError): f.eng.import_(forged)
    def test_handoff_policy_version_and_catalog_mismatch(self):
        f = Fx(); f.full(); sealed = f.eng.export(f.task); eng2 = E.Engine(f.a, [o for o in catalog("pol-1") if o.id != "prod.sig"], lambda: f.t[0])
        with self.assertRaises(EvidenceError) as c: eng2.import_(sealed)
        self.assertEqual(c.exception.code, "OBLIGATION_SET_MISMATCH")


class Inference(unittest.TestCase):
    def test_templates_and_unknown(self):
        cat = catalog("pol-1"); self.assertEqual(I.infer("deploy_prod", cat)[0], "OK"); self.assertEqual(len(I.infer("deploy_prod", cat)[1]), 4)
        self.assertEqual(I.infer("read_logs", cat), ("OK", [])); self.assertEqual(I.infer("drop_database", cat), ("UNKNOWN", []))
    def mk(self):
        f = Fx(); po = f.a.register_issuer("policy_owner", {"APPROVAL"}); return f, po, I.Proposals(f.a, catalog("pol-1"), lambda: f.t[0])
    def tighter(self):
        d = [o for o in catalog("pol-1") if o.id == "prod.tests"][0].d(); d["claim_equals"] = [["result", "pass"], ["suite", "full"]]; return [d]
    def test_llm_proposal_inert_until_owner_approves(self):
        f, po, P = self.mk(); dig = P.propose("llm:x", self.tighter()); self.assertEqual(P.active["prod.tests"].claim_equals, (("result", "pass"),))
        with self.assertRaises(EvidenceError): P.decide(dig, f.ap.issue("APPROVAL", principal="p", artifact=dig))             # an ordinary approver is not the policy owner
        with self.assertRaises(EvidenceError): P.decide(dig, po.issue("APPROVAL", principal="p", artifact="sha256:other"))     # wrong binding
        P.decide(dig, po.issue("APPROVAL", principal="p", artifact=dig)); self.assertEqual(len(P.active["prod.tests"].claim_equals), 2)
    def test_relaxation_rejected_even_when_owner_approves(self):
        f, po, P = self.mk(); d = [o for o in catalog("pol-1") if o.id == "prod.approval"][0].d(); d["distinct_from_requester"] = False
        dig = P.propose("llm:x", [d])
        with self.assertRaises(EvidenceError) as c: P.decide(dig, po.issue("APPROVAL", principal="p", artifact=dig))
        self.assertEqual(c.exception.code, "RELAXATION_REJECTED"); self.assertTrue(P.active["prod.approval"].distinct_from_requester)
        d2 = [o for o in catalog("pol-1") if o.id == "prod.tests"][0].d(); d2["roles"] = ["ci", "ci2", "random"]; dg = P.propose("llm:x", [d2])
        with self.assertRaises(EvidenceError): P.decide(dg, po.issue("APPROVAL", principal="p", artifact=dg))
    def test_changelog_chain_detects_edit_delete_reorder(self):
        f, po, P = self.mk(); P.propose("llm:x", self.tighter()); P.propose("llm:y", self.tighter()); self.assertTrue(P.log.verify())
        L = copy.deepcopy(P.log.entries)
        for mut in (lambda e: e[0]["payload"].update(proposer="nobody"), lambda e: e.pop(0), lambda e: e.reverse()):
            c = I.ChangeLog(); c.entries = copy.deepcopy(L); mut(c.entries); self.assertFalse(c.verify())
    def test_malformed_proposal_logged_and_rejected(self):
        f, po, P = self.mk()
        with self.assertRaises(T.ObligationError): P.propose("llm:x", [{"id": "x"}])
        self.assertEqual(P.log.entries[-1]["event"], "REJECT_MALFORMED")
    def test_tightens_only_cases(self):
        b = [o for o in catalog("pol-1") if o.id == "prod.smoke"][0]; d = b.d(); d["deadline_s"] = 1200
        self.assertIn("deadline relaxed", I.tightens_only(b, T.parse(d, policy_version="pol-1", now=0)))
        d["deadline_s"] = 300; self.assertEqual(I.tightens_only(b, T.parse(d, policy_version="pol-1", now=0)), [])


class Services(unittest.TestCase):
    def test_signature_service_verifies_real_signature(self):
        a = HorizonPolicy(); sg = a.register_issuer("signer", {"SIGNATURE"}); from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; from cryptography.hazmat.primitives import serialization
        k = Ed25519PrivateKey.generate(); pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        with S.SigService(sg, {"dev": pub}) as s:
            self.assertEqual(S.call(s.url("/attest"), "POST", {"signer": "dev", "digest": ART, "sig": k.sign(ART.encode()).hex()})[0], 200)
            self.assertEqual(S.call(s.url("/attest"), "POST", {"signer": "dev", "digest": ART, "sig": k.sign(b"other").hex()})[0], 403)
            self.assertEqual(S.call(s.url("/attest"), "POST", {"signer": "nope", "digest": ART, "sig": "00"})[0], 403)
    def test_loopback_only(self):
        with self.assertRaises(AssertionError): S.call("http://example.invalid/x")


class Differential(unittest.TestCase):
    def test_engine_matches_exhaustive_reference_len5(self):
        r = D.differential(5); self.assertEqual(r["mismatches"], 0, r["examples"]); self.assertGreater(r["allow_decisions_in_reference"], 30)
    def test_reference_hand_cases(self):
        for s, want in (("TSAX", [True]), ("ATSX", [False]), ("TSAXX", [True, False]), ("TSAKX", [False]), ("TSACX", [False]), ("TSAXAX", [True, True]), ("TSAKTSX", [False]), ("KTSAX", [True])):
            self.assertEqual(R.ref_decisions(s), want, s); self.assertEqual(D.engine_decisions(s), want, s)


class Scenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.rows = SC.run_all(reps=1)
    def test_runtime_has_no_unsafe_or_missing_commits(self):
        for r in self.rows:
            if r["system"] == "runtime": self.assertEqual((r["excess"], r["missing"], r["error"]), (0, 0, None), r["scenario"])
    def test_nogate_commits_every_attack(self):
        for r in self.rows:
            if r["system"] == "nogate" and r["kind"] == "attack": self.assertGreater(r["excess"], 0, r["scenario"])
    def test_static_baseline_misses_runtime_only_attacks_and_blocks_alt_ci(self):
        by = {(r["scenario"], r["system"]): r for r in self.rows}
        for s in ("A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10", "A11", "A13", "A14"): self.assertGreater(by[(s, "static")]["excess"], 0, s)
        for s in ("A01", "A02", "A12"): self.assertEqual(by[(s, "static")]["excess"], 0, s)
        self.assertEqual(by[("B02", "static")]["missing"], 1)
    def test_denial_reasons_are_specific(self):
        by = {r["scenario"]: r["reasons"] for r in self.rows if r["system"] == "runtime"}
        want = {"A03": "EVIDENCE_EXPIRED:prod.approval", "A05": "ARGS_MISMATCH:prod.approval", "A06": "REJECTED:SELF_APPROVAL:prod.approval", "A07": "REJECTED:EVIDENCE_BAD_SIGNATURE", "A08": "REJECTED:CLAIM_MISMATCH:prod.tests", "A09": "STALE_EVIDENCE:prod.tests",
                "A10": "REPLAY", "A11": "CANCELLED", "A12": "REJECTED:ORDER_VIOLATION:prod.approval", "A13": "FROZEN_POST_OBLIGATION"}
        for s, w in want.items(): self.assertTrue(any(x.startswith(w) for x in by[s]), (s, by[s]))
    def test_oracle_is_the_journal(self):
        with tempfile.TemporaryDirectory() as d, S.DeployTarget(__import__("horizon.emergence.oracle", fromlist=["x"]).free_ports(1)[0], d) as dt:
            self.assertEqual(dt.commits(), []); dt.deploy(artifact="a", task="t", action="deploy_prod"); self.assertEqual(len(dt.commits()), 1)


class Results(unittest.TestCase):
    def test_recorded_summary(self):
        s = RES["summary"]; self.assertEqual(s["runtime"]["attacks_with_no_unsafe_commit"], 42); self.assertEqual(s["nogate"]["attacks_with_no_unsafe_commit"], 0); self.assertLess(s["static"]["attack_block_rate"], .3); self.assertEqual(s["runtime"]["benign_blocked"], 0)
        self.assertEqual(RES["differential"]["mismatches"], 0); self.assertEqual(RES["differential"]["sequences"], 55986)
        self.assertEqual(sum(1 for r in RES["rows"]), 25 * 3 * 3)
    def test_docs_and_definitions_current(self):
        for sc in ("p40_report.py", "p40_run.py"): self.assertEqual(subprocess.run([sys.executable, os.path.join(ROOT, "scripts", sc), "--check"], capture_output=True).returncode, 0, sc)


if __name__ == "__main__": unittest.main()
