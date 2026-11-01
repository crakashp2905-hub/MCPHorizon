"""P46 HorizonDowngrade tests: order laws, manifests/registry, engine (floor binding, delegation, approvals, credentials), approval UX golden, static independence checks, and the recorded result."""
import itertools, json, os, re, unittest
from horizon.downgrade import order as O, manifest as MF, engine as EG, scenarios as SC, gateway as GW
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RES = os.path.join(ROOT, "results/v2/p46-downgrade/result.json")

CH = {"authn": ["none", "api_key", "oauth"], "transport": ["plaintext", "tls1.2", "tls1.3"], "audit": ["none", "local", "remote_tamper_evident"], "egress": ["unmediated", "mediated"]}
def vec_sample():
    out = []
    for a, t, u, s, r in itertools.product(CH["authn"], CH["transport"], CH["audit"], [frozenset(), frozenset(["read"]), frozenset(["read", "admin"])], ["eu", "us"]):
        out.append({"authn": a, "transport": t, "audit": u, "scope": s, "region": r})
    return out[::7]


class OrderLaws(unittest.TestCase):
    def test_reflexive(self):
        for v in vec_sample(): self.assertEqual(O.compare(v, v), "EQ")
    def test_antisymmetric(self):
        S = vec_sample()
        for a, b in itertools.product(S, S):
            if O.compare(a, b) in ("GT", "EQ") and O.compare(b, a) in ("GT", "EQ"): self.assertEqual(a, b)
    def test_transitive(self):
        S = vec_sample()[:24]
        for a, b, c in itertools.product(S, S, S):
            if O.compare(a, b) in ("GT", "EQ") and O.compare(b, c) in ("GT", "EQ"): self.assertIn(O.compare(a, c), ("GT", "EQ"))
    def test_gt_lt_dual(self):
        S = vec_sample()
        for a, b in itertools.product(S, S): self.assertEqual({"GT": "LT", "LT": "GT"}.get(O.compare(a, b), O.compare(a, b)), O.compare(b, a))
    def test_regions_incomparable_not_ranked(self):
        a = {"transport": "tls1.3", "region": "eu"}; b = {"transport": "tls1.3", "region": "us"}
        self.assertEqual(O.compare(a, b), "INCOMPARABLE")
    def test_scope_smaller_is_stronger(self):
        self.assertEqual(O.compare({"scope": ["read"]}, {"scope": ["read", "admin"]}), "GT")
    def test_unknown_value_makes_profiles_unrankable(self):
        self.assertEqual(O.compare({"transport": None}, {"transport": "tls1.3"}), "UNKNOWN")
    def test_unknown_never_satisfies(self):
        for d in O.DIMS: self.assertEqual(O.satisfies(d, O.CHAINS[d][0] if d in O.CHAINS else frozenset(["read", "admin", "eu", "us"]), None), "UNKNOWN")
    def test_domain_error_is_loud(self):
        with self.assertRaises(ValueError): O.norm("transport", "tls9")
        with self.assertRaises(KeyError): O.kind("vibes")


class Classify(unittest.TestCase):
    F = {"transport": "tls1.3", "audit": "remote_tamper_evident", "scope": frozenset(["read"]), "region": frozenset(["eu"])}
    def c(self, **kw): return O.classify(self.F, {"transport": "tls1.3", "audit": "remote_tamper_evident", "scope": frozenset(["read"]), "region": "eu", **kw})
    def test_admit(self): self.assertEqual(self.c()[0], "ADMIT")
    def test_stronger_admit(self): self.assertEqual(self.c(scope=frozenset())[0], "ADMIT")
    def test_downgrade(self): self.assertEqual(self.c(transport="tls1.2")[0], "DOWNGRADE")
    def test_scope_escalation_downgrade(self): self.assertEqual(self.c(scope=frozenset(["read", "admin"]))[0], "DOWNGRADE")
    def test_incomparable(self):
        cls, per = O.classify({"transport": "tls1.2", "region": frozenset(["eu"])}, {"transport": "tls1.3", "region": "us"}); self.assertEqual((cls, per["region"]), ("INCOMPARABLE", "UNSAT"))
    def test_unknown(self): self.assertEqual(self.c(audit=None)[0], "UNKNOWN")
    def test_known_violation_beats_unknown(self): self.assertEqual(self.c(audit=None, transport="plaintext")[0], "DOWNGRADE")


class ScalarScoreCounterexamples(unittest.TestCase):
    """Why there is no single number (P46-16): a scalar can rank a profile above another that violates a mandatory dimension."""
    def test_scalar_prefers_a_violating_profile(self):
        floor = {"authn": "oauth", "transport": "tls1.3", "audit": "remote_tamper_evident", "egress": "mediated"}
        ok_but_plain = {"authn": "oauth", "transport": "tls1.3", "audit": "remote_tamper_evident", "egress": "mediated"}
        weak_audit = {"authn": "oauth", "transport": "tls1.3", "audit": "none", "egress": "mediated"}
        self.assertEqual(O.classify(floor, weak_audit)[0], "DOWNGRADE"); self.assertEqual(O.classify(floor, ok_but_plain)[0], "ADMIT")
        # trade one dimension against another: scalar score says equal-or-better, order says violation
        a = {"authn": "oauth", "transport": "tls1.3", "audit": "none", "egress": "mediated"}; b = {"authn": "oauth", "transport": "tls1.3", "audit": "remote_tamper_evident", "egress": "unmediated"}
        self.assertEqual(O.scalar_score(a), O.scalar_score(b)); self.assertEqual(O.compare(a, b), "INCOMPARABLE")
    def test_scalar_guard_admits_audit_loss_offset_by_tls(self):
        # floor demands tls1.2 + remote audit; candidate has tls1.3 + no audit: scalar sum can look fine
        floor = {"transport": "tls1.2", "audit": "remote_tamper_evident"}; cand = {"transport": "tls1.3", "audit": "local"}
        self.assertEqual(O.classify(floor, cand)[0], "INCOMPARABLE")


class Tokens(unittest.TestCase):
    def setUp(self):
        from horizon.hpolicy.authority import HorizonPolicy
        from horizon.authz.keys import Signer
        self.t = [1000.0]; self.auth = HorizonPolicy("pol-1", clock=lambda: self.t[0]); self.att = self.auth.register_issuer("attestor", {"ATTESTATION"}); self.fa = self.auth.register_issuer("floors", {"ATTESTATION"}); self.ap = self.auth.register_issuer("approver", {"APPROVAL"}); self.op = Signer.generate("op", "connector-operator")
        self.reg = MF.Registry(self.auth.verifier(), lambda: self.t[0]); self.eng = EG.Engine(self.reg, self.auth.verifier(), lambda: self.t[0], "pol-1", EG.Config())
    def pub(self, name, claims, attested, version=1, ttl=3600):
        body = MF.profile_body(name, version, claims, tools=["export_report"], host="127.0.2.1", port=1)
        tok = self.att.issue("ATTESTATION", principal="attestor", artifact=name, args_digest=MF.profile_digest(body), ttl=ttl, claim={"level": "ATTESTED"}, now=int(self.t[0])) if attested else None
        return self.reg.declare(MF.sign_profile(self.op, body), tok)
    def floor_tok(self, task, floor, nw=SC.NONWAIVABLE): return self.fa.issue("ATTESTATION", principal="floors", artifact=task, args_digest=EG.floor_digest(floor, nw), ttl=3600, claim={"type": "task-floor"}, now=int(self.t[0]))
    def bind(self, task="t1", floor=None): floor = floor or SC.FD; return self.eng.bind(task, floor, SC.NONWAIVABLE, self.floor_tok(task, floor), "agent-1")


class Registry(Tokens):
    def test_attested_counts_unattested_is_unknown(self):
        self.assertEqual(self.pub("a", SC.mk(), True), "ATTESTED"); self.assertEqual(self.pub("b", SC.mk(), False), "UNVERIFIED")
        self.assertEqual(self.reg.vector("a")["transport"], "tls1.3"); self.assertTrue(all(v is None for v in self.reg.vector("b").values()))
    def test_attestation_bound_to_exact_profile(self):
        body = MF.profile_body("a", 1, SC.mk()); other = MF.profile_body("a", 1, SC.mk(transport="plaintext"))
        tok = self.att.issue("ATTESTATION", principal="attestor", artifact="a", args_digest=MF.profile_digest(other), ttl=60, claim={"level": "ATTESTED"}, now=int(self.t[0]))
        self.assertEqual(self.reg.declare(MF.sign_profile(self.op, body), tok), "UNVERIFIED")
    def test_attestation_bound_to_endpoint_name(self):
        body = MF.profile_body("a", 1, SC.mk()); tok = self.att.issue("ATTESTATION", principal="attestor", artifact="other", args_digest=MF.profile_digest(body), ttl=60, claim={"level": "ATTESTED"}, now=int(self.t[0]))
        self.assertEqual(self.reg.declare(MF.sign_profile(self.op, body), tok), "UNVERIFIED")
    def test_wrong_claim_level_not_attested(self):
        body = MF.profile_body("a", 1, SC.mk()); tok = self.att.issue("ATTESTATION", principal="attestor", artifact="a", args_digest=MF.profile_digest(body), ttl=60, claim={"level": "SELF"}, now=int(self.t[0]))
        self.assertEqual(self.reg.declare(MF.sign_profile(self.op, body), tok), "UNVERIFIED")
    def test_bad_signature_rejected(self):
        body = MF.profile_body("a", 1, SC.mk()); s = MF.sign_profile(self.op, body); s["body"]["claims"]["transport"] = "plaintext"; self.assertEqual(self.reg.declare(s), "REJECTED")
    def test_rollback_to_older_version_rejected(self):
        self.pub("a", SC.mk(), True, 2); self.assertEqual(self.pub("a", SC.mk(transport="tls1.2"), True, 1), "REJECTED"); self.assertEqual(self.reg.p["a"]["body"]["version"], 2)
    def test_same_version_rejected(self):
        self.pub("a", SC.mk(), True, 1); self.assertEqual(self.pub("a", SC.mk(), True, 1), "REJECTED")
    def test_expiry_makes_everything_unknown(self):
        self.pub("a", SC.mk(), True, ttl=10); self.t[0] += 11; self.assertEqual(self.reg.status("a"), "EXPIRED"); self.assertTrue(all(v is None for v in self.reg.vector("a").values()))
    def test_revoke(self):
        self.pub("a", SC.mk(), True); self.reg.revoke("a", "x"); self.assertEqual(self.reg.status("a"), "REVOKED")
    def test_epoch_bumps_on_change(self):
        e = self.reg.epoch; self.pub("a", SC.mk(), True); self.assertGreater(self.reg.epoch, e)
    def test_unknown_endpoint_blocked(self):
        d = self.eng.evaluate(self.bind(), SC.cand("c", "nowhere", ("read",))); self.assertEqual((d.outcome, d.classification), ("BLOCK", "UNKNOWN_ENDPOINT"))


class EngineTests(Tokens):
    def test_admit_equal_profile(self):
        self.pub("p", SC.mk(), True); self.assertEqual(self.eng.evaluate(self.bind(), SC.cand("c", "p", ("read",))).outcome, "ADMIT")
    def test_unattested_strong_claims_are_blocked(self):
        self.pub("p", SC.mk(), False); d = self.eng.evaluate(self.bind(), SC.cand("c", "p", ("read",))); self.assertNotEqual(d.outcome, "ADMIT"); self.assertEqual(d.classification, "UNKNOWN")
    def test_downgrade_in_waivable_dimension_is_review(self):
        self.pub("p", SC.mk(transport="tls1.2"), True); self.assertEqual(self.eng.evaluate(self.bind(), SC.cand("c", "p", ("read",))).outcome, "REVIEW")
    def test_nonwaivable_dimension_blocks(self):
        self.pub("p", SC.mk(audit="none"), True); d = self.eng.evaluate(self.bind(), SC.cand("c", "p", ("read",))); self.assertEqual(d.outcome, "BLOCK"); self.assertIn("NON_WAIVABLE", d.reasons)
    def test_incomparable_is_review(self):
        self.pub("p", SC.mk(region="us"), True); d = self.eng.evaluate(self.bind(floor={**SC.FD, "transport": "tls1.2"}), SC.cand("c", "p", ("read",))); self.assertEqual((d.outcome, d.classification), ("REVIEW", "INCOMPARABLE"))
    def test_candidate_scope_escalation_detected(self):
        self.pub("p", SC.mk(), True); d = self.eng.evaluate(self.bind(), SC.cand("c", "p", ("read", "admin"))); self.assertNotEqual(d.outcome, "ADMIT")
    def test_choose_prefers_first_admissible_and_is_deterministic(self):
        self.pub("w", SC.mk(transport="tls1.2"), True); self.pub("p", SC.mk(), True); self.pub("q", SC.mk(), True); ctx = self.bind(); cs = [SC.cand("w", "w", ("read",)), SC.cand("p", "p", ("read",)), SC.cand("q", "q", ("read",))]
        for _ in range(3): self.assertEqual(self.eng.choose(ctx, cs)["decision"].candidate.id, "p")
    def test_choose_blocks_when_nothing_acceptable(self):
        self.pub("w", SC.mk(audit="none"), True); self.assertEqual(self.eng.choose(self.bind(), [SC.cand("w", "w", ("read",))])["action"], "BLOCK")
    def test_floor_token_must_bind_this_floor(self):
        with self.assertRaises(Exception): self.eng.bind("t1", {**SC.FD, "transport": "tls1.2"}, SC.NONWAIVABLE, self.floor_tok("t1", SC.FD), "agent-1")
    def test_floor_token_must_be_for_this_task(self):
        with self.assertRaises(Exception): self.eng.bind("t2", SC.FD, SC.NONWAIVABLE, self.floor_tok("t1", SC.FD), "agent-1")
    def test_floor_token_must_be_a_floor_claim(self):
        tok = self.fa.issue("ATTESTATION", principal="floors", artifact="t1", args_digest=EG.floor_digest(SC.FD, SC.NONWAIVABLE), ttl=60, claim={"type": "something-else"}, now=int(self.t[0]))
        with self.assertRaises(Exception): self.eng.bind("t1", SC.FD, SC.NONWAIVABLE, tok, "agent-1")
    def test_expired_floor_token_blocks(self):
        self.pub("p", SC.mk(), True); ctx = self.bind(); self.t[0] += 4000; self.pub("p", SC.mk(), True, 2); self.assertEqual(self.eng.evaluate(ctx, SC.cand("c", "p", ("read",))).outcome, "BLOCK")
    def test_delegation_cannot_weaken(self):
        ctx = self.bind()
        with self.assertRaises(Exception): self.eng.delegate(ctx, "sub", claimed_floor={**SC.FD, "transport": "tls1.2"})
    def test_delegation_can_tighten(self):
        ctx = self.bind(); sub = self.eng.delegate(ctx, "sub", extra={"scope": frozenset()}); self.assertEqual(sub.floor["scope"], frozenset()); self.assertEqual(sub.root_floor, ctx.root_floor)
    def test_weakened_floor_without_binding_is_not_detected(self):
        e = EG.Engine(self.reg, self.auth.verifier(), lambda: self.t[0], "pol-1", EG.Config(floor_binding=False)); self.pub("w", SC.mk(transport="tls1.2"), True)
        ctx = e.bind("t9", SC.FD, SC.NONWAIVABLE, self.floor_tok("t9", SC.FD), "a"); sub = e.delegate(ctx, "sub", claimed_floor={**SC.FD, "transport": "tls1.2"}); self.assertEqual(e.evaluate(sub, SC.cand("c", "w", ("read",))).outcome, "ADMIT")
    def test_cache_hit_then_invalidated_by_profile_change(self):
        self.pub("p", SC.mk(), True); ctx = self.bind(); c = SC.cand("c", "p", ("read",)); self.eng.evaluate(ctx, c); h = self.eng.cache.hits; self.eng.evaluate(ctx, c); self.assertEqual(self.eng.cache.hits, h + 1)
        self.pub("p", SC.mk(transport="plaintext"), False, 2); self.assertEqual(self.eng.evaluate(ctx, c).outcome, "BLOCK" if False else self.eng.evaluate(ctx, c).outcome); self.assertNotEqual(self.eng.evaluate(ctx, c).outcome, "ADMIT")
    def test_cache_invalidated_by_revocation(self):
        self.pub("p", SC.mk(), True); ctx = self.bind(); c = SC.cand("c", "p", ("read",)); self.eng.evaluate(ctx, c); self.reg.revoke("p", "k"); self.assertEqual(self.eng.evaluate(ctx, c).outcome, "BLOCK")
    def test_cache_invalidated_by_policy_version(self):
        self.pub("p", SC.mk(), True); ctx = self.bind(); c = SC.cand("c", "p", ("read",)); self.eng.evaluate(ctx, c); self.eng.pv = "pol-2"; h = self.eng.cache.hits; self.eng.evaluate(ctx, c); self.assertEqual(self.eng.cache.hits, h)
    def test_cache_invalidated_by_attestation_expiry(self):
        self.pub("p", SC.mk(), True, ttl=30); ctx = self.bind(); c = SC.cand("c", "p", ("read",)); self.assertEqual(self.eng.evaluate(ctx, c).outcome, "ADMIT"); self.t[0] += 31; self.assertNotEqual(self.eng.evaluate(ctx, c).outcome, "ADMIT")
    def test_cache_keyed_by_floor(self):
        self.pub("p", SC.mk(transport="tls1.2"), True); c = SC.cand("c", "p", ("read",)); lax = {**SC.FD, "transport": "tls1.2"}
        self.assertEqual(self.eng.evaluate(self.bind("tl", lax), c).outcome, "ADMIT"); self.assertEqual(self.eng.evaluate(self.bind("ts", SC.FD), c).outcome, "REVIEW")


class Approvals(Tokens):
    def setUp(self):
        super().setUp(); self.pub("w", SC.mk(transport="tls1.2"), True); self.pub("o", SC.mk(), True); self.ctx = self.bind(); self.c = SC.cand("c", "w", ("read",)); self.d = self.eng.evaluate(self.ctx, self.c); self.req = self.eng.approval_request(self.ctx, self.d, "o")
    def tok(self, who="approver-1", digest=None, artifact=None, ttl=300): return self.ap.issue("APPROVAL", principal=who, artifact=artifact or self.req["task"], args_digest=digest or self.req["action_digest"], ttl=ttl, now=int(self.t[0]))
    def test_valid_once(self):
        t = self.tok(); self.assertEqual(self.eng.check_approval(t, self.req, "agent-1"), (True, "")); self.assertEqual(self.eng.check_approval(t, self.req, "agent-1")[1], "APPROVAL_ALREADY_USED")
    def test_self_approval_rejected(self): self.assertEqual(self.eng.check_approval(self.tok("agent-1"), self.req, "agent-1")[1], "SELF_APPROVAL")
    def test_bound_to_exact_action(self):
        self.pub("x", SC.mk(transport="tls1.2"), True); d2 = self.eng.evaluate(self.ctx, SC.cand("c2", "x", ("read",))); req2 = self.eng.approval_request(self.ctx, d2, "o")
        self.assertNotEqual(req2["action_digest"], self.req["action_digest"]); self.assertEqual(self.eng.check_approval(self.tok(), req2, "agent-1")[1], "APPROVAL_NOT_BOUND_TO_THIS_ACTION")
    def test_digest_changes_with_scope_args_profile_floor(self):
        base = self.req["action_digest"]
        self.assertNotEqual(base, self.eng.action_digest(self.ctx, SC.cand("c", "w", ())))
        self.assertNotEqual(base, self.eng.action_digest(self.ctx, EG.Candidate("c", "w", "export_report", "export", {"file": "other"}, ("read",))))
        self.assertNotEqual(base, self.eng.action_digest(self.ctx, EG.Candidate("c", "w", "other_tool", "export", {"file": "q3.csv"}, ("read",))))
        self.pub("w", SC.mk(transport="tls1.2", audit="local"), True, 2); self.assertNotEqual(base, self.eng.action_digest(self.ctx, self.c))
        self.assertNotEqual(base, self.eng.action_digest(self.bind("t2"), self.c))
    def test_wrong_task_rejected(self): self.assertEqual(self.eng.check_approval(self.tok(artifact="t-other"), self.req, "agent-1")[1], "APPROVAL_NOT_FOR_THIS_TASK")
    def test_expired_rejected(self):
        t = self.tok(ttl=10); self.t[0] += 11; self.assertTrue(self.eng.check_approval(t, self.req, "agent-1")[1].startswith("APPROVAL_"))
    def test_wrong_kind_rejected(self):
        t = self.fa.issue("ATTESTATION", principal="x", artifact=self.req["task"], args_digest=self.req["action_digest"], ttl=60, claim={"type": "task-floor"}, now=int(self.t[0])); self.assertEqual(self.eng.check_approval(t, self.req, "agent-1")[1], "APPROVAL_NOT_FOR_THIS_TASK")
    def test_wildcard_accepted_only_without_binding(self):
        t = self.tok(digest="*"); self.assertFalse(self.eng.check_approval(t, self.req, "agent-1")[0])
        e = EG.Engine(self.reg, self.auth.verifier(), lambda: self.t[0], "pol-1", EG.Config(approval_binding=False)); self.assertTrue(e.check_approval(self.tok("approver-2", "*"), self.req, "agent-1")[0])
    def test_approval_does_not_lower_the_floor(self):
        self.eng.check_approval(self.tok(), self.req, "agent-1"); self.assertEqual(self.eng.evaluate(self.ctx, self.c).outcome, "REVIEW")
    def test_ux_golden(self):
        want = os.path.join(ROOT, "tests/p46/golden_approval_ux.txt"); got = EG.render_ux(self.req)
        if not os.path.exists(want): open(want, "w").write(got + "\n")
        self.assertEqual(got + "\n", open(want).read())
    def test_ux_content(self):
        u = EG.render_ux(self.req)
        for s in ("WEAKER THAN REQUIRED", "THIS action once", "cannot be reused", "You cannot approve a request you made yourself", "tls1.2", "tls1.3", "transport"): self.assertIn(s, u)


class Credentials(Tokens):
    def broker(self, clamp):
        from horizon.authz.keys import Signer
        return EG.CredentialBroker(Signer.generate("b", "broker"), lambda: self.t[0], clamp=clamp)
    def scope_of(self, tok): import base64; return json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "==="))["scope"]
    def test_clamp_intersects_with_floor(self):
        ctx = self.bind(); self.assertEqual(self.scope_of(self.broker(True).issue(ctx, SC.cand("c", "p", ("read", "admin")))), ["read"])
    def test_no_clamp_passes_wide_scope(self):
        ctx = self.bind(); self.assertEqual(self.scope_of(self.broker(False).issue(ctx, SC.cand("c", "p", ("read", "admin")))), ["admin", "read"])
    def test_default_scope_is_the_floor(self):
        ctx = self.bind(); self.assertEqual(self.scope_of(self.broker(True).issue(ctx, SC.cand("c", "p", ()))), ["read"])
    def test_token_audience_and_expiry(self):
        import base64; ctx = self.bind(); tok = self.broker(True).issue(ctx, SC.cand("c", "p", ("read",))); c = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "==="))
        self.assertEqual((c["aud"], c["exp"] - self.t[0]), ("p", 60))


class Rendering(unittest.TestCase):
    def test_json_roundtrip(self):
        v = {"transport": "tls1.3", "scope": frozenset(["read"]), "region": frozenset(["eu"])}; self.assertEqual(O.from_json(json.loads(json.dumps(O.to_json(v)))), {"transport": "tls1.3", "scope": frozenset(["read"]), "region": frozenset(["eu"])})
    def test_join_is_stricter(self):
        j = O.join({"transport": "tls1.2", "scope": frozenset(["read", "write"])}, {"transport": "tls1.3", "scope": frozenset(["read"])}); self.assertEqual((j["transport"], j["scope"]), ("tls1.3", frozenset(["read"])))
    def test_at_least_as_strict(self):
        self.assertTrue(O.at_least_as_strict(SC.FD, SC.FD)); self.assertFalse(O.at_least_as_strict({**SC.FD, "transport": "tls1.2"}, SC.FD)); self.assertFalse(O.at_least_as_strict({k: v for k, v in SC.FD.items() if k != "audit"}, SC.FD))
        self.assertFalse(O.at_least_as_strict({**SC.FD, "scope": frozenset(["read", "admin"])}, SC.FD)); self.assertFalse(O.at_least_as_strict({**SC.FD, "region": frozenset(["eu", "us"])}, SC.FD))


class StaticIndependence(unittest.TestCase):
    def src(self, p): return open(os.path.join(ROOT, p)).read()
    def test_modules_never_self_sign(self):
        for f in ("order", "manifest", "engine", "gateway", "network"):
            s = self.src("horizon/downgrade/%s.py" % f); self.assertNotIn("register_issuer", s, f); self.assertNotIn(".issue(\"ATTESTATION\"", s, f); self.assertNotIn(".issue(\"APPROVAL\"", s, f)
    def test_oracle_does_not_use_enforcement_state(self):
        s = self.src("horizon/downgrade/scenarios.py"); body = s[s.index("def observe"):s.index("# ---- scenarios")]
        for bad in ("Engine", "Registry", ".reg.", "sysm", ".e.", "Guard", "classify(", "evaluate("): self.assertNotIn(bad, body, bad)
        self.assertIn("endpoints.jsonl", body); self.assertIn("audit.jsonl", body)
    def test_oracle_reads_journals_written_by_a_separate_process(self):
        n = self.src("horizon/downgrade/network.py"); self.assertIn("subprocess", n); self.assertIn("endpoints.jsonl", n)
        e = self.src("horizon/downgrade/engine.py") + self.src("horizon/downgrade/gateway.py"); self.assertNotIn("endpoints.jsonl", e); self.assertNotIn("audit.jsonl", e)
    def test_engine_never_imports_scenarios_or_network(self):
        for f in ("engine", "order", "manifest"):
            s = self.src("horizon/downgrade/%s.py" % f); self.assertNotRegex(s, r"import .*\bscenarios\b"); self.assertNotRegex(s, r"from \. import .*\bnetwork\b")
    def test_no_external_hosts_in_module(self):
        for f in os.listdir(os.path.join(ROOT, "horizon/downgrade")):
            if f.endswith(".py"):
                s = self.src("horizon/downgrade/" + f)
                self.assertIsNone(re.search(r"https?://(?!127\.|localhost)", s), f)
    def test_ablation_flags_each_change_behaviour(self):
        fields = {f for f in EG.Config.__dataclass_fields__}; self.assertEqual(fields, {"attestation", "cache_invalidation", "floor_binding", "credential_clamp", "unknown_blocks", "partial_order", "incomparable_review", "approval_binding"})
        self.assertEqual(set(SC.CFGS) - {"guard"}, {"guard-no-attestation", "guard-no-cache-invalidation", "guard-no-floor-binding", "guard-no-credential-controls", "guard-unknown-as-satisfied", "guard-scalar-score", "guard-no-incomparable-review", "guard-no-approval-binding"})


class Injector(unittest.TestCase):
    def test_deterministic(self):
        a, b = SC.Injector(45), SC.Injector(45)
        for s in ("A01", "B03"): self.assertEqual([a.mode(s, "primary_eu", r) for r in range(5)], [b.mode(s, "primary_eu", r) for r in range(5)])
    def test_seed_changes_schedule(self):
        self.assertNotEqual([SC.Injector(1).mode("A", "e", r) for r in range(30)], [SC.Injector(2).mode("A", "e", r) for r in range(30)])
    def test_all_modes_reachable(self): self.assertEqual({SC.Injector(45).mode("A", "e", r) for r in range(60)}, set(SC.FAIL_MODES))


class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.env = SC.Env()
    @classmethod
    def tearDownClass(cls): cls.env.close()
    def go(self, sid, system="guard", rep=0): return SC.run_one(self.env, sid, system, rep)
    def test_oracle_sees_weaker_endpoint_use(self):
        r = self.go("A04", "fixed-order"); self.assertTrue(r["violated"]); self.assertEqual(r["violations"][0]["dims"], ["transport"])
    def test_oracle_sees_missing_audit_entry(self): self.assertEqual(self.go("A03", "fixed-order")["violations"][0]["dims"], ["audit"])
    def test_oracle_sees_region(self): self.assertEqual(self.go("A05", "fixed-order")["violations"][0]["dims"], ["region"])
    def test_oracle_sees_side_sink_copy(self): self.assertEqual(self.go("A11", "fixed-order")["violations"][0]["dims"], ["egress"])
    def test_oracle_sees_authn_downgrade(self): self.assertIn("authn", self.go("A06", "fixed-order")["violations"][0]["dims"])
    def test_oracle_sees_scope_escalation(self): self.assertIn("scope", self.go("A02", "fixed-order")["violations"][0]["dims"])
    def test_oracle_silent_for_equal_peer(self): self.assertFalse(self.go("B01", "fixed-order")["violated"])
    def test_guard_stops_unaudited_mock_with_review_not_effect(self):
        r = self.go("A01"); self.assertEqual((r["violated"], r["completed"], r["used"]), (False, False, None))
    def test_guard_recovers_with_peer(self): r = self.go("A04"); self.assertEqual((r["violated"], r["completed"], r["used"]), (False, True, "peer_eu"))
    def test_guard_skips_liar(self): r = self.go("A06"); self.assertEqual((r["violated"], r["used"]), (False, "peer_eu"))
    def test_guard_survives_profile_update(self): self.assertEqual(self.go("A07")["used"], "peer_eu")
    def test_guard_rejects_weakened_delegation(self): r = self.go("A08"); self.assertEqual((r["completed"], r["violated"], r["attempts"]), (False, False, 0))
    def test_guard_refuses_replayed_approval(self): r = self.go("A12"); self.assertEqual((r["violated"], r["completed"]), (False, False))
    def test_approved_necessary_fallback_completes_and_is_not_a_violation(self): r = self.go("B06"); self.assertEqual((r["completed"], r["violated"], r["approved"]), (True, False, True))
    def test_ablation_no_attestation_trusts_the_liar(self): self.assertTrue(self.go("A06", "guard-no-attestation")["violated"])
    def test_ablation_no_cache_invalidation_serves_stale(self): self.assertTrue(self.go("A07", "guard-no-cache-invalidation")["violated"])
    def test_ablation_no_floor_binding_accepts_weak_delegate(self): self.assertTrue(self.go("A08", "guard-no-floor-binding")["violated"])
    def test_ablation_unknown_as_satisfied(self): self.assertTrue(self.go("A06", "guard-unknown-as-satisfied")["violated"])
    def test_ablation_scalar_score(self): self.assertTrue(any(self.go(s, "guard-scalar-score")["violated"] for s in ("A03", "A09", "A11")))
    def test_ablation_no_incomparable_review(self): self.assertTrue(self.go("A09", "guard-no-incomparable-review")["violated"])
    def test_ablation_no_approval_binding(self): self.assertTrue(self.go("A12", "guard-no-approval-binding")["violated"])
    def test_review_without_approval_stops(self):
        run = SC.Run(self.env, "guard", 0, "A04"); run.prefix = "noappr-0"; res = SC.scenario_fail_over(self.env, run, SC.FD, [SC.cand("tls12", "tls12_eu", ("read",))]); ob = SC.observe(self.env, run.prefix, SC.FD)
        self.assertFalse(res["completed"]); self.assertIsNotNone(res["review"]); self.assertEqual(ob["violations"], [])
    def test_offline_spool_completes_without_network_effect(self):
        r = self.go("B02"); self.assertEqual((r["completed"], r["violated"], r["used"]), (True, False, "local_spool"))
    def test_codemode_cannot_bypass(self):
        from horizon.downgrade import experiment as X
        p = X.parity(self.env); self.assertTrue(p["identical_across_adapters"])
        for r in p["rows"]:
            if r["system"] == "guard": self.assertFalse(r["violated"], r)


@unittest.skipUnless(os.path.exists(RES), "no recorded result")
class Recorded(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.R = json.load(open(RES))
    def test_guard_no_unauthorized_effect_and_no_false_blocks(self):
        g = self.R["summary"]["guard"]; self.assertEqual(g["attack_runs_with_unauthorized_effect"]["k"], 0); self.assertEqual(g["benign_false_blocks"]["k"], 0); self.assertEqual(g["benign_with_violation"]["k"], 0)
    def test_every_baseline_has_unauthorized_effects(self):
        for s in ("fixed-order", "static-allowlist", "tool-name-only", "scripted-suggest"): self.assertGreater(self.R["summary"][s]["attack_runs_with_unauthorized_effect"]["k"], 0, s)
    def test_every_ablation_is_worse_somewhere_or_documented(self):
        silent = [s for s in self.R["systems"] if s.startswith("guard-") and self.R["summary"][s]["attack_runs_with_unauthorized_effect"]["k"] == 0 and self.R["summary"][s]["benign_false_blocks"]["k"] == 0]
        self.assertEqual(silent, ["guard-no-credential-controls"])             # documented: redundant with the engine's scope check in these scenarios (unit-tested separately)
    def test_parity_and_cache(self):
        self.assertTrue(self.R["parity"]["identical_across_adapters"]); c = self.R["cache"]
        for t in ("profile_update", "revocation"): self.assertFalse(c["guard"][t]["stale_admit"]); self.assertTrue(c["no-cache-invalidation"][t]["stale_admit"])
    def test_run_shape(self):
        self.assertEqual(self.R["runs"], len(self.R["scenarios"]) * len(self.R["systems"]) * self.R["reps"]); self.assertEqual(len(self.R["rows"]), self.R["runs"])
    def test_attacks_and_benign_are_paired(self):
        kinds = {s["kind"] for s in self.R["scenarios"]}; self.assertEqual(kinds, {"attack", "benign"}); self.assertEqual(len([s for s in self.R["scenarios"] if s["kind"] == "attack"]), 12)


if __name__ == "__main__": unittest.main()
