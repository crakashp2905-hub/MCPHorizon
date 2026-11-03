import dataclasses, os, random, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from horizon import normalize as N
from horizon.authz import effect as E
from horizon.authz.keys import Signer, TrustStore
from horizon.authz.gateway import Verifier, NonceStore, ProofError
from horizon.effects.canonical import CanonicalEffect, commit_verify
from horizon.assurance.registry import AssuranceClaim, Registry
from research.novel import coverage, permitfuzz, diffkernel, sinkdiff, witnesses, racebench, negreg
NOW = 1000
class Cov(unittest.TestCase):
    def test_wilson(self):
        self.assertEqual(coverage.wilson(0, 0), (0.0, 1.0)); lo, hi = coverage.wilson(10, 10); self.assertGreater(lo, 0.69); self.assertEqual(hi, 1.0); self.assertLess(coverage.wilson(5, 10)[0], coverage.wilson(50, 100)[0])
    def test_zero_probe_declared_covered_is_unknown(self):
        r = coverage.report({"fs": "COVERED", "net": "COVERED"}, [("fs", True)] * 5); self.assertEqual(r["states"], {"fs": "COVERED", "net": "UNKNOWN"}); self.assertEqual(r["covered_fraction"], 0.5); self.assertEqual(r["unknown_fraction"], 0.5)
    def test_failed_probe_fails_item(self): self.assertEqual(coverage.report({"fs": "COVERED"}, [("fs", True), ("fs", False)])["states"]["fs"], "FAILED")
    def test_unsupported_excluded_from_denominator(self):
        r = coverage.report({"fs": "COVERED", "ws": "UNSUPPORTED"}, [("fs", True)] * 3); self.assertEqual(r["covered_fraction"], 1.0); self.assertEqual(r["counts"]["UNSUPPORTED"], 1)
    def test_lower_bound_below_point_and_grows_with_probes(self):
        a = coverage.report({"x": "COVERED"}, [("x", True)] * 3)["covered_fraction_lower"]; b = coverage.report({"x": "COVERED"}, [("x", True)] * 300)["covered_fraction_lower"]; self.assertLess(a, b); self.assertLess(b, 1.0)
    def test_undeclared_probe_rejected(self):
        with self.assertRaises(ValueError): coverage.report({"a": "COVERED"}, [("b", True)])
    def test_empty(self): r = coverage.report({}, []); self.assertEqual((r["covered_fraction"], r["unknown_fraction"]), (0.0, 1.0))
    def test_declared_unknown_stays_unknown_even_with_passing_probes(self): self.assertEqual(coverage.report({"a": "UNKNOWN"}, [("a", True)] * 9)["states"]["a"], "UNKNOWN")
class Fuzz(unittest.TestCase):
    def setUp(self):
        self.s = Signer.generate("k1", "iss"); self.ts = TrustStore(clock=lambda: NOW); self.ts.add("k1", "iss", self.s.public_raw(), not_before=0, not_after=10**6)
        self.ce = CanonicalEffect("t1", "srv1", "sess1", "agent-a", "write", "file", "/data/a.txt", {"a": 1})
    def mv(self): return Verifier(self.ts, NonceStore(clock=lambda: NOW), issuer="iss", audience="gw", contract_version="c1", policy_version=lambda: "p1", clock=lambda: NOW)
    def mint(self, o=None):
        ce = self.ce; e = dict(v=1, iss="iss", sub=ce.principal, tenant=ce.tenant, effect=ce.effect, target=N.canonical_target(ce.target_kind, ce.target_raw), args_digest=ce.bound_args_digest(), contract_version="c1", policy_version="p1", aud="gw", iat=NOW - 1, exp=NOW + 30, nonce=os.urandom(8).hex(), decision_id="d")
        e.update(o or {}); return E.sign(self.s._p, "k1", e)
    def test_no_bound_field_is_unbound(self):
        r = permitfuzz.run(self.mv, self.s, self.ce, NOW, self.mint); self.assertTrue(r["baseline_ok"]); self.assertEqual(r["accepted"], []); self.assertGreaterEqual(r["tested"], 25)
    def test_decision_id_is_reported_as_expected_unbound(self):
        r = permitfuzz.run(self.mv, self.s, self.ce, NOW, self.mint); self.assertEqual(r["accepted_expected_unbound"], ["claim.decision_id"])
    def test_fuzzer_detects_a_weak_verifier(self):   # the fuzzer itself must be able to fail: a verifier that ignores the principal (principal is NOT folded into the args digest, so only the principal check binds it)
        class Weak(Verifier):
            def _verify(self, token, principal, *a, **k): return super()._verify(token, "agent-a", *a, **k)
        def mk(): return Weak(self.ts, NonceStore(clock=lambda: NOW), issuer="iss", audience="gw", contract_version="c1", policy_version=lambda: "p1", clock=lambda: NOW)
        r = permitfuzz.run(mk, self.s, self.ce, NOW, self.mint); self.assertIn("ce.principal", r["accepted"])
    def test_only_decision_id_is_allowed_to_be_unbound(self): self.assertEqual(permitfuzz.EXPECT_UNBOUND, {"decision_id"})
    def test_tenant_is_double_bound(self):
        self.assertIn("tenant", self.ce.bound_args_digest.__doc__ or "tenant")   # documented: tenant is in both the claim and the args digest
        self.assertNotEqual(self.ce.bound_args_digest(), dataclasses.replace(self.ce, tenant="t2").bound_args_digest())
class Diff(unittest.TestCase):
    def test_ref_ok_and_each_code(self):
        c, rq, env, seen = diffkernel.gen_case(random.Random(1)); c, rq, env, seen = ({"iss": "iss", "aud": "gw", "iat": 990, "exp": 1020, "sub": "a", "tenant": "t", "effect": "write", "target": {"kind": "file", "canonical_id": "/x"}, "args_digest": "sha256:" + "a" * 64, "contract_version": "c1", "policy_version": "p1", "nonce": "n1"}, rq, dict(env, policy="p1"), set())
        self.assertEqual(diffkernel.ref_decide(c, rq, env, seen), "OK")
        for k, v, code in (("iss", "x", "BAD_ISSUER"), ("aud", "x", "BAD_AUDIENCE"), ("exp", 900, "MALFORMED"), ("sub", "x", "PRINCIPAL_MISMATCH"), ("tenant", "x", "TENANT_MISMATCH"), ("effect", "x", "EFFECT_MISMATCH"), ("args_digest", "x", "ARGS_MISMATCH"), ("contract_version", "x", "CONTRACT_MISMATCH"), ("policy_version", "x", "STALE_POLICY")):
            self.assertEqual(diffkernel.ref_decide(dict(c, **{k: v}), rq, env, seen), code, k)
        self.assertEqual(diffkernel.ref_decide(c, rq, env, {"n1"}), "REPLAY"); self.assertEqual(diffkernel.ref_decide(dict(c, exp=1004, iat=900), rq, env, seen), "EXPIRED" if 1000 > 1004 + 5 else "OK")
    def test_differential_against_verifier_5000_cases(self):
        s = Signer.generate("k0", "iss"); rng = random.Random(7); n = mism = 0; codes = set()
        for i in range(5000):
            claim, req, env, seen = diffkernel.gen_case(rng); ts = TrustStore(clock=lambda: 1000)
            for kid, iss in (("k-iss", "iss"), ("k-issx", "issx")): ts.add(kid, iss, s.public_raw(), not_before=0, not_after=10**6)
            ns = NonceStore(clock=lambda: 1000)
            for x in seen: ns.consume(x, 2000)
            v = Verifier(ts, ns, issuer="iss", audience="gw", contract_version="c1", policy_version=(None if env["policy"] is None else (lambda: "p1")), clock=lambda: 1000)
            body = {k: claim[k] for k in E.FIELDS if k != "v"}; body["v"] = 1
            try:
                tok = E.sign(s._p, "k-iss" if claim["iss"] == "iss" else "k-issx", body) if claim["iss"] in ("iss", "issx") else None
            except E.EffectError: tok = None
            if tok is None: continue
            exp = diffkernel.ref_decide(claim, req, env, seen)
            try: v.verify(tok, principal=req["principal"], tenant=req["tenant"], effect=req["effect"], target={"kind": "file", "raw": "/x"}, args_digest=req["args_digest"]); got = "OK"
            except ProofError as e: got = e.code
            n += 1; codes.add(exp)
            if got != exp: mism += 1
        self.assertGreater(n, 1000); self.assertEqual(mism, 0); self.assertGreaterEqual(len(codes), 6)
class Sink(unittest.TestCase):
    @staticmethod
    def wf(real_block):
        def run(sinks, control):
            log = []
            for tag in ("a", "b"):
                if control and control(tag): log.append(f"blocked:{tag}"); (None if not real_block else None)
                if control and control(tag) and real_block: continue
                sinks.write("net", tag)
            return log
        return run
    def test_effective_control(self):
        r = sinkdiff.diff(self.wf(True), lambda t: t == "b", sinkdiff.Rows); self.assertTrue(r["control_effective"]); self.assertEqual(r["removed_by_control"], [("net", "b")]); self.assertEqual(r["claims_without_effect"], [])
    def test_control_that_only_logs_is_flagged(self):
        r = sinkdiff.diff(self.wf(False), lambda t: t == "b", sinkdiff.Rows); self.assertFalse(r["control_effective"]); self.assertEqual(r["claims_without_effect"], ["blocked:b"])
    def test_no_control_no_change(self): r = sinkdiff.diff(self.wf(True), lambda t: False, sinkdiff.Rows); self.assertEqual((r["removed_by_control"], r["added_by_control"], r["baseline_effects"]), ([], [], 2))
    def test_side_effects_added_detected(self):
        def wf(sinks, control):
            sinks.write("net", "a")
            if control: sinks.write("fs", "shadow")
        r = sinkdiff.diff(wf, lambda t: True, sinkdiff.Rows); self.assertTrue(r["side_effects_added"])
class Wit(unittest.TestCase):
    A = {"trust_root": "R1", "signing_key": "K1", "operator": "o1", "host": "h1", "os_user": "u1", "library": "L1", "network_path": "n1"}
    def test_shared_key_dependent(self): b = dict(self.A, trust_root="R2", signing_key="K1", operator="o2", host="h2", os_user="u2", library="L2", network_path="n2"); self.assertTrue(witnesses.dependent(self.A, b))
    def test_shared_trust_root_dependent(self): self.assertTrue(witnesses.dependent(self.A, {"trust_root": "R1", "host": "z"}))
    def test_shared_operator_dependent(self): self.assertTrue(witnesses.dependent(self.A, {"operator": "o1"}))
    def test_fully_distinct_independent(self): b = {"trust_root": "R2", "signing_key": "K2", "operator": "o2", "host": "h2", "os_user": "u2", "library": "L2", "network_path": "n2"}; self.assertFalse(witnesses.dependent(self.A, b)); self.assertEqual(witnesses.similarity(self.A, b), 0)
    def test_soft_similarity_threshold(self):
        b = {"trust_root": "R2", "signing_key": "K2", "operator": "o2", "host": "h1", "os_user": "u1", "library": "Lx", "network_path": "nx"}; self.assertTrue(witnesses.dependent(self.A, b)); self.assertFalse(witnesses.dependent(self.A, dict(b, os_user="uz")))
    def test_missing_attributes_never_count_as_shared(self): self.assertFalse(witnesses.dependent({"host": None}, {"host": None}))
    def test_clusters_transitive_and_count(self):
        ws = {"a": {"signing_key": "K1"}, "b": {"signing_key": "K1", "operator": "o"}, "c": {"operator": "o"}, "d": {"signing_key": "K9"}}
        self.assertEqual(witnesses.clusters(ws), [["a", "b", "c"], ["d"]]); self.assertEqual(witnesses.effective_independent(ws), 2); self.assertTrue(witnesses.may_claim_independent(ws))
    def test_three_witnesses_one_cluster_cannot_claim_independence(self):
        ws = {n: {"trust_root": "R", "host": n} for n in "abc"}; self.assertEqual(witnesses.effective_independent(ws), 1); self.assertFalse(witnesses.may_claim_independent(ws))
    def test_empty(self): self.assertFalse(witnesses.may_claim_independent({}))
class Race(unittest.TestCase):
    def test_designs(self):
        r = {d: racebench.evaluate(d) for d in racebench.DESIGNS}
        self.assertEqual(r["NAIVE"]["violating_schedules"], 1); self.assertEqual(r["ATOMIC"]["violating_schedules"], 0); self.assertEqual(r["EPOCH_FENCED"]["violating_schedules"], 0)
        self.assertEqual(r["CHECK_AFTER"]["violating_schedules"], r["CHECK_AFTER"]["detected_after_the_fact"]); self.assertGreaterEqual(r["CHECK_AFTER"]["violating_schedules"], 1)
        self.assertEqual(r["NAIVE"]["schedules"], 3); self.assertEqual(r["ATOMIC"]["schedules"], 2)
    def test_interleavings_complete_and_ordered(self):
        s = list(racebench.interleavings(["a", "b"], ["r"])); self.assertEqual(len(s), 3); self.assertTrue(all([x for w, x in z if w == "C"] == ["a", "b"] for z in s))
    def test_recheck_on_retry_is_safe(self): self.assertTrue(racebench.crash_recovery_safe())
class Neg(unittest.TestCase):
    def setUp(self):
        self.s = Signer.generate("kc", "custodian"); self.ts = TrustStore(); self.ts.add("kc", "custodian", self.s.public_raw(), not_before=0, not_after=2**40); self.r = negreg.NegRegistry(self.s)
        self.r.append("sandbox-v1", "symlink-escape", "FAILED", "a" * 64, "abc"); self.r.append("gate-v2", "id-collision", "HELD_UNDER_TEST", "b" * 64, "abd")
    def test_chain_verifies(self): self.assertTrue(negreg.verify_chain(self.r.recs, self.ts))
    def test_tamper_detected(self):
        import copy
        for k, v in (("outcome", "HELD_UNDER_TEST"), ("defense", "x"), ("commit", "zz"), ("evidence_sha256", "c" * 64), ("seq", 5)):
            recs = copy.deepcopy(self.r.recs); recs[0][k] = v; self.assertFalse(negreg.verify_chain(recs, self.ts), k)
    def test_reorder_and_drop_detected(self):
        self.assertFalse(negreg.verify_chain(self.r.recs[::-1], self.ts)); self.assertFalse(negreg.verify_chain(self.r.recs[1:], self.ts))
    def test_wrong_key_rejected(self):
        ts = TrustStore(); ts.add("kc", "custodian", Signer.generate("x", "custodian").public_raw(), not_before=0, not_after=2**40); self.assertFalse(negreg.verify_chain(self.r.recs, ts))
    def test_bad_input(self):
        for a in (("d", "a", "WON", "e", "c"), ("", "a", "FAILED", "e", "c")):
            with self.assertRaises(negreg.NegError): self.r.append(*a)
    def test_partial_result_also_suspends(self):
        r = negreg.NegRegistry(self.s); r.append("d1", "a", "PARTIAL", "e" * 64, "c"); reg = Registry(lambda: 1); self.assertEqual(r.suspend_dependants(reg), ["d1"])
    def test_query(self): self.assertEqual(len(self.r.query(outcome="FAILED")), 1); self.assertEqual(len(self.r.query(defense="gate-v2")), 1)
    def test_failed_result_suspends_dependent_claim_but_held_does_not(self):
        reg = Registry(lambda: 100); reg.set_node("sandbox-v1", "d"); reg.set_node("gate-v2", "d")
        reg.add(AssuranceClaim("c:fs", ("fs",), 1, 200, ("sandbox-v1",), (("sandbox-v1", "d"),))); reg.add(AssuranceClaim("c:mcp", ("mcp",), 1, 200, ("gate-v2",), (("gate-v2", "d"),)))
        self.assertEqual(self.r.suspend_dependants(reg), ["sandbox-v1"]); self.assertEqual(reg.status("c:fs", 1)[0], "SUSPENDED"); self.assertEqual(reg.status("c:mcp", 1)[0], "VALID")
if __name__ == "__main__": unittest.main()
