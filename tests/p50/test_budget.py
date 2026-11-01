import json, os, random, tempfile, threading, unittest
from horizon.hpolicy.authority import HorizonPolicy, EvidenceError
from horizon.budget import units as U, ledger as L, broker as B, sinks as S, harness as H, scenarios as SC, experiment as X
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SYS = {s.name: s for s in H.systems()}
def run(sid, name): return X.run_one(next(s for s in SC.SCENARIOS if s["id"] == sid), SYS[name])
def src(m):
    import ast
    t = ast.parse(open(os.path.join(ROOT, "horizon/budget", m + ".py")).read())
    if t.body and isinstance(t.body[0], ast.Expr) and isinstance(getattr(t.body[0], "value", None), ast.Constant): t.body = t.body[1:]
    return ast.unparse(t)


class Mk:
    def __init__(self, limits=None, **kw):
        self.t = [1000.0]; self.clk = lambda: self.t[0]; self.A = HorizonPolicy("pol-1", clock=self.clk); self.owner = self.A.register_issuer("owner", {"ATTESTATION"}); self.other = self.A.register_issuer("ci", {"ATTESTATION"})
        self.led = L.Ledger(":memory:", self.A.verifier(), self.clk, **kw)
        if limits is not None: self.led.open_task(self.tok("T", limits))
    def tok(self, task, limits, principal="lead", rev=3, ver=1, issuer=None):
        c = {"type": "budget", "task": task, "limits": limits, "rev": rev}; return (issuer or self.owner).issue("ATTESTATION", principal=principal, artifact=task, args_digest=U.digest(c), object_version=ver, claim=c, ttl=10 ** 7, now=1000)


class Units(unittest.TestCase):
    def test_cost_from_registry(self): self.assertEqual(U.cost_of("export_csv", {"rows": 5}), {"export_rows": 5}); self.assertEqual(U.cost_of("http_get", {}), {"requests": 1})
    def test_same_class_across_tools(self): self.assertEqual(U.cost_of("export_json", {"records": 3}), {"export_rows": 3}); self.assertEqual(U.cost_of("export_bulk", {"n": 3}), {"export_rows": 3})
    def test_bad_units_refused(self):
        for v in (-1, 1.5, True, "5", None, 10 ** 10): 
            with self.assertRaises(U.CostError): U.cost_of("export_csv", {"rows": v})
    def test_unknown_tool(self):
        with self.assertRaises(U.CostError): U.cost_of("rm_rf", {})
    def test_agent_declared_cost_ignored(self): self.assertEqual(U.cost_of("export_csv", {"rows": 5, "cost": 0, "export_rows": 0}), {"export_rows": 5})
    def test_clean_limits(self):
        self.assertEqual(U.clean_limits({"requests": 3}), {"requests": 3})
        for bad in ({"nope": 1}, {"requests": -1}, {"requests": 1.0}, [], {"requests": True}):
            with self.assertRaises(U.CostError): U.clean_limits(bad)
    def test_classes_and_damage(self): self.assertEqual(len(U.CLASSES), 5); self.assertTrue(set(U.IRREVERSIBLE) <= set(U.CLASSES))
    def test_naive_cost_allows_negative(self): self.assertEqual(B.naive_cost("export_csv", {"rows": -5}), ("export_rows", -5))


class Assignment(unittest.TestCase):
    def test_open_and_remaining(self): m = Mk({"export_rows": 10}); self.assertEqual(m.led.remaining("T"), {"export_rows": 10})
    def test_wrong_role_refused(self):
        m = Mk(); 
        with self.assertRaises(EvidenceError) as c: m.led.open_task(m.tok("T", {"export_rows": 10}, issuer=m.other))
        self.assertEqual(c.exception.code, "ROLE_NOT_OWNER")
    def test_policy_revision_bound(self):
        m = Mk()
        with self.assertRaises(EvidenceError) as c: m.led.open_task(m.tok("T", {"export_rows": 10}, rev=2))
        self.assertEqual(c.exception.code, "POLICY_REVISION")
    def test_version_must_increase(self):
        m = Mk({"export_rows": 10})
        with self.assertRaises(EvidenceError) as c: m.led.open_task(m.tok("T", {"export_rows": 10 ** 6}, ver=1))
        self.assertEqual(c.exception.code, "STALE_VERSION"); m.led.open_task(m.tok("T", {"export_rows": 20}, ver=2)); self.assertEqual(m.led.remaining("T"), {"export_rows": 20})
    def test_digest_must_match_claim(self):
        m = Mk(); c = {"type": "budget", "task": "T", "limits": {"requests": 1}, "rev": 3}
        t = m.owner.issue("ATTESTATION", principal="lead", artifact="T", args_digest=U.digest({**c, "limits": {"requests": 99}}), claim=c, now=1000)
        with self.assertRaises(EvidenceError): m.led.open_task(t)
    def test_not_a_budget(self):
        m = Mk(); t = m.owner.issue("ATTESTATION", principal="lead", artifact="T", claim={"type": "other"}, now=1000)
        with self.assertRaises(EvidenceError): m.led.open_task(t)
    def test_type_must_be_budget_even_with_valid_digest(self):
        m = Mk(); c = {"type": "other", "task": "T", "limits": {"requests": 1}, "rev": 3}
        with self.assertRaises(EvidenceError) as e: m.led.open_task(m.owner.issue("ATTESTATION", principal="lead", artifact="T", args_digest=U.digest(c), claim=c, now=1000))
        self.assertEqual(e.exception.code, "MALFORMED")
    def test_wrong_kind_refused(self):
        m = Mk(); m.A.register_issuer("approver", {"APPROVAL"}); i = m.A.register_issuer("owner2", {"APPROVAL"}); c = {"type": "budget", "task": "T", "limits": {}, "rev": 3}
        with self.assertRaises(EvidenceError): m.led.open_task(i.issue("APPROVAL", principal="lead", artifact="T", args_digest=U.digest(c), claim=c, now=1000))
    def test_bad_limits_refused(self):
        m = Mk()
        with self.assertRaises(U.CostError): m.led.open_task(m.tok("T", {"export_rows": -5}))
    def test_unsigned_ablation_accepts_any_role(self): m = Mk(signed=False); m.led.open_task(m.tok("T", {"export_rows": 5}, issuer=m.other)); self.assertEqual(m.led.remaining("T"), {"export_rows": 5})
    def test_expired_token_refused(self):
        m = Mk(); t = m.tok("T", {"requests": 1}); m.t[0] = 10 ** 9
        with self.assertRaises(EvidenceError): m.led.open_task(t)
    def test_no_budget_no_effect(self): m = Mk(); self.assertEqual(m.led.reserve("NOPE", "x", "r", "d", {"requests": 1})["reason"], "NO_BUDGET")


class Lifecycle(unittest.TestCase):
    def setUp(self): self.m = Mk({"export_rows": 100, "requests": 5}); self.l = self.m.led
    def test_reserve_commit(self):
        self.assertTrue(self.l.reserve("T", "lead", "r1", "d", {"export_rows": 60})["ok"]); self.assertEqual(self.l.remaining("T")["export_rows"], 40); self.l.start("r1"); self.l.commit("r1", {"export_rows": 60}); self.assertEqual(self.l.state("r1"), "COMMITTED")
    def test_over_cap_denied(self): self.l.reserve("T", "lead", "r1", "d", {"export_rows": 60}); r = self.l.reserve("T", "lead", "r2", "d", {"export_rows": 41}); self.assertEqual((r["ok"], r["reason"]), (False, "BUDGET_EXCEEDED"))
    def test_exact_cap_allowed(self): self.assertTrue(self.l.reserve("T", "lead", "r1", "d", {"export_rows": 100})["ok"]); self.assertFalse(self.l.reserve("T", "lead", "r2", "d", {"export_rows": 1})["ok"])
    def test_zero_cost_class_not_checked(self): self.l.reserve("T", "lead", "r1", "d", {"export_rows": 100}); self.assertTrue(self.l.reserve("T", "lead", "r2", "d", {"requests": 1})["ok"])
    def test_unlisted_class_has_zero_cap(self): self.assertFalse(self.l.reserve("T", "lead", "r1", "d", {"compute_units": 1})["ok"])
    def test_release_refunds_only_unstarted(self):
        self.l.reserve("T", "lead", "r1", "d", {"export_rows": 60}); self.assertTrue(self.l.release("r1")["ok"]); self.assertEqual(self.l.remaining("T")["export_rows"], 100)
        self.l.reserve("T", "lead", "r2", "d", {"export_rows": 60}); self.l.start("r2"); self.assertFalse(self.l.release("r2")["ok"]); self.assertEqual(self.l.remaining("T")["export_rows"], 40)
    def test_expiry_refunds_unstarted(self):
        self.l.reserve("T", "lead", "r1", "d", {"export_rows": 60}, ttl=10); self.m.t[0] += 11; self.assertEqual(self.l.remaining("T")["export_rows"], 100) if self.l.reserve("T", "lead", "r9", "d", {"requests": 1}) else None; self.assertEqual(self.l.state("r1"), "EXPIRED")
    def test_expiry_boundary(self):
        self.l.reserve("T", "lead", "r1", "d", {"export_rows": 60}, ttl=10); self.m.t[0] += 10; self.l.reserve("T", "lead", "r9", "d", {"requests": 1}); self.assertEqual(self.l.state("r1"), "RESERVED"); self.m.t[0] += 1; self.l.reserve("T", "lead", "r8", "d", {"requests": 1}); self.assertEqual(self.l.state("r1"), "EXPIRED")
    def test_started_timeout_becomes_unknown_and_stays_charged(self):
        self.l.reserve("T", "lead", "r1", "d", {"export_rows": 60}, ttl=10); self.l.start("r1"); self.m.t[0] += 11; self.l.reserve("T", "lead", "r9", "d", {"requests": 1}); self.assertEqual(self.l.state("r1"), "UNKNOWN"); self.assertEqual(self.l.remaining("T")["export_rows"], 40)
    def test_reconcile_with_observed_commits(self):
        self.l.reserve("T", "lead", "r1", "d", {"export_rows": 60}, ttl=10); self.l.start("r1"); self.m.t[0] += 11; self.l.reserve("T", "lead", "r9", "d", {"requests": 1}); self.l.reconcile("r1", {"export_rows": 60}); self.assertEqual(self.l.state("r1"), "COMMITTED")
    def test_reconcile_zero_refunds(self):
        self.l.reserve("T", "lead", "r1", "d", {"export_rows": 60}); self.l.start("r1"); self.l.reconcile("r1", {"export_rows": 0}); self.assertEqual(self.l.state("r1"), "RELEASED"); self.assertEqual(self.l.remaining("T")["export_rows"], 100)
    def test_reconcile_mixed_observation_charges_not_refunds(self):
        self.l.reserve("T", "lead", "r1", "d", {"export_rows": 60}); self.l.start("r1"); self.l.reconcile("r1", {"export_rows": 0, "requests": 3}); self.assertEqual(self.l.state("r1"), "COMMITTED"); self.assertEqual(self.l.used("T"), {"export_rows": 0, "requests": 3})
    def test_reconcile_unreachable_keeps_charge(self):
        self.l.reserve("T", "lead", "r1", "d", {"export_rows": 60}); self.l.start("r1"); r = self.l.reconcile("r1", None); self.assertTrue(r["unknown"]); self.assertEqual(self.l.remaining("T")["export_rows"], 40)
    def test_commit_shortfall_refunds_difference(self): self.l.reserve("T", "lead", "r1", "d", {"export_rows": 60}); self.l.start("r1"); self.l.commit("r1", {"export_rows": 20}); self.assertEqual(self.l.remaining("T")["export_rows"], 80)
    def test_commit_overrun_charged_and_noted(self):
        self.l.reserve("T", "lead", "r1", "d", {"export_rows": 10}); self.l.start("r1"); r = self.l.commit("r1", {"export_rows": 150}); self.assertEqual(r["overrun"], {"export_rows": 140}); self.assertEqual(self.l.remaining("T")["export_rows"], -50)
    def test_commit_requires_start(self): self.l.reserve("T", "lead", "r1", "d", {"export_rows": 5}); self.assertEqual(self.l.commit("r1", {"export_rows": 5})["reason"], "NOT_STARTED")
    def test_double_start_refused(self): self.l.reserve("T", "lead", "r1", "d", {"export_rows": 5}); self.l.start("r1"); self.assertFalse(self.l.start("r1")["ok"])
    def test_double_commit_refused(self): self.l.reserve("T", "lead", "r1", "d", {"export_rows": 5}); self.l.start("r1"); self.l.commit("r1", {"export_rows": 5}); self.assertFalse(self.l.commit("r1", {"export_rows": 5})["ok"])
    def test_idempotent_same_digest(self):
        self.l.reserve("T", "lead", "r1", "d", {"export_rows": 60}); r = self.l.reserve("T", "lead", "r1", "d", {"export_rows": 60}); self.assertTrue(r["replayed"]); self.assertEqual(self.l.remaining("T")["export_rows"], 40)
    def test_reused_id_different_digest(self): self.l.reserve("T", "lead", "r1", "d", {"export_rows": 5}); self.assertEqual(self.l.reserve("T", "lead", "r1", "e", {"export_rows": 5})["reason"], "REQUEST_ID_REUSE")
    def test_reused_id_other_scope(self): self.l.reserve("T", "lead", "r1", "d", {"export_rows": 5}); self.l.delegate("T", "c", "kid", {"export_rows": 5}); self.assertEqual(self.l.reserve("c", "kid", "r1", "d", {"export_rows": 5})["reason"], "REQUEST_ID_REUSE")
    def test_expired_id_not_reusable(self): self.l.reserve("T", "lead", "r1", "d", {"export_rows": 5}, ttl=1); self.m.t[0] += 5; self.assertEqual(self.l.reserve("T", "lead", "r1", "d", {"export_rows": 5})["reason"], "RESERVATION_EXPIRED")
    def test_bad_cost_refused(self):
        for c in ({"export_rows": -1}, {"export_rows": 1.5}, {"nope": 1}): self.assertEqual(self.l.reserve("T", "lead", "r%s" % id(c), "d", c)["reason"], "BAD_COST")
    def test_principal_bound_to_scope(self): self.assertEqual(self.l.reserve("T", "evil", "r1", "d", {"export_rows": 1})["reason"], "NOT_SCOPE_PRINCIPAL")
    def test_audit_chain(self): self.l.reserve("T", "lead", "r1", "d", {"export_rows": 5}); self.assertTrue(self.l.verify_chain()); self.l.db.execute("UPDATE entries SET body='{}' WHERE seq=1"); self.assertFalse(self.l.verify_chain())
    def test_denials_are_logged(self): self.l.reserve("T", "lead", "r1", "d", {"export_rows": 101}); self.assertEqual(self.l.entries()[-1]["why"], "BUDGET_EXCEEDED")


class Delegation(unittest.TestCase):
    def setUp(self): self.m = Mk({"export_rows": 100}); self.l = self.m.led
    def test_attenuation_clamps(self): self.assertEqual(self.l.delegate("T", "c", "kid", {"export_rows": 500})["cap"], {"export_rows": 100})
    def test_shared_pool(self):
        self.l.delegate("T", "a", "ka", {"export_rows": 100}); self.l.delegate("T", "b", "kb", {"export_rows": 100}); self.assertTrue(self.l.reserve("a", "ka", "r1", "d", {"export_rows": 70})["ok"]); self.assertFalse(self.l.reserve("b", "kb", "r2", "d", {"export_rows": 40})["ok"]); self.assertEqual(self.l.remaining("T")["export_rows"], 30)
    def test_child_cap_applies(self): self.l.delegate("T", "a", "ka", {"export_rows": 20}); self.assertFalse(self.l.reserve("a", "ka", "r1", "d", {"export_rows": 21})["ok"])
    def test_grandchild_counts_at_every_ancestor(self):
        self.l.delegate("T", "a", "ka", {"export_rows": 60}); self.l.delegate("a", "g", "kg", {"export_rows": 100}); self.assertEqual(self.l.remaining("g")["export_rows"], 60); self.assertTrue(self.l.reserve("g", "kg", "r1", "d", {"export_rows": 50})["ok"]); self.assertEqual(self.l.remaining("a")["export_rows"], 10); self.assertEqual(self.l.remaining("T")["export_rows"], 50)
    def test_class_not_in_parent_gets_zero(self): self.assertEqual(self.l.delegate("T", "c", "kid", {"requests": 5})["cap"], {"requests": 0})
    def test_no_parent(self): self.assertEqual(self.l.delegate("nope", "c", "kid", {})["reason"], "NO_PARENT")
    def test_scope_exists(self): self.l.delegate("T", "c", "kid", {}); self.assertEqual(self.l.delegate("T", "c", "other", {})["reason"], "SCOPE_EXISTS")
    def test_no_ancestor_ablation_resets_quota(self):
        m = Mk({"export_rows": 100}, ancestors=False); m.led.delegate("T", "a", "ka", {"export_rows": 100}); m.led.delegate("T", "b", "kb", {"export_rows": 100})
        self.assertTrue(m.led.reserve("a", "ka", "r1", "d", {"export_rows": 100})["ok"]); self.assertTrue(m.led.reserve("b", "kb", "r2", "d", {"export_rows": 100})["ok"]); self.assertTrue(m.led.invariants())
    def test_no_attenuation_ablation_keeps_ancestor_protection(self):
        m = Mk({"export_rows": 100}, attenuate=False); self.assertEqual(m.led.delegate("T", "a", "ka", {"export_rows": 500})["cap"], {"export_rows": 500}); m.led.reserve("a", "ka", "r1", "d", {"export_rows": 100}); self.assertFalse(m.led.reserve("a", "ka", "r2", "d", {"export_rows": 1})["ok"])
    def test_transfer_holds_at_parent(self):
        r = self.l.delegate("T", "c", "kid", {"export_rows": 40}, mode="transfer"); self.assertTrue(r["ok"]); self.assertEqual(self.l.remaining("T")["export_rows"], 60)
        self.assertTrue(self.l.reserve("c", "kid", "r1", "d", {"export_rows": 40})["ok"]); self.assertFalse(self.l.reserve("c", "kid", "r2", "d", {"export_rows": 1})["ok"]); self.assertEqual(self.l.remaining("T")["export_rows"], 60)
    def test_transfer_insufficient_parent(self): self.assertEqual(self.l.delegate("T", "c", "kid", {"export_rows": 101}, mode="transfer")["reason"], "PARENT_INSUFFICIENT")
    def test_transfer_close_returns_unused(self):
        self.l.delegate("T", "c", "kid", {"export_rows": 40}, mode="transfer"); self.l.reserve("c", "kid", "r1", "d", {"export_rows": 30}); self.l.close_scope("c"); self.assertEqual(self.l.remaining("T")["export_rows"], 70)
    def test_close_requires_transfer(self): self.l.delegate("T", "c", "kid", {"export_rows": 40}); self.assertFalse(self.l.close_scope("c")["ok"])
    def test_child_principal_bound(self): self.l.delegate("T", "c", "kid", {"export_rows": 40}); self.assertEqual(self.l.reserve("c", "lead", "r1", "d", {"export_rows": 1})["reason"], "NOT_SCOPE_PRINCIPAL")
    def test_invariants_hold(self): self.l.delegate("T", "c", "kid", {"export_rows": 40}); self.l.reserve("c", "kid", "r1", "d", {"export_rows": 40}); self.assertEqual(self.l.invariants(), [])


class Carriers(unittest.TestCase):
    def test_roundtrip_all_carriers(self):
        ctx = {"task": "T", "scope": "T", "agent": "a", "rid": "r"}
        for c in B.CARRIERS: self.assertEqual(B.decode(c, B.encode(c, ctx, "export_csv", {"rows": 3})), (ctx, "export_csv", {"rows": 3}))
    def test_malformed(self):
        for c in B.CARRIERS: self.assertIsNone(B.decode(c, {"junk": 1}))
    def test_all_carriers_charge_one_ledger(self):
        e = H.Env(SYS["budget"]); a = e.open("T", {"export_rows": 100}, "lead")
        for c in B.CARRIERS: self.assertEqual(a.call(c, *SC.exp(c, 25))["status"], "ok")
        self.assertEqual(a.call("mcp", "export_csv", {"rows": 1})["status"], "denied"); e.close()
    def test_malformed_context_denied(self): e = H.Env(SYS["budget"]); self.assertEqual(e.broker.call("x", {"junk": 1}, "mcp")["reason"], "MALFORMED_CONTEXT"); e.close()
    def test_non_object_context_denied(self):
        e = H.Env(SYS["budget"])
        for ctx in ([1], "x", 5, None): self.assertEqual(e.broker.call("x", {"effect": {"tool": "export_csv", "args": {"rows": 1}}, "ctx": ctx}, "os")["reason"], "MALFORMED_CONTEXT")
        e.close()
    def test_missing_request_id_denied(self):
        e = H.Env(SYS["budget"]); e.open("T", {"export_rows": 5}, "lead"); msg = B.encode("mcp", {"task": "T", "scope": "T"}, "export_csv", {"rows": 1}); self.assertEqual(e.broker.call("lead", msg, "mcp")["reason"], "NO_REQUEST_ID"); e.close()
    def test_unknown_tool_denied(self): e = H.Env(SYS["budget"]); a = e.open("T", {"export_rows": 5}, "lead"); self.assertEqual(a.call("mcp", "rm_rf", {})["reason"], "UNKNOWN_TOOL"); e.close()
    def test_charge_is_what_the_receiver_observed(self):
        e = H.Env(SYS["budget"]); a = e.open("T", {"export_rows": 100}, "lead"); orig = e.rc.apply
        def half(tool, args, rid, task, cls, key, max_units=None): r = orig(tool, {**args, key: args[key] // 2}, rid, task, cls, key, max_units); return r
        e.rc.apply = half; self.assertEqual(a.call("mcp", "export_csv", {"rows": 40})["observed"], {"export_rows": 20}); self.assertEqual(e.led.remaining("T")["export_rows"], 80); e.close()
    def test_committed_retry_does_not_reach_the_receiver_again(self):
        e = H.Env(SYS["budget"]); a = e.open("T", {"export_rows": 100}, "lead"); a.call("mcp", "export_csv", {"rows": 10}, rid="same"); n = e.rc.calls; r = a.call("utcp", "export_csv", {"rows": 10}, rid="same")
        self.assertEqual((r["status"], r.get("replayed"), e.rc.calls), ("ok", True, n)); self.assertEqual(e.rc.total("T", "export_rows"), 10); e.close()
    def test_spawn_requires_the_parent_principal(self):
        e = H.Env(SYS["budget"]); e.open("T", {"export_rows": 100}, "lead"); self.assertEqual(e.broker.spawn("T", "evil", "c", "kid", {"export_rows": 50})["reason"], "NOT_SCOPE_PRINCIPAL"); self.assertTrue(e.broker.spawn("T", "lead", "c", "kid", {"export_rows": 50})["ok"]); e.close()
    def test_sink_cap_limits_real_effect(self):
        e = H.Env(SYS["budget"]); a = e.open("T", {"export_rows": 5}, "lead"); a.call("codemode", "export_bulk", {"n": 3, "expand": True}); self.assertEqual(e.rc.total("T", "export_rows"), 3); e.close()


class Receiver(unittest.TestCase):
    def test_idempotent_by_request_id(self): r = S.Receiver(); r.apply("export_csv", {"rows": 5}, "x", "T", "export_rows", "rows"); self.assertTrue(r.apply("export_csv", {"rows": 5}, "x", "T", "export_rows", "rows")["replayed"]); self.assertEqual(r.total("T", "export_rows"), 5)
    def test_non_idempotent_double_applies(self): r = S.Receiver(idempotent=False); [r.apply("export_csv", {"rows": 5}, "x", "T", "export_rows", "rows") for _ in range(2)]; self.assertEqual(r.total("T", "export_rows"), 10)
    def test_negative_does_nothing(self): r = S.Receiver(); r.apply("export_csv", {"rows": -5}, "x", "T", "export_rows", "rows"); self.assertEqual(r.total("T", "export_rows"), 0)
    def test_crash_after_effect_still_applies(self):
        r = S.Receiver(); r.crash_after.add("x")
        with self.assertRaises(TimeoutError): r.apply("export_csv", {"rows": 5}, "x", "T", "export_rows", "rows")
        self.assertEqual(r.total("T", "export_rows"), 5); self.assertEqual(r.observe("x"), {"export_rows": 5})
    def test_drop_before_effect(self):
        r = S.Receiver(); r.drop_before.add("x")
        with self.assertRaises(TimeoutError): r.apply("export_csv", {"rows": 5}, "x", "T", "export_rows", "rows")
        self.assertEqual(r.total("T", "export_rows"), 0)
    def test_silent_telemetry(self): r = S.Receiver(); r.apply("export_csv", {"rows": 5}, "x", "T", "export_rows", "rows"); r.silent = True; self.assertIsNone(r.observe("x"))
    def test_max_units_hard_cap(self): r = S.Receiver(); r.apply("export_bulk", {"n": 3, "expand": True}, "x", "T", "export_rows", "n", max_units={"export_rows": 3}); self.assertEqual(r.total("T", "export_rows"), 3)
    def test_expand_without_cap(self): r = S.Receiver(); r.apply("export_bulk", {"n": 3, "expand": True}, "x", "T", "export_rows", "n"); self.assertEqual(r.total("T", "export_rows"), 150)


class Matrix(unittest.TestCase):
    def test_full_system_never_over_budget(self):
        for s in SC.SCENARIOS:
            r = run(s["id"], "budget"); self.assertEqual(r["over"], [], s["id"]); self.assertEqual(r["invariants"], []); self.assertTrue(r["chain"])
    def test_full_system_completes_benign(self):
        for s in SC.SCENARIOS:
            if s["kind"] == "benign": self.assertTrue(run(s["id"], "budget")["completed"], s["id"])
    def test_benign_complete_under_all_baselines(self):
        for n in ("none", "per-agent-cap", "eventual-counter", "post-hoc-alert", "single-protocol-limiter", "per-tool-cap"):
            for s in SC.SCENARIOS:
                if s["kind"] == "benign": self.assertTrue(run(s["id"], n)["completed"], (n, s["id"]))
    def test_baseline_failures(self):
        self.assertTrue(run("A01", "per-agent-cap")["over"]); self.assertTrue(run("A03", "per-agent-cap")["over"]); self.assertTrue(run("A04", "single-protocol-limiter")["over"]); self.assertTrue(run("A01", "per-tool-cap")["over"])
        self.assertTrue(run("A02", "eventual-counter")["over"]); self.assertTrue(run("A08", "post-hoc-alert")["over"]); self.assertTrue(run("A01", "none")["over"])
    def test_single_protocol_limiter_holds_when_one_carrier(self): self.assertEqual(run("A02", "single-protocol-limiter")["over"], [])
    def test_ablation_targets(self):
        T = {"atomic": "A02", "ancestors": "A03", "idempotency": "A05", "conservative": "A06", "signature": "A09", "principal-binding": "A10", "sink-cap": "A07", "reconcile": "A07"}
        for n, sid in T.items(): self.assertTrue(run(sid, "budget-no-" + n)["over"], n)
    def test_attenuation_is_redundant_with_ancestor_checks(self):
        for s in SC.SCENARIOS: self.assertEqual(run(s["id"], "budget-no-attenuation")["over"], [], s["id"])
    def test_no_atomic_race_breaks_invariant(self): self.assertTrue(run("A02", "budget-no-atomic")["invariants"])
    def test_unknowns_reported(self): self.assertEqual(run("F01", "budget")["unknown_reservations"], 1); self.assertEqual(run("F01", "budget")["over"], []); self.assertTrue(run("F01", "budget-no-conservative")["over"])
    def test_retry_charged_once(self):
        r = run("B02", "budget"); self.assertTrue(r["completed"]); self.assertEqual(r["effects"], 50)
    def test_no_idempotency_double_effect(self): self.assertEqual(run("B02", "budget-no-idempotency")["effects"], 100)
    def test_transfer_return(self): self.assertTrue(run("B08", "budget")["completed"])
    def test_system_list(self): self.assertEqual(len(SYS), 16)


class Reference:
    """Independent model of the lifecycle for the property test: plain dicts, no SQL."""
    def __init__(self, caps, kids, t): self.caps, self.parent, self.res, self.t = caps, kids, {}, t
    def chain(self, s): out = [s]; [out.append(self.parent[out[-1]]) for _ in range(5) if out[-1] in self.parent]; return out
    def used(self, node):
        u = {}
        for r in self.res.values():
            if r["state"] in ("RESERVED", "STARTED", "COMMITTED", "UNKNOWN") and node in self.chain(r["scope"]):
                for k, v in r["charge"].items(): u[k] = u.get(k, 0) + v
        return u
    def sweep(self, now):
        for r in self.res.values():
            if r["state"] in ("RESERVED", "STARTED") and r["t0"] + r["ttl"] < now: r["state"] = "EXPIRED" if r["state"] == "RESERVED" else "UNKNOWN"
    def reserve(self, scope, rid, cost, now, ttl):
        self.sweep(now)
        if rid in self.res: return self.res[rid]["state"] in ("RESERVED", "STARTED", "COMMITTED", "UNKNOWN") and self.res[rid]["scope"] == scope
        for n in self.chain(scope):
            u = self.used(n)
            if any(v > 0 and u.get(k, 0) + v > self.caps[n].get(k, 0) for k, v in cost.items()): return False
        self.res[rid] = {"scope": scope, "charge": dict(cost), "state": "RESERVED", "t0": now, "ttl": ttl}; return True
    def start(self, rid, now):
        self.sweep(now); r = self.res.get(rid)
        if not r or r["state"] != "RESERVED": return False
        r["state"] = "STARTED"; return True
    def release(self, rid, now):
        self.sweep(now); r = self.res.get(rid)
        if not r or r["state"] != "RESERVED": return False
        r["state"] = "RELEASED"; return True
    def commit(self, rid, obs, now):
        self.sweep(now); r = self.res.get(rid)
        if not r or r["state"] not in ("STARTED", "UNKNOWN"): return False
        r["state"] = "COMMITTED"; r["over"] = any(v > r["charge"].get(k, 0) for k, v in obs.items()); r["charge"] = dict(obs); return True


class Property(unittest.TestCase):
    def test_random_sequences_match_reference_and_never_overspend(self):
        rng = random.Random(50); n_over = 0
        for trial in range(400):
            m = Mk({"export_rows": rng.choice([20, 50, 100]), "requests": 6}); l = m.led; l.delegate("T", "A", "pa", {"export_rows": rng.choice([10, 30, 200])}); l.delegate("A", "G", "pg", {"export_rows": 25})
            ref = Reference({"T": dict(l._scope("T")["cap"]), "A": dict(l._scope("A")["cap"]), "G": dict(l._scope("G")["cap"])}, {"A": "T", "G": "A"}, m.t[0]); P = {"T": "lead", "A": "pa", "G": "pg"}; ids = []; overran = False
            for step in range(30):
                op = rng.choice(["reserve"] * 4 + ["start", "commit", "release", "tick", "commit_over", "reconcile0"]); now = m.t[0]
                if op == "reserve":
                    sc = rng.choice("TAG"); rid = rng.choice(ids) if ids and rng.random() < 0.15 else "r%d" % len(ids); cost = {"export_rows": rng.randint(0, 30)}
                    if rng.random() < 0.2: cost = {"requests": rng.randint(0, 4)}
                    a = l.reserve(sc, P[sc], rid, "d", cost, ttl=5)["ok"]; b = ref.reserve(sc, rid, cost, now, 5); self.assertEqual(a, b, (trial, step, op)); ids.append(rid) if rid not in ids else None
                elif ids:
                    rid = rng.choice(ids)
                    if op == "start": self.assertEqual(l.start(rid)["ok"], ref.start(rid, now))
                    elif op == "release": self.assertEqual(l.release(rid)["ok"], ref.release(rid, now))
                    elif op in ("commit", "commit_over"):
                        rs = ref.res.get(rid); base = (rs or {"charge": {"export_rows": 5}})["charge"]; obs = {k: (v + rng.randint(1, 20) if op == "commit_over" else rng.randint(0, v)) for k, v in base.items()}
                        a = l.commit(rid, obs)["ok"]; b = ref.commit(rid, obs, now); self.assertEqual(a, b); overran = overran or bool(a and ref.res[rid].get("over"))
                    elif op == "reconcile0":
                        if l.state(rid) in ("STARTED", "UNKNOWN"): l.reconcile(rid, {"export_rows": 0}); ref.res[rid]["state"] = "RELEASED"
                elif op == "tick": pass
                if op == "tick": m.t[0] += rng.choice([1, 3, 7])
                if rng.random() < 0.1: m.t[0] += 2
            l.reserve("T", "lead", "final", "d", {"requests": 0}); ref.sweep(m.t[0])
            for rid, r in ref.res.items(): self.assertEqual(l.state(rid), r["state"], (trial, rid))
            if not overran: self.assertEqual(l.invariants(), [], trial)
            else: n_over += 1
            self.assertTrue(l.verify_chain())
        self.assertGreater(n_over, 0)
    def test_charges_never_decrease_except_by_refund_states(self):
        rng = random.Random(7); m = Mk({"export_rows": 60}); l = m.led; prev = 0
        for i in range(200):
            op = rng.choice(["r", "r", "s", "c", "x", "t"]); rid = "q%d" % rng.randint(0, 12)
            if op == "r": l.reserve("T", "lead", rid, "d", {"export_rows": rng.randint(0, 20)}, ttl=4)
            elif op == "s": l.start(rid)
            elif op == "c": l.commit(rid, {"export_rows": rng.randint(0, 20)})
            elif op == "x": l.release(rid)
            else: m.t[0] += 3
            l.reserve("T", "lead", "probe%d" % i, "d", {"requests": 0}); cur = l.used("T").get("export_rows", 0); states = {r: l.state(r) for r in ["q%d" % k for k in range(13)]}
            if cur < prev: self.assertTrue(op in ("x", "t", "c", "s") , (i, op))      # only release/expiry/shortfall can lower the charged total
            prev = cur
    def test_concurrent_reserve_never_overspends(self):
        d = tempfile.mkdtemp(); t = [1000.0]; clk = lambda: t[0]; A = HorizonPolicy("pol-1", clock=clk); ow = A.register_issuer("owner", {"ATTESTATION"}); path = os.path.join(d, "l.db")
        c = {"type": "budget", "task": "T", "limits": {"compute_units": 100}, "rev": 3}; tok = ow.issue("ATTESTATION", principal="lead", artifact="T", args_digest=U.digest(c), claim=c, ttl=10 ** 7, now=1000)
        L.Ledger(path, A.verifier(), clk).open_task(tok); led = L.Ledger(path, A.verifier(), clk); ok = []; bar = threading.Barrier(16)
        def w(i): bar.wait(); ok.append(led.reserve("T", "lead", "r%d" % i, "d", {"compute_units": 10})["ok"])
        ts = [threading.Thread(target=w, args=(i,)) for i in range(16)]; [x.start() for x in ts]; [x.join() for x in ts]
        self.assertEqual(sum(ok), 10); self.assertEqual(led.invariants(), []); self.assertTrue(led.verify_chain())
    def test_concurrent_processes(self):
        import subprocess, sys
        d = tempfile.mkdtemp(); path = os.path.join(d, "l.db"); code = """
import sys, json, os
sys.path.insert(0, %r)
from horizon.budget import ledger as L, units as U
from horizon.hpolicy.authority import HorizonPolicy
A = HorizonPolicy('pol-1', clock=lambda: 1000.0)
""" % ROOT
        t = [1000.0]; clk = lambda: t[0]; A = HorizonPolicy("pol-1", clock=clk); ow = A.register_issuer("owner", {"ATTESTATION"}); c = {"type": "budget", "task": "T", "limits": {"compute_units": 100}, "rev": 3}
        tok = ow.issue("ATTESTATION", principal="lead", artifact="T", args_digest=U.digest(c), claim=c, ttl=10 ** 7, now=1000); l1 = L.Ledger(path, A.verifier(), clk); l1.open_task(tok)
        import multiprocessing as mp
        def child(q, k): led = L.Ledger(path, A.verifier(), clk); q.put(sum(led.reserve("T", "lead", "p%d-%d" % (k, i), "d", {"compute_units": 10})["ok"] for i in range(10)))
        q = mp.get_context("fork").Queue(); ps = [mp.get_context("fork").Process(target=child, args=(q, k)) for k in range(4)]; [p.start() for p in ps]; got = sum(q.get() for _ in ps); [p.join() for p in ps]
        self.assertEqual(got, 10); self.assertEqual(l1.invariants(), [])


class Gates(unittest.TestCase):
    def test_modules_hold_no_issuer(self):
        for m in ("units", "ledger", "broker", "sinks", "scenarios", "experiment"): self.assertNotIn("register_issuer", src(m)); self.assertNotIn(".issue(", src(m))
    def test_receiver_independent_of_ledger(self):
        s = src("sinks"); self.assertNotIn("ledger", s); self.assertNotIn("horizon", s)
    def test_no_network(self):
        for m in ("units", "ledger", "broker", "sinks", "harness", "scenarios", "experiment"): self.assertNotRegex(src(m), r"https?://|import socket|import requests|urllib")
    def test_deterministic(self): self.assertEqual(json.dumps(X.run(), sort_keys=True, default=str), json.dumps(X.run(), sort_keys=True, default=str))
    def test_canary_not_needed_but_no_real_services(self): self.assertEqual(SYS["budget"].kind, "budget")


class Recorded(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.R = json.load(open(os.path.join(ROOT, "results/v2/p50-budget/result.json")))
    def test_full_system_zero_over_budget(self): self.assertEqual(self.R["summary"]["budget"]["attack_over_budget"]["k"], 0); self.assertEqual(self.R["summary"]["budget"]["benign_completed"]["k"], 8)
    def test_baselines_over_budget(self):
        for n in ("none", "per-agent-cap", "eventual-counter", "post-hoc-alert", "single-protocol-limiter", "per-tool-cap"): self.assertGreaterEqual(self.R["summary"][n]["attack_over_budget"]["k"], 4)
    def test_redundant_disclosed(self): self.assertIn("budget-no-attenuation", self.R["redundant"])
    def test_stored_results_match_live(self): self.assertEqual(json.loads(json.dumps(X.run(), default=str, sort_keys=True)), json.loads(json.dumps(self.R, default=str, sort_keys=True)))


if __name__ == "__main__": unittest.main()
