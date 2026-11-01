import ast, json, os, unittest
from horizon.hpolicy.authority import EvidenceError
from horizon.continuity import core as C, migrate as M, scenarios as SC, experiment as X, oracle as O, runtime as R, services as S
from horizon.continuity.world import World, eg, sd, sp, act, au, fin, xs
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SYS = {e.name: e for e in X.systems()}; SCN = {s["id"]: s for s in SC.SCENARIOS}
_cache = {}
def run(sid, name):
    k = (sid, name)
    if k not in _cache: _cache[k] = X.run_one(SYS[name], SCN[sid])
    return _cache[k]
def src(m): return open(os.path.join(ROOT, "horizon/continuity", m + ".py")).read()
ATT = [s["id"] for s in SC.SCENARIOS if s["kind"] == "attack"]; BEN = [s["id"] for s in SC.SCENARIOS if s["kind"] == "benign"]
def cont(**off): return M.Continuity("t", M.CCfg(**{k: False for k in off}))
def viol(sid, ex): return bool(X.run_one(ex, SCN[sid])["violations"])
def reasons(sid, ex): return X.run_one(ex, SCN[sid])["reasons"]
def env0():
    w = World(SYS["continuity"], SCN["B01"]); return w, M.build_env(w, "n-1")


class Core(unittest.TestCase):
    def test_envelope_valid(self): w, e = env0(); self.assertIs(C.validate(e), e); self.assertEqual(set(e), set(C.SECTIONS))
    def test_missing_extra_section(self):
        w, e = env0(); d = dict(e); d.pop("labels")
        with self.assertRaises(C.EnvError) as c: C.validate(d)
        self.assertEqual(c.exception.code, "MISSING_SECTION")
        with self.assertRaises(C.EnvError) as c: C.validate({**e, "x": 1})
        self.assertEqual(c.exception.code, "EXTRA_SECTION")
    def test_bad_controls_and_labels(self):
        w, e = env0()
        for k, v, code in (("controls", {"egress": 3}, "BAD_CONTROLS"), ("controls", {"nope": 1}, "BAD_CONTROLS"), ("controls", {}, "BAD_CONTROLS"), ("labels", {"d": "SECRET"}, "BAD_LABELS"), ("obligations", [{"id": "x"}], "BAD_OBLIGATIONS")):
            with self.assertRaises(C.EnvError) as c: C.validate({**e, k: v})
            self.assertEqual(c.exception.code, code)
    def test_no_raw_credential_in_envelope(self):
        w, e = env0(); self.assertNotIn(C.CANARY, json.dumps(e)); self.assertEqual(set(e["credentials"][0]), set(C.CRED_KEYS))
        with self.assertRaises(C.EnvError) as c: C.validate({**e, "credentials": [{"handle": "h", "scope": "r", "broker": "b", "value": "x"}]})
        self.assertEqual(c.exception.code, "RAW_CREDENTIAL_FIELD")
        with self.assertRaises(C.EnvError) as c: C.validate({**e, "labels": {"d": "PUBLIC"}, "artifacts": {"a": C.CANARY}})
        self.assertEqual(c.exception.code, "RAW_SECRET")
    def test_times_checked(self):
        w, e = env0()
        with self.assertRaises(C.EnvError): C.validate({**e, "exp": e["iat"]})
    def test_covers(self):
        K = {"egress": 1, "label": 1}; self.assertEqual(C.covers(K, {"egress": 2, "label": 1}), []); self.assertEqual(C.covers(K, {"egress": 0, "label": 1}), ["egress"]); self.assertEqual(C.covers(K, {}), ["egress", "label"]); self.assertEqual(C.covers({}, {}), [])
    def test_widening(self):
        g = {"chain": ["o", "a"], "permissions": ["read"]}; L = {"d": "CONFIDENTIAL"}; base = {"chain": ["o", "a"], "permissions": ["read"], "labels": {"d": "CONFIDENTIAL"}}
        self.assertEqual(C.widening(base, g, L), []); self.assertEqual(C.widening({**base, "permissions": ["read", "x"]}, g, L), ["PERMISSIONS_WIDENED"]); self.assertEqual(C.widening({**base, "chain": ["o"]}, g, L), ["CHAIN_CHANGED"])
        self.assertIn("LABEL_LOWERED", C.widening({**base, "labels": {"d": "PUBLIC"}}, g, L)); self.assertIn("LABEL_DROPPED", C.widening({**base, "labels": {}}, g, L)); self.assertIn("LABEL_DROPPED", C.widening({k: v for k, v in base.items() if k != "labels"}, g, L))
    def test_digest_canonical(self): self.assertEqual(C.digest({"a": 1, "b": 2}), C.digest({"b": 2, "a": 1})); self.assertNotEqual(C.digest([1]), C.digest([2]))
    def test_allowed_hosts(self): self.assertEqual(C.ALLOWED[2], ("intra.test",)); self.assertIn("partner.test", C.ALLOWED[1]); self.assertNotIn("evil.test", C.ALLOWED[1]); self.assertIn("evil.test", C.ALLOWED[0])


class Services(unittest.TestCase):
    def test_broker_rebind(self):
        b = S.Broker(); c1 = b.issue("t", "src", "read"); self.assertTrue(b.valid(c1, "src")); self.assertFalse(b.valid(c1, "tgt")); b.revoke_runtime("src"); self.assertFalse(b.valid(c1, "src"))
    def test_ledger_cap(self): l = S.Ledger({"api": 100}); self.assertTrue(l.charge("api", 100)); self.assertFalse(l.charge("api", 1)); self.assertEqual(l.get("api"), 100)
    def test_revocation_unknown_when_feed_down(self):
        r = S.Revocation(lambda: 5.0); self.assertEqual(r.status("k"), "LIVE"); r.revoke("k"); self.assertEqual(r.status("k"), "REVOKED"); r.feed_up = False; self.assertEqual(r.status("k"), "UNKNOWN")
    def test_attestation_binds_runtime_and_guarantees(self):
        w = World(SYS["continuity"], SCN["B01"]); p = w.verifier.verify(w.attestor.attest(w.tgt)); self.assertEqual(p["claim"]["rt"], "tgt"); self.assertEqual(p["role"], "attestor"); self.assertEqual(p["args_digest"], C.digest(p["claim"]))
    def test_unattestable_runtime(self):
        w = World(SYS["continuity"], SCN["U01"])
        with self.assertRaises(KeyError): w.attestor.attest(w.tgt)
    def test_receiver_records_time(self): t = [3.0]; r = S.Receiver(lambda: t[0]); r.record(rt="x", op="y", rid="1"); self.assertEqual(r.effects[0]["at"], 3.0)


class RuntimeOps(unittest.TestCase):
    def rt(self, sid="B01", name="continuity"):
        w = World(SYS[name], SCN[sid]); return w, w.src
    def test_egress_levels(self):
        w, s = self.rt(); self.assertEqual(s.op(w, eg("partner.test"))[0], "OK"); self.assertEqual(s.op(w, eg("evil.test")), ("DENIED", "EGRESS")); s.eff["egress"] = 2; self.assertEqual(s.op(w, eg("partner.test")), ("DENIED", "EGRESS")); s.eff["egress"] = 0; self.assertEqual(s.op(w, eg("evil.test"))[0], "OK")
    def test_secret_export_blocked(self): w, s = self.rt(); self.assertEqual(s.op(w, xs("partner.test")), ("DENIED", "SECRET_EXPORT"))
    def test_label_blocks_confidential_external(self):
        w, s = self.rt(); self.assertEqual(s.op(w, sd("docC", "evil.test")), ("DENIED", "LABEL")); self.assertEqual(s.op(w, sd("docC", "intra.test"))[0], "OK"); self.assertEqual(s.op(w, sd("docP", "evil.test"))[0], "OK")
    def test_budget_cap(self):
        w, s = self.rt(); self.assertEqual(s.op(w, sp(100))[0], "OK"); self.assertEqual(s.op(w, sp(1)), ("DENIED", "BUDGET"))
    def test_delete_needs_valid_approval(self):
        w, s = self.rt("B04"); self.assertEqual(s.op(w, act("delete")), ("DENIED", "APPROVAL")); self.assertEqual(s.op(w, act("delete", "ap1"))[0], "OK"); w.t[0] += 1000; w.src.state["approvals"]["ap1"]["exp"] = w.t[0] - 1; self.assertEqual(s.op(w, {**act("delete", "ap1"), "rid": "z"}), ("DENIED", "APPROVAL"))
    def test_permission(self): w, s = self.rt(); self.assertEqual(s.op(w, act("admin")), ("DENIED", "PERMISSION"))
    def test_finish_needs_obligation(self): w, s = self.rt(); self.assertEqual(s.op(w, fin()), ("DENIED", "OBLIGATION_PENDING")); s.op(w, au()); self.assertEqual(s.op(w, fin())[0], "OK")
    def test_frozen_and_dead(self):
        w, s = self.rt(); s.freeze(); self.assertEqual(s.op(w, sp(1)), ("DENIED", "FROZEN")); s.unfreeze(); self.assertEqual(s.op(w, sp(1))[0], "OK"); s.dead = True; self.assertEqual(s.op(w, sp(1)), ("DENIED", "DEAD"))
    def test_idempotent_by_request_id(self): w, s = self.rt(); s.op(w, {**sp(10), "rid": "x"}); self.assertEqual(s.op(w, {**sp(10), "rid": "x"}), ("OK", "DEDUP")); self.assertEqual(len(w.recv.effects), 1)
    def test_revocation_and_feed_down_deny(self):
        w, s = self.rt(); w.rev.revoke("rev-t1"); self.assertEqual(s.op(w, sp(1)), ("DENIED", "REVOKED")); w2, s2 = self.rt(); w2.rev.feed_up = False; self.assertEqual(s2.op(w2, sp(1)), ("DENIED", "REVOCATION_UNKNOWN"))
    def test_unsupported_control_cannot_be_enforced(self):
        w = World(SYS["continuity"], SCN["A01"]); t = w.tgt; t.eff = {k: max(t.defaults.get(k, 0), min(lvl, t.supports.get(k, 0))) for k, lvl in C.CONTROLS.items()}; self.assertEqual(t.eff.get("egress", 0), 0)


class Oracle(unittest.TestCase):
    def test_oracle_imports_only_json_and_core(self):
        t = ast.parse(src("oracle")); names = {n.module for n in ast.walk(t) if isinstance(n, ast.ImportFrom)} | {a.name for n in ast.walk(t) if isinstance(n, ast.Import) for a in n.names}
        self.assertEqual(names - {None}, {"json"})
    def test_clean_run_has_no_violation(self): self.assertEqual(run("B01", "continuity")["violations"], [])
    def test_each_violation_kind_is_producible(self):
        kinds = {k for sid in ATT + ["B08"] for r in [run(sid, "state-serialization"), run(sid, "container-snapshot")] for k in r["violation_kinds"]}
        self.assertTrue({"EGRESS_VIOLATION", "SECRET_EXPORTED", "LABEL_VIOLATION", "BUDGET_EXCEEDED", "OBLIGATION_LOST", "AUTHORITY_WIDENED", "REVOKED_AFTER", "APPROVAL_INVALID", "DUPLICATE_EFFECT", "SPLIT_BRAIN", "EXTRA_HOLDER"} <= kinds, kinds)
    def test_oracle_does_not_read_system_decisions(self):
        self.assertNotIn("status", src("oracle")); self.assertNotIn("reasons", src("oracle"))


class Attacks(unittest.TestCase):
    def test_continuity_prevents_every_attack(self):
        for s in ATT: self.assertEqual(run(s, "continuity")["violations"], [], s)
    def test_baselines_are_exploited(self):
        for n in ("state-serialization", "token-copying", "tool-name-check"): self.assertGreaterEqual(sum(1 for s in ATT if run(s, n)["violations"]), 13, n)
        self.assertGreaterEqual(sum(1 for s in ATT if run(s, "container-snapshot")["violations"]), 9); self.assertGreaterEqual(sum(1 for s in ATT if run(s, "config-sync")["violations"]), 12)
    def test_restrictive_rule_prevents_by_never_migrating_but_does_not_drain(self): self.assertEqual([s for s in ATT if run(s, "restrictive-rule")["violations"]], ["A13"]); self.assertTrue(all(run(s, "restrictive-rule")["status"] == "ROLLED_BACK" for s in ATT))
    def test_a01_not_covered_reason(self): self.assertEqual(run("A01", "continuity")["reasons"], ["NOT_COVERED:egress,secret_export"])
    def test_a06_forged_envelope(self): self.assertEqual(run("A06", "continuity")["reasons"], ["ENVELOPE_DIGEST"])
    def test_a07_partial_transfer(self): self.assertEqual(run("A07", "continuity")["reasons"], ["MISSING_SECTION"])
    def test_a08_replay_refused_at_second_target(self): w = World(SYS["continuity"], SCN["A08"]); w.execute(); self.assertEqual(w.status2["reasons"], ["REPLAY"]); self.assertEqual(w.status2["status"], "ROLLED_BACK")
    def test_a09_revoked(self): self.assertEqual(run("A09", "continuity")["reasons"], ["REVOKED"])
    def test_a10_expired_approval_not_carried(self):
        w = World(SYS["continuity"], SCN["A10"]); w.execute(); self.assertEqual(w.tgt.state["approvals"], {}); self.assertEqual(w.results[-1][-1], "APPROVAL")
    def test_a11_stale_attestation(self): self.assertEqual(run("A11", "continuity")["reasons"], ["ATTESTATION_EXPIRED"])
    def test_a12_wrong_attestation_identity(self): self.assertEqual(run("A12", "continuity")["reasons"], ["ATTESTATION_IDENTITY"])
    def test_a13_inflight_drained_once(self): r = run("A13", "continuity"); self.assertEqual(r["effects"], 1); self.assertEqual(r["violations"], [])
    def test_a14_source_frozen(self): w = World(SYS["continuity"], SCN["A14"]); w.execute(); self.assertEqual(w.results[-1][-2:], ("DENIED", "FROZEN")); self.assertTrue(w.src.frozen)
    def test_forged_envelope_succeeds_without_integrity(self): self.assertTrue(run("A06", "state-serialization")["violations"])
    def test_token_is_single_use_and_replay_succeeds_in_baselines(self): self.assertIn("EXTRA_HOLDER", run("A08", "container-snapshot")["violation_kinds"])


class Benign(unittest.TestCase):
    def test_continuity_completes_every_benign_control(self):
        for s in BEN: r = run(s, "continuity"); self.assertTrue(r["completed"] and not r["violations"], s)
    def test_equivalent_and_stronger_targets_migrate(self):
        for s in ("B01", "B02", "B03", "B04", "B05", "B06", "B08", "B09", "B10"): self.assertEqual(run(s, "continuity")["status"], "MIGRATED", s)
    def test_failed_admission_rolls_back_with_unchanged_authority(self):
        r = run("B07", "continuity"); self.assertEqual(r["status"], "ROLLED_BACK"); self.assertTrue(r["completed"])
        w = World(SYS["continuity"], SCN["B07"]); w.execute(); self.assertEqual(sorted(w.src.state["perms"]), sorted(["read", "write", "egress", "spend", "delete", "audit"])); self.assertFalse(w.src.frozen); self.assertEqual(w.tgt.state["perms"], [])
    def test_rollback_does_not_consume_the_envelope(self): w = World(SYS["continuity"], SCN["B07"]); w.execute(); self.assertEqual(w.used_nonces, set())
    def test_migration_consumes_the_envelope_once(self): w = World(SYS["continuity"], SCN["B01"]); w.execute(); self.assertEqual(w.used_nonces, {"n-1"})
    def test_budget_is_global_across_runtimes(self): w = World(SYS["continuity"], SCN["B09"]); w.execute(); self.assertEqual(w.ledger.get("api"), 80)
    def test_credential_rebound_not_copied(self):
        w = World(SYS["continuity"], SCN["B01"]); w.execute(); self.assertTrue(w.broker.valid(w.tgt.state["cred"], "tgt")); self.assertFalse(w.broker.valid(w.src.state["cred"], "src")); self.assertIsNone(w.tgt.state["raw_secret"])
    def test_obligation_carried_and_closed_on_target(self): w = World(SYS["continuity"], SCN["B10"]); w.execute(); self.assertEqual(w.tgt.state["obligations"][0]["status"], "done")
    def test_restrictive_rule_disrupts_equivalent_targets(self): self.assertGreaterEqual(sum(1 for s in BEN if run(s, "restrictive-rule")["status"] != "MIGRATED"), 6)
    def test_baselines_duplicate_inflight_call(self): self.assertIn("DUPLICATE_EFFECT", run("B08", "state-serialization")["violation_kinds"])


class Unsupported(unittest.TestCase):
    def test_unknown_provider_denied_and_flagged_unknown(self): r = run("U01", "continuity"); self.assertEqual(r["reasons"], ["NO_ATTESTATION"]); self.assertTrue(r["unknown"]); self.assertEqual(r["violations"], [])
    def test_unmediated_sink_denied_and_flagged_unknown(self): r = run("U03", "continuity"); self.assertEqual(r["reasons"], ["SINK_UNVERIFIED"]); self.assertTrue(r["unknown"])
    def test_deceived_attestor_is_a_trust_gap_not_prevented(self): r = run("U02", "continuity"); self.assertEqual(r["status"], "MIGRATED"); self.assertEqual(r["violation_kinds"], ["EGRESS_VIOLATION"]); self.assertFalse(r["unknown"])
    def test_feed_down_fails_closed(self):
        r = run("F01", "continuity"); self.assertEqual(r["violations"], []); self.assertTrue(r["unknown"]); self.assertEqual(r["reasons"], ["REVOCATION_UNKNOWN"]); self.assertFalse(run("F02", "continuity")["completed"]); self.assertTrue(run("F01", "state-serialization")["violations"])
    def test_without_admission_fail_closed_the_runtime_still_refuses(self): r = run("F01", "continuity-no-fail-closed"); self.assertEqual(r["status"], "MIGRATED"); self.assertFalse(r["unknown"]); self.assertEqual(r["violations"], [])


class EachMechanismAlone(unittest.TestCase):
    """Switch off the mechanisms that overlap a check, so it cannot hide behind them."""
    def test_signature_alone(self): self.assertEqual(reasons("A06", cont(schema=True, widening=True)), ["ENVELOPE_DIGEST"]); self.assertTrue(viol("A06", cont(signature=True, widening=True, schema=True)))
    def test_widening_alone(self): self.assertEqual(reasons("A06", cont(signature=True))[0], "PERMISSIONS_WIDENED"); self.assertTrue(viol("A06", cont(signature=True, widening=True)))
    def test_schema_alone(self): self.assertEqual(reasons("A07", cont(widening=True)), ["MISSING_SECTION"]); self.assertTrue(viol("A07", cont(schema=True, widening=True)))
    def test_labels_dropped_caught_by_widening(self): self.assertIn("LABEL_DROPPED", reasons("A07", cont(schema=True)))
    def test_nonce_alone(self): w = World(cont(ledger=True), SCN["A08"]); w.execute(); self.assertEqual(w.status2["reasons"], ["REPLAY"])
    def test_nonce_off_second_target_resumes(self): w = World(cont(nonce=True), SCN["A08"]); w.execute(); self.assertEqual(w.status2["status"], "MIGRATED")
    def test_ledger_alone(self): self.assertTrue(viol("A08", cont(nonce=True, ledger=True))); self.assertFalse(viol("A08", cont(nonce=True)))
    def test_expiry_of_envelope_alone(self):
        sc = {**SCN["A08"], "id": "T", "mid": lambda w, b: w.t.__setitem__(0, w.t[0] + 400), "post": [sp(10)], "replay": False, "approvals": {}}
        w = World(M.Continuity("t"), sc); w.execute(); self.assertIn(w.status["reasons"][0], ("ENVELOPE_EXPIRED", "EXPIRED")); self.assertEqual(w.status["status"], "ROLLED_BACK")
    def test_envelope_expiry_flag_independent_of_token_expiry(self):
        def mid(w, b): b["env"]["exp"] = b["env"]["iat"] + 1; b["token"] = w.sign(b["env"]); w.t[0] += 5
        sc = {**SCN["A08"], "id": "T", "mid": mid, "post": [sp(10)], "replay": False}
        w = World(M.Continuity("t"), sc); w.execute(); self.assertEqual(w.status["reasons"], ["ENVELOPE_EXPIRED"])
        w = World(cont(expiry=True), sc); w.execute(); self.assertEqual(w.status["status"], "MIGRATED")
    def test_revocation_alone(self): self.assertEqual(reasons("A09", cont()), ["REVOKED"]); self.assertEqual(run("A09", "continuity-no-revocation")["status"], "MIGRATED"); self.assertEqual(run("A09", "continuity-no-revocation")["violations"], [])
    def test_covers_alone(self): self.assertTrue(viol("A01", cont(covers=True))); self.assertTrue(viol("A03", cont(covers=True))); self.assertEqual(reasons("A01", cont()), ["NOT_COVERED:egress,secret_export"])
    def test_brokered_credential_makes_secret_export_harmless_even_if_admitted(self): self.assertFalse(viol("A02", cont(covers=True))); self.assertTrue(viol("A02", SYS["state-serialization"]))
    def test_att_freshness_alone(self): self.assertTrue(viol("A11", cont(att_fresh=True))); self.assertEqual(reasons("A11", cont(att_identity=True)), ["ATTESTATION_EXPIRED"])
    def test_att_identity_alone(self): self.assertTrue(viol("A12", cont(att_identity=True))); self.assertEqual(reasons("A12", cont()), ["ATTESTATION_IDENTITY"])
    def test_sink_policy_alone(self): self.assertEqual(reasons("U03", cont()), ["SINK_UNVERIFIED"]); self.assertTrue(viol("U03", cont(sink_policy=True)))
    def test_approval_expiry_alone(self): self.assertEqual(run("A10", "continuity-no-approval-expiry")["violations"], [])
    def test_approval_expiry_drops_dead_approvals_from_target_state(self): w = World(cont(approval_expiry=True), SCN["A10"]); w.execute(); self.assertIn("ap1", w.tgt.state["approvals"])
    def test_obligations_carry_alone(self): self.assertTrue(viol("A05", cont(obligations_carry=True))); self.assertTrue(viol("A07", cont(obligations_carry=True, schema=True, widening=True)))
    def test_freeze_alone(self): self.assertTrue(viol("A14", cont(freeze=True, broker_rebind=True))); self.assertFalse(viol("A14", cont(broker_rebind=True)))
    def test_rebind_alone(self): self.assertFalse(viol("A14", cont(freeze=True))); self.assertTrue(viol("A14", cont(freeze=True, broker_rebind=True)))
    def test_drain_alone(self): self.assertTrue(viol("A13", cont(drain=True))); self.assertTrue(viol("B08", cont(drain=True))); self.assertFalse(viol("A13", cont()))
    def test_rollback_alone(self): r = run("B07", "continuity-no-rollback"); self.assertEqual(r["status"], "SAFE_STOP"); self.assertFalse(r["completed"]); self.assertEqual(r["violations"], [])


class AdmissionDetails(unittest.TestCase):
    def admit(self, mutate, sid="B01", ex=None):
        ex = ex or SYS["continuity"]; w = World(ex, SCN[sid]); b = {}
        def mid(w_, bundle): mutate(w_, bundle)
        w.hooks["mid"] = mid; return w, ex.migrate(w)
    def test_attestation_token_is_not_an_envelope_token(self): w, r = self.admit(lambda w, b: b.__setitem__("token", w.attestor.attest(w.tgt))); self.assertEqual(r["reasons"], ["WRONG_TOKEN_KIND"])
    def test_envelope_token_is_not_an_attestation(self): w, r = self.admit(lambda w, b: b.__setitem__("att", b["token"])); self.assertEqual(r["reasons"], ["ATTESTATION_WRONG_ROLE"])
    def test_token_bound_to_the_task(self):
        def f(w, b): b["token"] = w.checkpointer.issue("ATTESTATION", principal="src", artifact="other-task", args_digest=C.digest(b["env"]), claim={"k": "envelope"}, ttl=300, nonce=b["env"]["resume_nonce"], now=int(w.clock()))
        self.assertEqual(self.admit(f)[1]["reasons"], ["TOKEN_ENVELOPE_MISMATCH"])
    def test_token_bound_to_the_nonce(self):
        def f(w, b): b["token"] = w.checkpointer.issue("ATTESTATION", principal="src", artifact="t1", args_digest=C.digest(b["env"]), claim={"k": "envelope"}, ttl=300, nonce="n-other", now=int(w.clock()))
        self.assertEqual(self.admit(f)[1]["reasons"], ["TOKEN_ENVELOPE_MISMATCH"])
    def test_labels_travel_and_are_enforced_on_the_target(self):
        w = World(SYS["continuity"], SCN["B01"]); w.execute(); self.assertEqual(w.tgt.state["labels"], w.grants.labels); self.assertEqual(w.tgt.op(w, sd("docC", "evil.test")), ("DENIED", "LABEL")); self.assertEqual(w.tgt.op(w, sd("docC", "intra.test"))[0], "OK")
    def test_source_frozen_before_the_checkpoint_and_after_resume(self):
        seen = []
        def f(w, b): seen.append(w.src.frozen)
        w, r = self.admit(f); self.assertEqual(seen, [True]); self.assertTrue(w.src.frozen); self.assertEqual(r["status"], "MIGRATED")
    def test_unfrozen_source_after_rollback_only(self): w = World(SYS["continuity"], SCN["B07"]); w.execute(); self.assertFalse(w.src.frozen); w2 = World(SYS["continuity"], SCN["B01"]); w2.execute(); self.assertTrue(w2.src.frozen)
    def test_baseline_target_runs_with_its_own_defaults(self):
        w = World(SYS["state-serialization"], SCN["A01"]); w.execute(); self.assertEqual(w.tgt.eff, {}); w2 = World(SYS["state-serialization"], SCN["B01"]); w2.execute(); self.assertEqual(w2.tgt.eff, w2.tgt.defaults)
    def test_baseline_applies_exactly_the_target_defaults(self):
        def f(w, b): w.tgt.defaults = {"egress": 2, "label": 1}
        w, r = self.admit(f, ex=SYS["state-serialization"]); self.assertEqual(w.tgt.eff, {"egress": 2, "label": 1})
    def test_tool_name_check_denies_a_target_without_the_tools(self):
        def f(w, b): w.tgt.tools = ("egress",)
        w, r = self.admit(f, ex=SYS["tool-name-check"]); self.assertEqual((r["status"], r["reasons"]), ("ROLLED_BACK", ["POLICY_COMPAT"])); self.assertEqual(self.admit(lambda w, b: None, ex=SYS["tool-name-check"])[1]["status"], "MIGRATED")
    def test_inflight_call_is_applied_by_the_source_and_deduplicated_at_the_target(self):
        w = World(SYS["continuity"], SCN["A13"]); w.execute(); self.assertEqual([(e["rt"], e["rid"]) for e in w.recv.effects], [("src", "op7")]); self.assertEqual(w.results[-1][-1], "DEDUP")
    def test_without_drain_the_call_lands_twice(self): w = World(cont(drain=True), SCN["A13"]); w.execute(); self.assertEqual(sorted(e["rt"] for e in w.recv.effects), ["src", "tgt"])
    def test_lowered_label_in_envelope_is_rejected(self): self.assertIn("LABEL_LOWERED", reasons_of(lambda w, b: b["env"]["labels"].__setitem__("docC", "PUBLIC")))


def reasons_of(mutate):
    ex = cont(signature=True, schema=True); w = World(ex, SCN["B01"]); w.hooks["mid"] = mutate; return ex.migrate(w)["reasons"]


class Structure(unittest.TestCase):
    def test_target_side_code_never_signs(self):
        t = ast.parse(src("migrate"))
        for cls in (n for n in ast.walk(t) if isinstance(n, ast.ClassDef)):
            for f in (n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in ("admit", "resume", "fail")):
                self.assertNotIn("checkpointer", ast.unparse(f), f.name); self.assertNotIn("att_iss", ast.unparse(f), f.name); self.assertNotIn("sign(", ast.unparse(f), f.name)
    def test_only_synthetic_hosts_and_canary(self):
        for m in ("core", "scenarios", "world", "runtime", "services", "migrate"): self.assertNotRegex(src(m), r"https?://|socket|urllib|requests")
        self.assertEqual(C.CANARY, "TEST_CANARY_NOT_SECRET")
    def test_systems_do_not_import_oracle(self): self.assertNotIn("oracle", src("migrate")); self.assertNotIn("oracle", src("runtime")); self.assertNotIn("oracle", src("world"))
    def test_every_runtime_kind_is_used_by_a_scenario(self):
        used = {x[k] for x in SC.SCENARIOS for k in ('target',)} | {x.get('target2') for x in SC.SCENARIOS} | {x.get('source') for x in SC.SCENARIOS} | {'sandbox-a', 'sandbox-b'}
        self.assertEqual(set(R.LIB) - used, set())
    def test_every_flag_has_an_ablation(self):
        for f in M.CCfg.__dataclass_fields__: self.assertIn("continuity-no-" + f.replace("_", "-"), SYS)


class Experiment(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.R = X.run()
    def test_counts(self): self.assertEqual((len(ATT), len(BEN)), (14, 10)); self.assertEqual(self.R["summary"]["continuity"]["attacks_with_a_prohibited_effect"]["k"], 0)
    def test_differential(self):
        S = self.R["summary"]; self.assertGreaterEqual(S["state-serialization"]["attacks_with_a_prohibited_effect"]["k"], 13); self.assertEqual(S["restrictive-rule"]["benign_migrated"]["k"], 3); self.assertEqual(S["continuity"]["benign_migrated"]["k"], 9)
    def test_unknown_reported_separately(self): s = self.R["summary"]["continuity"]; self.assertEqual(s["unsupported_flagged_unknown"], 2); self.assertEqual(s["unsupported_unflagged_with_effect"], ["U02"])
    def test_coverage_metric(self): c = self.R["summary"]["continuity"]["policy_continuity_coverage"]; self.assertEqual(c["k"], c["n"]); self.assertLess(self.R["summary"]["state-serialization"]["policy_continuity_coverage"]["k"], self.R["summary"]["state-serialization"]["policy_continuity_coverage"]["n"])
    def test_counterexamples_recorded(self): self.assertTrue(self.R["counterexamples"]); self.assertIn("U02", {c["scenario"] for c in self.R["counterexamples"] if c["system"] == "continuity"})
    def test_redundant_ablations_disclosed(self): self.assertIn("continuity-no-signature", self.R["redundant"]); self.assertNotIn("continuity-no-covers", self.R["redundant"]); self.assertNotIn("continuity-no-att-fresh", self.R["redundant"])
    def test_deterministic(self): self.assertEqual(json.dumps(X.run(), sort_keys=True, default=str), json.dumps(self.R, sort_keys=True, default=str))


class Recorded(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.D = os.path.join(ROOT, "results/v2/p53-continuity")
        if not os.path.exists(os.path.join(cls.D, "result.json")): raise unittest.SkipTest("no recorded run")
        cls.R = json.load(open(os.path.join(cls.D, "result.json")))
    def test_matches_fresh_run(self): self.assertEqual(json.loads(json.dumps(X.run(), sort_keys=True, default=str)), self.R)
    def test_headline(self): self.assertEqual(self.R["summary"]["continuity"]["attacks_with_a_prohibited_effect"]["k"], 0)
    def test_trust_gaps_file(self): T = json.load(open(os.path.join(self.D, "trust_gaps.json"))); self.assertTrue(T["supported_targets"]); self.assertTrue(T["trust_gaps"]); self.assertTrue(T["properties"])


class Gates(unittest.TestCase):
    def test_docs_exist_and_state_limits(self):
        L = open(os.path.join(ROOT, "docs/evidence/p53/ASSUMPTIONS_AND_LIMITS.md")).read()
        for w in ("CANDIDATE", "attestation", "theorem", "same author", "not a proof", "trust gap", "UNKNOWN"): self.assertIn(w, L)
        self.assertTrue(os.path.exists(os.path.join(ROOT, "docs/evidence/p53/RESULTS.md")))
    def test_nothing_claims_verified(self): self.assertNotRegex(open(os.path.join(ROOT, "docs/evidence/p53/RESULTS.md")).read(), r"\bVERIFIED\b")
