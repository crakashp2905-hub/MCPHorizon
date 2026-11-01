import ast, json, os, tempfile, threading, unittest
from horizon.hpolicy.authority import HorizonPolicy, EvidenceError
from horizon.temporal import core as C, gate as G, scenarios as SC, experiment as X, oracle as O
from horizon.temporal.store import Store
from horizon.temporal.world import World, explore, interleavings, call, wait
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SYS = {e.name: e for e in X.systems()}; SCN = {s["id"]: s for s in SC.SCENARIOS}
def ex(sid, name): return explore(SCN[sid], SYS[name])
def src(m): return open(os.path.join(ROOT, "horizon/temporal", m + ".py")).read()
def store():
    t = [1000.0]; s = Store(lambda: t[0]); s.put_object("d", "PUBLIC", "hello"); return s, t
ATT = [s["id"] for s in SC.SCENARIOS if s["kind"] == "attack"]; BEN = [s["id"] for s in SC.SCENARIOS if s["kind"] == "benign"]


class Core(unittest.TestCase):
    def test_digest_canonical(self): self.assertEqual(C.digest({"a": 1, "b": 2}), C.digest({"b": 2, "a": 1})); self.assertNotEqual(C.digest([1]), C.digest([2]))
    def test_slice_digest_covers_only_deciding_rules(self):
        r, v = dict(C.RULES0), {k: 1 for k in C.RULES0}; a = C.slice_digest(r, v, "PUBLIC", "partner.test")
        r2 = dict(r); r2["import.PUBLIC"] = {"allow": False}; self.assertEqual(a, C.slice_digest(r2, v, "PUBLIC", "partner.test"))
        r3 = dict(r); r3["export.PUBLIC"] = {"allow": False}; self.assertNotEqual(a, C.slice_digest(r3, v, "PUBLIC", "partner.test"))
        self.assertNotEqual(a, C.slice_digest(r, {**v, "dest.partner.test": 2}, "PUBLIC", "partner.test"))
        self.assertNotEqual(a, C.slice_digest(r, v, "INTERNAL", "partner.test"))
    def test_permits(self):
        R = C.RULES0; ok, _ = C.permits(R, ["export"], "PUBLIC", "partner.test", ["10.0.0.5"]); self.assertTrue(ok)
        self.assertFalse(C.permits(R, [], "PUBLIC", "partner.test", ["10.0.0.5"])[0]); self.assertFalse(C.permits(R, ["export"], "PUBLIC", "partner.test", ["10.6.6.6"])[0])
        self.assertFalse(C.permits(R, ["export"], "RESTRICTED", "partner.test", ["10.0.0.5"])[0]); self.assertFalse(C.permits(R, ["export"], "INTERNAL", "partner.test", ["10.0.0.5"])[0])
        self.assertFalse(C.permits(R, ["export"], "PUBLIC", "evil.test", ["10.6.6.6"])[0])
    def test_vector_fields_bind(self):
        base = C.vector(("d", 1, "PUBLIC"), ("a", 1, ["export"]), "s", "h", ["i"], 3, "c"); self.assertEqual(set(base), {"o", "g", "s", "d", "r", "c"})
        d = C.digest(C.envelope("export", "a", "d", "h", base))
        for k, v in (("c", "x"), ("s", "y"), ("r", 4)): self.assertNotEqual(d, C.digest(C.envelope("export", "a", "d", "h", {**base, k: v})), k)
    def test_envelope_binds_operation_actor_object_host(self):
        b = C.envelope("export", "a", "d", "h", {}); d = C.digest(b)
        for args in (("import", "a", "d", "h"), ("export", "b", "d", "h"), ("export", "a", "e", "h"), ("export", "a", "d", "g")): self.assertNotEqual(d, C.digest(C.envelope(*args, {})))


class StoreTests(unittest.TestCase):
    def test_cas_rejects_stale_and_lww_loses_the_update(self):
        s, _ = store(); self.assertTrue(s.cas_update("d", 1, content="a")); self.assertFalse(s.cas_update("d", 1, content="b")); self.assertEqual(s.obj("d")["content"], "a")
        s.lww_update("d", 1, content="c"); self.assertEqual(s.obj("d")["content"], "c"); self.assertEqual([x["reasons"] for x in O.judge(s) if x["reasons"] == ["LOST_UPDATE"]], [["LOST_UPDATE"]])
    def test_versions_increment_on_every_security_relevant_change(self):
        s, _ = store(); v = s.obj("d")["version"]; s.set_class("d", "INTERNAL"); self.assertEqual(s.obj("d")["version"], v + 1); s.replace_content("d", "x"); self.assertEqual(s.obj("d")["version"], v + 2)
    def test_threaded_cas_exactly_one_writer_wins(self):
        p = os.path.join(tempfile.mkdtemp(), "t.db"); t = [1.0]; a = Store(lambda: t[0], p); a.put_object("d", "PUBLIC", "x"); out = []; bar = threading.Barrier(8)
        def w(i):
            s = Store(lambda: t[0], p); bar.wait(); out.append(s.cas_update("d", 1, content="w%d" % i))
        th = [threading.Thread(target=w, args=(i,)) for i in range(8)]; [x.start() for x in th]; [x.join() for x in th]
        self.assertEqual(sum(out), 1); self.assertEqual(a.obj("d")["version"], 2); self.assertFalse(any(x["reasons"] == ["LOST_UPDATE"] for x in O.judge(a)))
    def test_threaded_lww_loses_updates(self):
        p = os.path.join(tempfile.mkdtemp(), "t.db"); t = [1.0]; a = Store(lambda: t[0], p); a.put_object("d", "PUBLIC", "x"); bar = threading.Barrier(4)
        def w(i):
            s = Store(lambda: t[0], p); bar.wait(); s.lww_update("d", 1, content="w%d" % i)
        th = [threading.Thread(target=w, args=(i,)) for i in range(4)]; [x.start() for x in th]; [x.join() for x in th]
        self.assertEqual(sum(1 for x in O.judge(a) if x["reasons"] == ["LOST_UPDATE"]), 3)
    def test_transaction_rolls_back_on_error(self):
        s, _ = store()
        try:
            with s.tx(): s.set_class("d", "INTERNAL"); raise RuntimeError("x")
        except RuntimeError: pass
        self.assertEqual(s.obj("d")["cls"], "PUBLIC")


class Oracle(unittest.TestCase):
    def test_oracle_is_independent_of_the_gateway(self):
        t = ast.parse(src("oracle")); names = {n.module for n in ast.walk(t) if isinstance(n, ast.ImportFrom)} | {a.name for n in ast.walk(t) if isinstance(n, ast.Import) for a in n.names}
        self.assertEqual(names - {None}, {"json"}); self.assertNotIn("gate", src("oracle").replace("gateway", "").split("import")[1] if "import" in src("oracle") else "")
    def test_clean_effect_is_legitimate(self):
        w = World(SYS["temporal"], SCN["B01"]); from horizon.temporal.world import run_order, expand
        ws = explore(SCN["B01"], SYS["temporal"]); self.assertEqual(ws[0]["violations"], [])
    def test_no_effects_no_violations(self): s, _ = store(); self.assertEqual(O.judge(s), [])
    def test_harm_and_stale_reasons_are_disjoint(self): self.assertFalse(set(O.HARM) & {"EXPIRED_APPROVAL", "REPLAYED_APPROVAL", "REVOKED_APPROVAL", "OBJECT_CHANGED", "CONTENT_CHANGED", "GRANT_CHANGED", "POLICY_CHANGED"})


class Scheduler(unittest.TestCase):
    def test_interleavings_enumerate_all_orders(self):
        a = {"x": [call("a1", None), call("a2", None)], "y": [call("b1", None), call("b2", None)]}; self.assertEqual(len(interleavings(a, [])), 6)
        self.assertEqual(len(interleavings(a, [("a2", "b1")])), 1)
    def test_orders_are_deterministic(self): self.assertEqual(ex("A10", "temporal"), ex("A10", "temporal"))
    def test_atomic_gateway_has_no_gap_non_atomic_has(self):
        full = SCN["A01"]; w = World(SYS["temporal"], full); self.assertEqual(SYS["temporal"].phases(w), 1); self.assertEqual(SYS["temporal-no-atomic"].phases(w), 2)
        self.assertGreater(len(ex("A01", "temporal-no-atomic")), len(ex("A01", "temporal")))
    def test_non_atomic_sink_forces_two_steps(self): w = World(SYS["temporal"], SCN["U01"]); self.assertEqual(SYS["temporal"].phases(w), 2)


class Attacks(unittest.TestCase):
    def test_full_gateway_prevents_every_attack_in_every_interleaving(self):
        for s in ATT: self.assertFalse(any(r["violations"] for r in ex(s, "temporal")), s)
    def test_authorize_once_baseline_is_exploited(self):
        v = {s for s in ATT if any(r["violations"] for r in ex(s, "one-time-check"))}; self.assertTrue({"A01", "A02", "A03", "A04", "A05", "A07", "A08", "A12"} <= v, v)
    def test_attack_needs_the_right_interleaving(self):
        for s in ("A01", "A02", "A03", "A04"): R = ex(s, "one-time-check"); self.assertTrue(any(r["violations"] for r in R) and not all(r["violations"] for r in R), s)
    def test_object_change_after_approval(self):
        for s in ("A01", "A02"): self.assertTrue(any("OBJECT_VERSION" in r["denials"] for r in ex(s, "temporal")), s)
    def test_class_change_leads_to_harm_in_baseline(self): self.assertTrue(any(r["harm"] for r in ex("A01", "one-time-check")))
    def test_content_canary_is_caught(self): self.assertTrue(any(any("CANARY_EXPORTED" in v["reasons"] for v in r["violations"]) for r in ex("A02", "one-time-check")))
    def test_expiry_enforced_on_authoritative_clock(self):
        self.assertTrue(any(r["violations"] for r in ex("A11", "jwt-expiry"))); self.assertFalse(any(r["violations"] for r in ex("A11", "temporal"))); self.assertTrue(any(r["violations"] for r in ex("A11", "temporal-no-authoritative-clock")))
        self.assertIn("EXPIRED", {d for r in ex("A05", "temporal") for d in r["denials"]})
    def test_replay_is_denied(self): self.assertIn("REPLAY", {d for r in ex("A06", "temporal") for d in r["denials"]}); self.assertTrue(any(r["violations"] for r in ex("A06", "one-time-check")))
    def test_dns_rebind_and_redirect(self):
        self.assertTrue(any(r["harm"] for r in ex("A07", "one-time-check"))); self.assertTrue(any(r["harm"] for r in ex("A08", "one-time-check")))
        self.assertTrue(any(r["violations"] for r in ex("A07", "temporal-no-destination"))); self.assertTrue(any(r["violations"] for r in ex("A08", "temporal-no-redirect")))
        self.assertIn("REDIRECT_DENIED", {d for r in ex("A08", "temporal") for d in r["denials"]})
    def test_confused_deputy_denied(self): self.assertTrue(any(r["violations"] for r in ex("A09", "one-time-check"))); self.assertFalse(any(r["violations"] for r in ex("A09", "temporal")))
    def test_other_object_token_denied(self): self.assertIn("OBJECT_MISMATCH", {d for r in ex("A13", "temporal") for d in r["denials"]}); self.assertTrue(any(r["violations"] for r in ex("A13", "op-token-no-object")))
    def test_cas_prevents_lost_update_lww_does_not(self):
        self.assertFalse(any(r["violations"] for r in ex("A10", "temporal"))); self.assertTrue(all(r["violations"] for r in ex("A10", "last-write-wins")))
    def test_revocation_cancels_the_approval(self): self.assertIn("APPROVAL_REVOKED", {d for r in ex("A12", "temporal") for d in r["denials"]}); self.assertTrue(any(r["violations"] for r in ex("A12", "temporal-no-revocation")))
    def test_grant_and_policy_change(self):
        self.assertTrue(any(r["violations"] for r in ex("A03", "jwt-expiry"))); self.assertTrue(any(r["violations"] for r in ex("A04", "jwt-expiry")))


class Benign(unittest.TestCase):
    def test_full_gateway_completes_every_benign_in_every_interleaving(self):
        for s in BEN: self.assertTrue(all(r["completed"] and not r["violations"] for r in ex(s, "temporal")), s)
    def test_justified_reapproval_only(self):
        for s in BEN:
            n = max(r["reapprovals"] for r in ex(s, "temporal")); self.assertEqual(n > 0, bool(SCN[s].get("justified_reapproval")), s)
        self.assertEqual(max(r["reapprovals"] for r in ex("B01", "temporal")), 0); self.assertEqual(max(r["reapprovals"] for r in ex("B03", "temporal")), 0)
    def test_unrelated_changes_do_not_block(self): self.assertTrue(all(r["completed"] for r in ex("B03", "temporal")))
    def test_retry_is_idempotent(self):
        R = ex("B06", "temporal"); self.assertTrue(all(r["completed"] and r["effects"] == 1 for r in R)); self.assertTrue(any(r["violations"] for r in ex("B06", "one-time-check")))
    def test_just_before_and_after_expiry(self): self.assertTrue(all(r["completed"] for r in ex("B09", "temporal"))); self.assertTrue(all(r["completed"] for r in ex("B10", "temporal")))
    def test_restrictive_rule_blocks_benign_work(self): self.assertGreaterEqual(sum(1 for s in BEN if not all(r["completed"] for r in ex(s, "restrictive-rule"))), 5)
    def test_stale_only_on_baselines(self): self.assertTrue(any(r["violations"] and not r["harm"] for r in ex("B02", "op-token-no-object")))


class Unsupported(unittest.TestCase):
    def test_non_conditional_sink_is_unknown_not_verified(self):
        R = ex("U01", "temporal"); bad = [r for r in R if r["violations"]]; self.assertTrue(bad); self.assertTrue(all(r["unknown"] for r in bad))
    def test_deferred_effect_is_unknown(self): R = ex("U02", "temporal"); bad = [r for r in R if r["violations"]]; self.assertTrue(bad); self.assertTrue(all(r["unknown"] for r in bad))
    def test_baselines_do_not_flag_unknown_where_they_cannot_know(self): self.assertTrue(any(r["violations"] for r in ex("U01", "one-time-check")))
    def test_no_unknown_when_supported(self): self.assertFalse(any(r["unknown"] for s in ATT + BEN for r in ex(s, "temporal")))
    def test_feed_down_fails_closed(self):
        self.assertFalse(any(r["violations"] for r in ex("F01", "temporal"))); self.assertTrue(all(r["unknown"] for r in ex("F01", "temporal"))); self.assertFalse(any(r["completed"] for r in ex("F02", "temporal")))
        self.assertTrue(any(r["violations"] for r in ex("F01", "temporal-no-fail-closed")))


class Structure(unittest.TestCase):
    def test_no_module_signs(self):
        for m in ("gate", "world", "scenarios", "experiment", "oracle", "store", "net", "core"): self.assertNotIn(".issue(", src(m), m); self.assertNotIn("Issuer", src(m).replace("holds the approver Issuer", ""), m)
        self.assertIn(".issue(", src("approver"))
    def test_only_synthetic_hosts_and_canary(self):
        for m in ("core", "scenarios", "world"): self.assertNotRegex(src(m), r"https?://|socket|urllib|requests")
        self.assertEqual(C.CANARY, "TEST_CANARY_NOT_SECRET")
    def test_gateway_does_not_import_oracle(self): self.assertNotIn("oracle", src("gate")); self.assertNotIn("oracle", src("approver"))
    def test_ablation_flags_all_exist(self):
        for f in G.TCfg.__dataclass_fields__: self.assertIn("temporal-no-" + f.replace("_", "-"), SYS) if f != "cas_writes" else self.assertIn("last-write-wins", SYS)


class Experiment(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.R = X.run()
    def test_systems_and_scenarios(self): self.assertEqual(len(self.R["scenarios"]), 29 - 0 if False else len(SC.SCENARIOS)); self.assertEqual(self.R["summary"]["temporal"]["attacks_with_a_violating_interleaving"]["k"], 0)
    def test_attack_and_benign_are_paired(self): self.assertEqual(len(ATT), 13); self.assertEqual(len(BEN), 10)
    def test_baseline_differential(self): S = self.R["summary"]; self.assertGreaterEqual(S["one-time-check"]["attacks_with_a_violating_interleaving"]["k"], 10); self.assertGreater(S["op-token-no-object"]["attacks_with_a_violating_interleaving"]["k"], 5)
    def test_unsupported_reported_separately(self): s = self.R["summary"]["temporal"]; self.assertEqual(s["unsupported_paths_violated"]["k"], 2); self.assertEqual(s["unsupported_paths_violated_and_flagged_unknown"], 2)
    def test_counterexamples_recorded(self): self.assertTrue(self.R["counterexamples"]); self.assertTrue(all(c["order"] and c["violations"] for c in self.R["counterexamples"]))
    def test_ablations_report_redundancy(self): self.assertIn("temporal-no-actor", self.R["redundant"]); self.assertNotIn("temporal-no-atomic", self.R["redundant"]); self.assertNotIn("temporal-no-revocation", self.R["redundant"])
    def test_atomicity_ablation_creates_gaps(self): s = self.R["summary"]["temporal-no-atomic"]; self.assertGreater(s["attacks_with_a_violating_interleaving"]["k"], 0)


class Recorded(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.D = os.path.join(ROOT, "results/v2/p52-temporal")
        if not os.path.exists(os.path.join(cls.D, "result.json")): raise unittest.SkipTest("no recorded run")
        cls.R = json.load(open(os.path.join(cls.D, "result.json")))
    def test_matches_fresh_run(self): self.assertEqual(json.loads(json.dumps(X.run(), sort_keys=True, default=str)), self.R)
    def test_headline(self): self.assertEqual(self.R["summary"]["temporal"]["attacks_with_a_violating_interleaving"]["k"], 0)
    def test_invariants_file(self):
        I = json.load(open(os.path.join(self.D, "invariants.json"))); self.assertTrue(I["invariants"]); self.assertTrue(I["counterexamples"])


def gw(**off): return G.Gateway("t", G.TCfg(**{k: False for k in off}))
def harm(sid, g): return any(r["harm"] for r in explore(SCN[sid], g))
def viol(sid, g): return any(r["violations"] for r in explore(SCN[sid], g))
def denials(sid, g): return {d for r in explore(SCN[sid], g) for d in r["denials"]}


class EachMechanismAlone(unittest.TestCase):
    """Each mechanism is exercised with the mechanisms that overlap it switched off, so a regression in it cannot hide behind them."""
    def test_content_digest_alone(self): self.assertFalse(viol("A02", gw(object_version=True))); self.assertTrue(viol("A02", gw(object_version=True, content=True)))
    def test_policy_slice_alone(self): self.assertFalse(viol("A04", gw(policy_recheck=True))); self.assertTrue(viol("A04", gw(policy_recheck=True, policy_slice=True)))
    def test_policy_recheck_alone(self): self.assertFalse(viol("A04", gw(policy_slice=True, grant=True))); self.assertTrue(viol("A04", gw(policy_slice=True, policy_recheck=True)))
    def test_policy_recheck_catches_class_change_alone(self): g = dict(object_version=True, object_class=True, policy_slice=True, content=True); self.assertFalse(harm("A01", gw(**g))); self.assertTrue(harm("A01", gw(policy_recheck=True, **g)))
    def test_grant_alone(self): self.assertFalse(viol("A03", gw(policy_recheck=True))); self.assertTrue(viol("A03", gw(policy_recheck=True, grant=True)))
    def test_actor_alone(self): self.assertFalse(viol("A09", gw(grant=True, policy_recheck=True))); self.assertTrue(viol("A09", gw(grant=True, policy_recheck=True, actor=True)))
    def test_object_id_alone(self): self.assertIn("OBJECT_MISMATCH", denials("A13", gw())); self.assertNotIn("OBJECT_MISMATCH", denials("A13", gw(object_id=True)))
    def test_destination_check_denies_rebind(self): self.assertIn("DESTINATION_CHANGED", denials("A07", gw())); self.assertNotIn("DESTINATION_CHANGED", denials("A07", gw(destination=True)))
    def test_pin_protects_between_check_and_connect(self):
        sc = {**SCN["A07"], "actors": {**SCN["A07"]["actors"], "env": [call("rebind", lambda w: w.net.rebind("partner.test", ["10.6.6.6"]))]}}
        full = gw(atomic=True); self.assertFalse(any(r["harm"] for r in explore(sc, full)))
    def test_host_mismatch_denied(self):
        w = World(SYS["temporal"], SCN["B01"]); tok = w.approver.request("agentA", "doc1", "partner.test"); r = SYS["temporal"].begin(w, tok, "agentA", {"op": "export", "obj": "doc1", "host": "intra.test", "queued": False}, "x")
        self.assertEqual(r["final"]["reason"], "HOST_MISMATCH")
    def test_token_must_match_its_envelope(self):
        w = World(SYS["temporal"], SCN["B01"]); v = w.store.view("agentA", "doc1", "partner.test", ["10.0.0.5"]); c = dict(v["vec"])
        bad = w.iss.issue("APPROVAL", principal="agentA", artifact="doc1", args_digest="sha256:forged", claim=c, nonce="forged-1", now=int(w.clock()), ttl=60)
        w.store.db.execute("INSERT INTO approvals(id,actor,claim,issued_seq,iat,exp) VALUES(?,?,?,?,?,?)", ("forged-1", "agentA", json.dumps({**c, "ips": ["10.0.0.5"]}), 0, w.clock(), w.clock() + 60))
        r = SYS["temporal"].begin(w, bad, "agentA", {"op": "export", "obj": "doc1", "host": "partner.test", "queued": False}, "x"); self.assertEqual(r["final"]["reason"], "BINDING_MISMATCH")
    def test_retry_returns_the_first_result_not_a_denial(self):
        w = World(SYS["temporal"], SCN["B06"]); from horizon.temporal.world import run_order, expand
        progs = {n: expand(p, SYS["temporal"], w) for n, p in SCN["B06"]["actors"].items()}; [st["fn"](w) for st in progs["agent"]]
        self.assertEqual([r["status"] for r in w.results], ["OK", "OK"]); self.assertTrue(w.results[1].get("replayed")); self.assertEqual(len(w.store.effects()), 1)
    def test_without_idempotency_the_retry_is_refused(self):
        w = World(gw(idempotent=True), SCN["B06"]); from horizon.temporal.world import expand
        progs = {n: expand(p, w.ex, w) for n, p in SCN["B06"]["actors"].items()}; [st["fn"](w) for st in progs["agent"]]; self.assertEqual([r["status"] for r in w.results], ["OK", "DENIED"])


class ApproverAndOracle(unittest.TestCase):
    def test_approver_refuses_what_policy_forbids(self):
        w = World(SYS["temporal"], SCN["B01"]); w.store.set_class("doc1", "RESTRICTED"); self.assertIsNone(w.approver.request("agentA", "doc1", "partner.test"))
        w2 = World(SYS["temporal"], SCN["B01"]); w2.store.revoke_grant("agentA", "export"); self.assertIsNone(w2.approver.request("agentA", "doc1", "partner.test")); w3 = World(SYS["temporal"], SCN["B01"]); self.assertIsNone(w3.approver.request("agentA", "doc2", "partner.test"))
    def test_approval_lifetime_is_short_and_ledger_matches(self):
        w = World(SYS["temporal"], SCN["B01"]); tok = w.approver.request("agentA", "doc1", "partner.test"); p = w.verifier.verify(tok); self.assertEqual(p["exp"] - p["iat"], 60)
        a = w.store.approval(p["nonce"]); self.assertEqual(a["exp"] - a["iat"], 60)
    def test_oracle_flags_content_change_without_canary(self):
        sc = {**SCN["A02"], "actors": {**SCN["A02"]["actors"], "env": [call("swap", lambda w: w.store.replace_content("doc1", "different but harmless text"))]}}
        self.assertTrue(any("CONTENT_CHANGED" in v["reasons"] and not v["harm"] for r in explore(sc, SYS["one-time-check"]) for v in r["violations"]))
    def test_reapprovals_are_counted(self):
        self.assertGreaterEqual(max(r["reapprovals"] for r in ex("B02", "temporal")), 1); self.assertGreaterEqual(max(r["reapprovals"] for r in ex("B10", "temporal")), 1)
    def test_stale_only_effects_are_separated_from_harm(self):
        R = X.run()["rows"]; r = next(x for x in R if x["scenario"] == "B02" and x["system"] == "op-token-no-object"); self.assertGreater(r["stale_only_orders"], 0); self.assertEqual(r["harm_orders"], 0)
    def test_pin_survives_rebind_between_check_and_effect(self):
        sc = {"id": "T", "kind": "attack", "desc": "", "actors": {"agent": [__import__("horizon.temporal.world", fromlist=["x"]).approve("agentA", "doc1", "partner.test"), __import__("horizon.temporal.world", fromlist=["x"]).dispatch("agentA", "doc1", "partner.test", "r1")], "env": [call("rebind", lambda w: w.net.rebind("partner.test", ["10.6.6.6"]))]},
              "expect": [], "before": [("approve", "rebind")]}
        g = G.Gateway("t", G.TCfg(atomic=False)); self.assertFalse(any(r["harm"] for r in explore(sc, g))); self.assertTrue(any(r["harm"] for r in explore(sc, SYS["one-time-check"])))


class Gates(unittest.TestCase):
    def test_docs_exist_and_state_limits(self):
        L = open(os.path.join(ROOT, "docs/evidence/p52/ASSUMPTIONS_AND_LIMITS.md")).read()
        for w in ("CANDIDATE", "atomic", "external", "deferred", "same author", "theorem", "not a proof"): self.assertIn(w, L)
        self.assertTrue(os.path.exists(os.path.join(ROOT, "docs/evidence/p52/RESULTS.md")))
    def test_nothing_claims_verified(self): self.assertNotRegex(open(os.path.join(ROOT, "docs/evidence/p52/RESULTS.md")).read(), r"\bVERIFIED\b")
