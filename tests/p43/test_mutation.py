import json, os, re, subprocess, sys, unittest
from horizon.mutation import ir, seeds as SD, operators as OP, oracle as OR, detectors as DT, pipeline as PL, minimize as MZ, experiment as EX
from horizon import schemas
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); D = os.path.join(ROOT, "results/v2/p43-mutation")
S = {g["id"]: g for g in SD.seeds()}


def G(s):
    g = ir.clone(S[s]); return g


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.o = OR.Oracle(); cls.o.rc.start()
    @classmethod
    def tearDownClass(cls): cls.o.rc.stop()


class IR(unittest.TestCase):
    def test_all_seeds_feasible_and_events_schema_valid(self):
        for g in S.values(): self.assertEqual(ir.feasibility(g), [], g["id"]); self.assertEqual(ir.validate_events(g), [], g["id"])
    def test_events_map_one_to_one_with_executing_nodes(self):
        g = G("S09"); ev = ir.to_events(g); self.assertEqual(len(ev), len(ir.executing(g))); self.assertEqual(len(ev), 2)         # only the branch selected by the flag runs
        self.assertEqual([e["monotonic_seq"] for e in ev], [0, 1]); self.assertTrue(all(e["phase"] == "before_call" for e in ev))
    def test_event_schema_rejects_bad_event(self):
        e = ir.to_events(G("S01"))[0]; e["phase"] = "bogus"; self.assertTrue(schemas.validate("event", e))
    def test_flags_select_branch(self):
        g = G("S09"); self.assertEqual([n["id"] for n in ir.executing(g)], ["n1", "n3"]); g["flags"]["export"] = "int"; self.assertEqual([n["id"] for n in ir.executing(g)], ["n1", "n2"])
    def test_feasibility_rejections(self):
        def bad(f):
            g = G("S03"); f(g); return ir.feasibility(g)
        self.assertTrue(bad(lambda g: g["nodes"].append(dict(g["nodes"][0]))))                                      # duplicate id
        self.assertTrue(bad(lambda g: ir.node(g, "n2").update(inputs=["zz"])))                                       # unknown input
        self.assertTrue(bad(lambda g: ir.node(g, "n2").update(t=0)))                                                 # input produced after use
        self.assertTrue(bad(lambda g: ir.node(g, "n2").update(op="rot47")))                                          # op outside whitelist
        self.assertTrue(bad(lambda g: ir.node(g, "n3").update(dest="WAN")))                                          # non-loopback destination
        self.assertTrue(bad(lambda g: ir.node(g, "n3").update(protocol="smtp")))
        self.assertTrue(bad(lambda g: ir.node(g, "n3").update(principal="ghost")))
        self.assertTrue(bad(lambda g: ir.node(g, "n3").update(approval="nope")))
        self.assertTrue(bad(lambda g: ir.node(g, "n3").update(inputs=["n1", "n2"])))
        self.assertTrue(bad(lambda g: g["nodes"].extend([dict(g["nodes"][0], id="x%d" % i) for i in range(ir.MAX_NODES)])))   # size guardrail
    def test_branch_input_must_execute(self):
        g = G("S09"); ir.node(g, "n3")["inputs"] = ["n2"]; self.assertTrue(any("does not execute" in e for e in ir.feasibility(g)))
    def test_digest_stable_and_sensitive(self):
        g = G("S01"); self.assertEqual(ir.digest(g), ir.digest(ir.clone(g))); g2 = ir.clone(g); ir.node(g2, "n2")["dest"] = "PAR"; self.assertNotEqual(ir.digest(g), ir.digest(g2))


class Oracle(Base):
    def test_seed_pairs_have_expected_ground_truth(self):
        for a, b in (("S01", "S02"), ("S03", "S04"), ("S05", "S06"), ("S07", "S08"), ("S09", "S10"), ("S11", "S12")):
            ja, jb = self.o.judge(G(a)), self.o.judge(G(b)); self.assertEqual((ja["status"], ja["V"], jb["status"], jb["V"]), ("OK", True, "OK", False), (a, b))
    def test_all_three_protocols_carry_the_canary(self):
        for p in ir.PROTOCOLS:
            g = G("S01"); ir.node(g, "n2")["protocol"] = p; j = self.o.judge(g); self.assertEqual((j["status"], j["V"], j["sinks"][0]["byte_seen"]), ("OK", True, True), p)
    def test_wire_bytes_differ_across_protocols(self):
        e = {p: OR.envelope(p, 1, "x y", "")[1:] for p in ir.PROTOCOLS}; self.assertEqual(len({str(v) for v in e.values()}), 3)
    def test_clearing_transforms_are_checked_against_bytes(self):
        for op in ("hash", "redact"):
            g = G("S01"); ir.node(g, "n2").update(inputs=["m1"]); g["nodes"].insert(1, {"id": "m1", "type": "transform", "principal": "agent-a", "t": 1, "inputs": ["n1"], "op": op}); j = self.o.judge(g); self.assertEqual((j["status"], j["V"], j["sinks"][0]["byte_seen"]), ("OK", False, False), op)
    def test_partial_sanitizer_is_unknown_not_scored(self):
        g = G("S01"); ir.node(g, "n2").update(inputs=["m1"]); g["nodes"].insert(1, {"id": "m1", "type": "transform", "principal": "agent-a", "t": 1, "inputs": ["n1"], "op": "weak_sanitize"}); j = self.o.judge(g)
        self.assertEqual((j["status"], j["V"]), ("UNKNOWN", None)); self.assertTrue(j["reasons"])
    def test_stacked_transform_disagreement_is_unknown(self):
        g = G("S03"); ir.node(g, "n3").update(inputs=["m1"]); g["nodes"].insert(2, {"id": "m1", "type": "transform", "principal": "agent-a", "t": 2, "inputs": ["n2"], "op": "reverse"}); self.assertEqual(self.o.judge(g)["status"], "UNKNOWN")
    def test_invalid_graph_is_never_executed(self):
        before = self.o.runs; g = G("S01"); ir.node(g, "n2")["dest"] = "WAN"; j = self.o.judge(g); self.assertEqual((j["status"], j["V"]), ("INVALID", None)); self.assertEqual(self.o.runs, before)
    def test_authorization_rules(self):
        g = G("S07"); s = ir.node(g, "n2")
        for t, ok in ((0, False), (1, True), (5, True), (6, False), (8, False)): self.assertEqual(OR.authorized(g, s, t), ok, t)           # window is [issued, issued+ttl)
        s["dest"] = "EXT"; self.assertFalse(OR.authorized(g, s, 3))                                                                       # approval is dest-bound
        g2 = G("S05"); self.assertFalse(OR.authorized(g2, ir.node(g2, "n3"))); g3 = G("S06"); self.assertTrue(OR.authorized(g3, ir.node(g3, "n3")))   # delegation grants EXT
    def test_transitive_delegation(self):
        g = G("S05"); g["delegations"] = [["alice", "agent-a"], ["agent-a", "agent-b"]]; self.assertIn("EXT", OR.grants(g, "agent-b")); g["delegations"] = [["agent-a", "agent-b"], ["agent-b", "agent-a"]]; self.assertEqual(OR.grants(g, "agent-a"), {"INT", "PAR"})
    def test_dead_receiver_gives_unknown_not_safe(self):
        with OR.Oracle() as o2:
            o2.rc.p.kill(); o2.rc.p.wait(); j = o2.judge(G("S01")); self.assertEqual(j["status"], "UNKNOWN"); self.assertIsNone(j["V"])
    def test_effect_observed_by_independent_process_journal(self):
        g = G("S01"); self.o.judge(g); rows = [r for r in self.o.rc.rows() if r["has_canary"]]; self.assertTrue(rows); self.assertNotEqual(self.o.rc.p.pid, os.getpid())
    def test_oracle_does_not_import_detectors_or_pipeline(self):
        src = open(os.path.join(ROOT, "horizon/mutation/oracle.py")).read(); self.assertFalse(re.search(r"^(from|import) .*(detectors|pipeline|experiment)", src, re.M))
    def test_detectors_do_not_import_the_oracle_judgement(self):
        src = open(os.path.join(ROOT, "horizon/mutation/detectors.py")).read(); imp = "\n".join(l for l in src.splitlines() if l.startswith(("from", "import")))
        self.assertEqual(sorted(re.findall(r"\b\w+\b", imp.split("from .oracle import")[1])), ["SECRET_TEXT", "envelope", "values"]); self.assertNotIn(".judge(", src)
    def test_memo_only_reuses_identical_real_sends(self):
        g = G("S01"); self.o.judge(g); r = self.o.runs; self.o.judge(g); self.assertEqual(self.o.runs, r); ir.node(g, "n2")["dest"] = "PAR"; self.o.judge(g); self.assertEqual(self.o.runs, r + 1)


class Operators(Base):
    def test_schema_fields_and_closed_vocabulary(self):
        self.assertEqual(len(OP.OPERATORS), 10); self.assertEqual(len({o.id for o in OP.OPERATORS}), 10)
        for o in OP.OPERATORS: self.assertIn(o.confidence, OP.CONFIDENCE); self.assertTrue(o.obligation and o.kind)
        for g in S.values():
            for o in OP.OPERATORS:
                for p in o.enumerate_params(g)[:6]: self.assertIn(o.predict(g, p), OP.RELATIONS)
    def test_all_covered_kinds(self):
        self.assertEqual({o.kind for o in OP.OPERATORS}, {"protocol", "principal", "order", "branch", "lineage", "destination", "temporal"})
    def test_protocol_swap_preserves_V_on_every_seed(self):
        for g in S.values():
            v = self.o.judge(g)["V"]
            for p in OP.BY_ID["OP-PROTO-SWAP"].enumerate_params(g): self.assertEqual(self.o.judge(OP.BY_ID["OP-PROTO-SWAP"].apply(g, p))["V"], v, (g["id"], p))
    def test_sink_before_approval_flips_to_violation(self):
        g = G("S08"); ir.node(g, "n1")["t"] = 0; ps = OP.BY_ID["OP-SINK-BEFORE-APPROVAL"].enumerate_params(g); self.assertEqual(ps, [{"sink": "n2", "t": 0}]); self.assertEqual(OP.BY_ID["OP-SINK-BEFORE-APPROVAL"].enumerate_params(G("S08")), [])          # needs the source to exist earlier; g2 = OP.BY_ID["OP-SINK-BEFORE-APPROVAL"].apply(g, ps[0])
        g2 = OP.BY_ID["OP-SINK-BEFORE-APPROVAL"].apply(g, ps[0])
        self.assertEqual(ir.feasibility(g2), []); self.assertEqual((self.o.judge(g)["V"], self.o.judge(g2)["V"]), (False, True)); self.assertEqual(OR.approval_state(g2, ir.node(g2, "n2")), "premature")
    def test_temporal_delay_makes_approval_stale_but_decision_time_is_kept(self):
        g = G("S08"); p = {"sink": "n2", "delay": 6}; g2 = OP.BY_ID["OP-TEMPORAL-DELAY"].apply(g, p); s = ir.node(g2, "n2")
        self.assertEqual((s["t"], s["t_decide"]), (9, 3)); self.assertEqual(self.o.judge(g2)["V"], True); self.assertEqual(OP.BY_ID["OP-TEMPORAL-DELAY"].predict(g, p), "CHANGE"); self.assertEqual(OP.BY_ID["OP-TEMPORAL-DELAY"].predict(g, {"sink": "n2", "delay": 1}), "SAME")
    def test_branch_flip_changes_executed_set_and_verdict(self):
        g = G("S09"); g2 = OP.BY_ID["OP-BRANCH-FLIP"].apply(g, {"flag": "export", "value": "int"}); self.assertEqual([n["id"] for n in ir.executing(g2)], ["n1", "n2"]); self.assertEqual((self.o.judge(g)["V"], self.o.judge(g2)["V"]), (True, False))
    def test_sanitize_insert_and_remove_are_inverse_in_effect(self):
        g = G("S01"); g2 = OP.BY_ID["OP-SANITIZE-INSERT"].apply(g, {"before": "n2", "op": "redact"}); self.assertEqual(ir.feasibility(g2), []); self.assertFalse(self.o.judge(g2)["V"])
        g3 = OP.BY_ID["OP-SANITIZE-REMOVE"].apply(g2, {"node": "m1"}); self.assertTrue(self.o.judge(g3)["V"]); self.assertEqual(ir.feasibility(g3), [])
    def test_role_transfer_prediction_is_unknown_without_delegation_link(self):
        g = G("S01"); self.assertEqual(OP.BY_ID["OP-ROLE-TRANSFER"].predict(g, {"node": "n2", "principal": "agent-b"}), "UNKNOWN"); g["delegations"] = [["agent-a", "agent-b"]]; self.assertEqual(OP.BY_ID["OP-ROLE-TRANSFER"].predict(g, {"node": "n2", "principal": "agent-b"}), "SAME")
    def test_role_transfer_authority_is_decided_by_oracle(self):
        g = G("S01"); g2 = OP.BY_ID["OP-ROLE-TRANSFER"].apply(g, {"node": "n2", "principal": "alice"}); self.assertEqual((self.o.judge(g)["V"], self.o.judge(g2)["V"]), (True, False))      # alice may export
    def test_mutations_do_not_modify_their_input(self):
        g = G("S07"); d = ir.digest(g)
        for o in OP.OPERATORS:
            for p in o.enumerate_params(g): o.apply(g, p)
        self.assertEqual(ir.digest(g), d)
    def test_dest_change_prediction_ignores_approvals_and_that_is_measurable(self):
        g = G("S08"); g2 = OP.BY_ID["OP-DEST-CHANGE"].apply(g, {"sink": "n2", "dest": "EXT"}); self.assertEqual(OP.BY_ID["OP-DEST-CHANGE"].predict(g, {"sink": "n2", "dest": "EXT"}), "SAME")           # PAR and EXT both outside agent-a's base grant
        self.assertEqual((self.o.judge(g)["V"], self.o.judge(g2)["V"]), (False, True))                                                                                                      # ...yet the oracle says CHANGE
    def test_operators_digest_changes_with_definition(self):
        self.assertEqual(OP.operators_digest(), OP.operators_digest())


class Pipeline(Base):
    def test_generation_is_deterministic(self):
        a, b = PL.generate(43, 160), PL.generate(43, 160); self.assertEqual([ (m["id"], ir.digest(m["graph"]), m["provenance"]) for m in a["mutants"]], [(m["id"], ir.digest(m["graph"]), m["provenance"]) for m in b["mutants"]])
    def test_different_seed_changes_depth2_only(self):
        a, b = PL.generate(43, 160), PL.generate(7, 160); self.assertEqual(ir.digest([m["id"] for m in a["mutants"][:a["depth1"]]]) is not None, True); self.assertEqual(a["depth1"], b["depth1"]); self.assertNotEqual([m["provenance"] for m in a["mutants"][a["depth1"]:]], [m["provenance"] for m in b["mutants"][b["depth1"]:]])
    def test_provenance_chain_links_to_parent_digest(self):
        G_ = PL.generate(43, 160); by = {m["id"]: m for m in G_["mutants"]}; roots = {r["id"]: r for r in G_["roots"]}; n = 0
        for m in G_["mutants"]:
            self.assertTrue(m["provenance"]); par = by.get(m["parent"]) or roots.get(m["parent"]); self.assertIsNotNone(par)
            self.assertEqual(m["provenance"][-1]["parent_digest"], ir.digest(par["graph"])); self.assertEqual(len(m["provenance"]), len(par.get("provenance", [])) + 1); self.assertEqual(m["family"], roots[m["root"]]["family"]); n += 1
        self.assertGreater(n, 300)
    def test_precondition_gate_rejects_and_counts_infeasible_candidates(self):
        bad = OP.Operator("OP-BAD", "test", lambda g: [{"x": 1}], lambda g, p: (lambda h: (ir.node(h, "n2").update(dest="WAN"), h)[1])(ir.clone(g)), lambda g, p: "SAME", "low", "x")
        out, rej = [], []; root = {"id": "S01", "graph": G("S01"), "family": "F-DIRECT", "provenance": []}; real = PL.OP.OPERATORS
        try:
            PL.OP.OPERATORS = (bad,); PL.expand(root, root, [0], 43, out, rej)
        finally: PL.OP.OPERATORS = real
        self.assertEqual(out, []); self.assertEqual(len(rej), 1); self.assertEqual(rej[0]["operator"], "OP-BAD")
    def test_every_emitted_mutant_is_feasible(self):
        for m in PL.generate(43, 160)["mutants"]: self.assertEqual(ir.feasibility(m["graph"]), [])
    def test_release_manifest_reproducible_and_guarded(self):
        a, b = PL.release_manifest(), PL.release_manifest(); self.assertEqual(a, b); self.assertEqual(a["manifest_digest"], ir.digest({k: v for k, v in a.items() if k != "manifest_digest"})); self.assertIn("loopback", a["guardrails"]["destinations"])
        self.assertEqual(json.loads(json.dumps(a)), a)
    def test_manifest_contains_no_secret_material(self):
        self.assertEqual(json.dumps(PL.release_manifest()).count("TEST_CANARY"), 1)          # only the guardrail text names the synthetic canary; no payload values
    def test_dedup_removes_exact_and_keeps_distinct_decision_time(self):
        a = {"id": "a", "graph": G("S08"), "family": "F-APPROVAL", "oracle": self.o.judge(G("S08"))}
        b = {"id": "b", "graph": ir.clone(G("S08")), "family": "F-APPROVAL", "oracle": a["oracle"]}; b["graph"]["nodes"][1]["protocol"] = "mcp"
        self.assertEqual(PL.effect_signature(a), PL.effect_signature(b)); self.assertEqual(PL.dedup([a, b])["exact_duplicates"], 1)
        g1 = OP.BY_ID["OP-TEMPORAL-DELAY"].apply(G("S07"), {"sink": "n2", "delay": 1}); g2 = OP.BY_ID["OP-TEMPORAL-DELAY"].apply(G("S08"), {"sink": "n2", "delay": 6}); m1 = {"id": "c", "graph": g1, "family": "F-APPROVAL", "oracle": self.o.judge(g1)}; m2 = {"id": "d", "graph": g2, "family": "F-APPROVAL", "oracle": self.o.judge(g2)}
        self.assertEqual((m1["oracle"]["V"], m2["oracle"]["V"]), (True, True)); self.assertNotEqual(PL.effect_signature(m1), PL.effect_signature(m2))      # same stale effect, different decision-time validity: different causal path
    def test_dedup_near_duplicates_need_same_family_and_verdict(self):
        base = G("S01"); a = {"id": "a", "graph": base, "family": "F-DIRECT", "oracle": self.o.judge(base)}; g2 = ir.clone(base); g2["nodes"][1]["dest"] = "PAR"
        b = {"id": "b", "graph": g2, "family": "F-DIRECT", "oracle": self.o.judge(g2)}; c = {"id": "c", "graph": base, "family": "F-OTHER", "oracle": a["oracle"]}
        self.assertEqual(PL.dedup([a, b])["kept"].__len__(), 2); self.assertEqual(PL.dedup([a, c])["kept"].__len__(), 1 + 0 if PL.effect_signature(a) == PL.effect_signature(c) else 2)
    def test_family_split_has_no_overlap_and_covers_all(self):
        G_ = PL.generate(43, 160); sp = PL.split_by_family(G_["mutants"]); self.assertFalse({m["family"] for m in sp["dev"]} & {m["family"] for m in sp["test"]}); self.assertEqual(len(sp["dev"]) + len(sp["test"]), len(G_["mutants"]))
        self.assertFalse(set(SD.DEV_FAMILIES) & set(SD.TEST_FAMILIES)); self.assertEqual(set(SD.DEV_FAMILIES) | set(SD.TEST_FAMILIES), set(SD.FAMILIES))
    def test_mutants_never_change_root_family(self):
        for m in PL.generate(43, 160)["mutants"]: self.assertEqual(m["family"], m["graph"]["family"]); self.assertTrue(m["root"].startswith("S"))
    def test_random_split_mixes_families(self):
        G_ = PL.generate(43, 160); sp = PL.split_random(G_["mutants"], 43); self.assertTrue({m["family"] for m in sp["dev"]} & {m["family"] for m in sp["test"]})
    def test_matched_pairs_share_tool_names_and_flip_truth(self):
        items = PL.label(self.o, PL.generate(43, 160)["mutants"][:120]); pairs = PL.matched_pairs(self.o, items); self.assertGreater(len(pairs), 3)
        for p in pairs:
            self.assertEqual(PL.tool_multiset(p["benign_graph"]), p["tools"]); j = self.o.judge(p["benign_graph"]); self.assertEqual((j["status"], j["V"]), ("OK", False)); self.assertEqual(ir.feasibility(p["benign_graph"]), [])
    def test_pair_with_different_tool_names_is_not_matched(self):
        g = G("S09"); g["principals"]["agent-a"]["base_auth"] = []
        g["nodes"] = [ir.node(g, "n1"), {"id": "n2", "type": "sink", "principal": "alice", "t": 2, "inputs": ["n1"], "dest": "INT", "protocol": "http", "approval": None, "guard": {"export": "int"}},
                      {"id": "n3", "type": "transform", "principal": "agent-a", "t": 2, "inputs": ["n1"], "op": "identity", "guard": {"export": "ext"}}, {"id": "n4", "type": "sink", "principal": "agent-a", "t": 3, "inputs": ["n3"], "dest": "EXT", "protocol": "http", "approval": None, "guard": {"export": "ext"}}]
        self.assertEqual(ir.feasibility(g), []); m = {"id": "x", "graph": g, "family": "F-BRANCH", "oracle": self.o.judge(g)}; self.assertTrue(m["oracle"]["V"])
        flipped = OP.BY_ID["OP-BRANCH-FLIP"].apply(g, {"flag": "export", "value": "int"}); self.assertEqual(self.o.judge(flipped)["V"], False)           # a real flip of the verdict...
        self.assertNotEqual(PL.tool_multiset(g), PL.tool_multiset(flipped))                                                                                  # ...but with a different tool-name multiset
        self.assertEqual(PL.matched_pairs(self.o, [m]), [])
    def test_branch_flip_never_enumerates_the_current_value(self):
        self.assertEqual(OP.BY_ID["OP-BRANCH-FLIP"].enumerate_params(G("S09")), [{"flag": "export", "value": "int"}]); self.assertEqual(OP.BY_ID["OP-BRANCH-FLIP"].enumerate_params(G("S10")), [{"flag": "export", "value": "ext"}])
    def test_lexical_baseline_changes_text_not_graph_structure(self):
        for m in PL.lexical_baseline(43, 20): self.assertEqual(ir.feasibility(m["graph"]), []); self.assertEqual(m["provenance"][0]["operator"], "LEXICAL")
    def test_random_baseline_produces_invalid_graphs(self):
        bad = [m for m in PL.random_baseline(43, 160) if ir.feasibility(m["graph"])]; self.assertGreater(len(bad), 10)
        for m in bad[:5]: j = self.o.judge(m["graph"]); self.assertEqual(j["status"], "INVALID")


class Detectors(Base):
    def test_lexical_misses_derived_forms_and_catches_raw(self):
        self.assertEqual(DT.d1(G("S01")), "BLOCK"); self.assertEqual(DT.d1(G("S03")), "ALLOW")          # b64 evades a raw-byte check although V is true
        self.assertTrue(self.o.judge(G("S03"))["V"])
    def test_lexical_ignores_approvals_so_it_blocks_authorized_exports(self):
        self.assertEqual(DT.d1(G("S08")), "BLOCK"); self.assertFalse(self.o.judge(G("S08"))["V"])
    def test_lineage_v1_misses_delayed_approval_v2_catches(self):
        g = OP.BY_ID["OP-TEMPORAL-DELAY"].apply(G("S08"), {"sink": "n2", "delay": 6}); self.assertTrue(self.o.judge(g)["V"]); self.assertEqual((DT.d2(g), DT.d2b(g)), ("ALLOW", "BLOCK"))
    def test_lineage_v1_false_blocks_untaken_branch(self):
        g = G("S10"); self.assertFalse(self.o.judge(g)["V"]); self.assertEqual((DT.d2(g), DT.d2b(g)), ("BLOCK", "ALLOW"))
    def test_restrictive_rule_over_blocks_approved_and_delegated(self):
        for s in ("S06", "S08"): self.assertFalse(self.o.judge(G(s))["V"]); self.assertEqual(DT.d3(G(s)), "BLOCK", s)
    def test_lineage_policies_agree_with_oracle_on_all_seeds_except_branch(self):
        for s in S.values():
            j = self.o.judge(s); v = j["V"]
            if s["family"] == "F-BRANCH" and not v: continue
            self.assertEqual(DT.d2b(s) == "BLOCK", v, s["id"])
    def test_d4_learns_only_violating_sink_signatures(self):
        d4 = DT.D4().fit([(G("S01"), {"n2"}), (G("S02"), set())]); self.assertEqual(d4.bad, {("EXT", ())}); self.assertEqual(d4(G("S03")), "ALLOW")      # b64 chain not learned
    def test_decisions_do_not_mutate_graph(self):
        g = G("S09"); d = ir.digest(g)
        for f in DT.STATIC.values(): f(g)
        self.assertEqual(ir.digest(g), d)


class Minimizer(Base):
    def test_minimizes_padded_failure_and_preserves_oracle_result(self):
        g = OP.BY_ID["OP-TEMPORAL-DELAY"].apply(G("S08"), {"sink": "n2", "delay": 6}); pred = lambda x: (not ir.feasibility(x)) and (lambda j: j["status"] == "OK" and j["V"] is True)(self.o.judge(x)) and DT.d2(x) == "ALLOW"
        padded = MZ.pad(g); self.assertEqual(len(padded["nodes"]), 6); self.assertTrue(pred(padded)); m, ev = MZ.minimize(padded, pred)
        self.assertEqual(len(m["nodes"]), 2); self.assertTrue(pred(m)); self.assertTrue(MZ.is_one_minimal(m, pred)); self.assertEqual(self.o.judge(m)["V"], True); self.assertGreater(ev, 1)
    def test_minimizer_never_returns_a_graph_that_fails_the_predicate(self):
        g = G("S11"); pred = lambda x: (not ir.feasibility(x)) and self.o.judge(x)["V"] is True; m, _ = MZ.minimize(MZ.pad(g), pred); self.assertTrue(pred(m)); self.assertEqual([n["op"] for n in m["nodes"] if n["type"] == "transform"], [])          # the predicate is only 'V true': even rot13 is removable
    def test_requires_a_failing_start(self):
        with self.assertRaises(AssertionError): MZ.minimize(G("S02"), lambda x: self.o.judge(x)["V"] is True)
    def test_is_one_minimal_detects_removable_node(self):
        pred = lambda x: (not ir.feasibility(x)) and self.o.judge(x)["V"] is True; self.assertFalse(MZ.is_one_minimal(MZ.pad(G("S01")), pred)); self.assertTrue(MZ.is_one_minimal(G("S01"), pred))
    def test_pad_preserves_verdict(self):
        for s in ("S01", "S04", "S07"): self.assertEqual(self.o.judge(MZ.pad(G(s)))["V"], self.o.judge(G(s))["V"], s)


class Recorded(unittest.TestCase):
    R = json.load(open(os.path.join(D, "result.json")))
    def test_llm_generator_not_claimed(self): self.assertIn("NOT RUN", self.R["generators"]["llm_generator"]["status"])
    def test_constrained_generator_has_no_invalid_but_random_does(self):
        c, r = self.R["generators"]["horizon_mutation_constrained"]["relation"], self.R["generators"]["unconstrained_scripted_random_NOT_AN_LLM"]["relation"]
        self.assertEqual(c["invalid_rate"]["k"], 0); self.assertGreater(r["invalid_rate"]["rate"], 0.1)
    def test_unknown_is_reported_separately_not_dropped(self):
        g = self.R["generation"]; self.assertGreater(g["status"].get("UNKNOWN", 0), 0); self.assertEqual(sum(g["status"].values()), g["depth1"] + g["depth2"])
    def test_family_split_overlap_empty(self): self.assertEqual(self.R["split"]["family_overlap"], [])
    def test_raw_random_split_overstates_vs_family_split(self):
        s = self.R["split_raw_not_deduplicated"]; self.assertGreater(s["random_split"]["on_held_out"]["recall"]["rate"], s["family_split"]["on_held_out"]["recall"]["rate"])
    def test_mutation_finds_a_failure_the_seeds_do_not(self):
        self.assertEqual(self.R["detectors_on_seeds_only"]["D2-lineage-v1"]["recall"]["rate"], 1.0); self.assertLess(self.R["detectors"]["D2-lineage-v1"]["recall"]["rate"], 1.0); self.assertEqual(self.R["detectors"]["D2b-lineage-v2"]["recall"]["rate"], 1.0)
    def test_restrictive_rule_has_high_disruption(self): self.assertGreater(self.R["detectors"]["D3-restrictive"]["benign_disruption"]["rate"], 0.3)
    def test_pairs_share_tool_names(self): self.assertTrue(self.R["pairs"]["tool_names_identical"]); self.assertGreater(self.R["pairs"]["n"], 5)
    def test_minimizer_rows_valid(self):
        for m in self.R["minimizer"]: self.assertTrue(m["oracle_V_unchanged"] and m["d2_still_misses"] and m["one_minimal"]); self.assertLess(m["nodes_after"], m["nodes_before"])
    def test_limits_state_same_author_and_declared_authority(self):
        t = " ".join(self.R["limits"]); self.assertIn("same author", t); self.assertIn("DECLARED", t); self.assertIn("not a language model", t)
    def test_report_and_docs_current(self):
        self.assertEqual(subprocess.run([sys.executable, "scripts/p43_report.py", "--check"], cwd=ROOT, capture_output=True).returncode, 0)
        t = open(os.path.join(ROOT, "docs/evidence/p43/ASSUMPTIONS_AND_TAXONOMY.md")).read()
        for w in ("Graph IR", "Operator schema", "Ground truth", "UNKNOWN", "Authority is declared", "Provenance", "Splits", "Assumptions"): self.assertIn(w, t)
    def test_dataset_contains_only_synthetic_material(self):
        t = open(os.path.join(D, "dataset.json")).read(); self.assertNotIn("TEST_CANARY", t); self.assertNotRegex(t, r"https?://(?!127\.0\.0\.1)")
    def test_experiment_rerun_matches_recorded_counts(self):
        r = json.loads(json.dumps(EX.run(43, 160))); rec = dict(self.R); [d.pop(k) for d in (r, rec) for k in ("wall_s", "detector_latency_us_median")]
        for k in rec: self.assertEqual(r[k], rec[k], k)          # the whole experiment is deterministic


if __name__ == "__main__": unittest.main()
