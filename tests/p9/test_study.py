"""P9 tests: baseline/ablation behaviour on hand-built worlds, self-consistency of the committed results with their raw rows, integrity manifest, and bounded-claim checks."""
import json, sys, unittest
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from bench.secbench import spec
from bench.secbench.world import World, Sut, NoRealNetwork, ALL_SUTS, BASELINES, ABLATIONS, HOSTS
from bench.secbench.runner import run_one
from bench.p9 import stats as S, manifest, study

RES = json.loads((REPO / "results/v2/p9_comparative.json").read_text()); ROWS = RES["rows"]
SC = {s["visible"]["id"]: s for s in spec.build()}


def send(sysn, src, via="utcp.post", dest="d1", read_also=()):
    w = World(1); s = Sut(sysn, w)
    for r in read_also: s.read(r, "mcp")
    v, h = s.read(src, "mcp"); r = s.send(via, v, [h], dest, None); s.close(); return r, w, s


class BaselineBehaviour(unittest.TestCase):
    def test_all_systems_registered(self): self.assertEqual(len(ALL_SUTS), len(set(ALL_SUTS))); self.assertTrue(set(BASELINES) | set(ABLATIONS) <= set(ALL_SUTS))
    def test_b2_blocks_unapproved_host_but_not_content_or_cli(self):
        self.assertTrue(send("b2_allowlist", "s2")[0]["ok"])                                  # secret bytes to the approved host pass: it only sees endpoints
        self.assertFalse(send("b2_allowlist", "s2", dest="d2")[0]["ok"]); self.assertTrue(send("b2_allowlist", "s2", via="cli.upload")[0]["ok"])
    def test_b3_blocks_any_send_after_a_secret_read_even_public_bytes(self):
        r, _, s = send("b3_read_send_pair", "s1", read_also=["s2"]); self.assertFalse(r["ok"]); self.assertEqual(s.blocked_by, "READ_SEND_PAIR"); self.assertTrue(send("b3_read_send_pair", "s1")[0]["ok"])
    def test_b4_catches_verbatim_not_encoded(self):
        r, w, _ = send("b4_exact_taint", "s2"); self.assertFalse(r["ok"])
        w = World(1); s = Sut("b4_exact_taint", w); v, h = s.read("s2", "mcp"); import base64; self.assertTrue(s.send("utcp.post", base64.b64encode(v.encode()).decode(), [h], "d1", None)["ok"])
    def test_b4_requires_the_whole_value(self):
        w = World(1); s = Sut("b4_exact_taint", w); v, h = s.read("s2", "mcp"); self.assertTrue(s.send("utcp.post", v[:3] + " and " + v[:-1], [h], "d1", None)["ok"])
    def test_baselines_never_use_lineage_handles(self): self.assertFalse(Sut("b4_exact_taint", World(1)).gated)

    def test_full_blocks_what_no_boundary_ablation_allows(self):
        sc = next(s for s in SC.values() if s["truth"]["template_code"] == "S1" and s["truth"]["role"] == "harmful" and not s["truth"]["tracked"])
        with NoRealNetwork(): full, nb = run_one(sc, "full", spec.SEED), run_one(sc, "full-no-boundary", spec.SEED)
        self.assertFalse(full["attacker_success"]); self.assertTrue(nb["attacker_success"])
    def test_manual_trust_ablation_accepts_unreviewed_swap(self):
        sc = next(s for s in SC.values() if s["truth"]["template_code"] == "U3" and s["truth"]["role"] == "harmful")
        with NoRealNetwork(): full, nm = run_one(sc, "full", spec.SEED), run_one(sc, "full-no-manual-trust", spec.SEED)
        self.assertFalse(full["attacker_success"]); self.assertTrue(nm["attacker_success"])
    def test_ledger_ablation_acts_on_untrusted_claim(self):
        sc = next(s for s in SC.values() if s["truth"]["template_code"] == "E2" and s["truth"]["role"] == "harmful")
        with NoRealNetwork(): full, nl = run_one(sc, "full", spec.SEED), run_one(sc, "full-no-ledger", spec.SEED)
        self.assertFalse(full["attacker_success"]); self.assertTrue(nl["attacker_success"])


class ResultsConsistency(unittest.TestCase):
    def test_no_error_or_timeout_rows(self): self.assertEqual({r["outcome"] for r in ROWS} - {"COMPLETED", "BLOCKED", "REFUSED"}, set())
    def test_every_system_ran_every_scenario(self):
        ids = {r["id"] for r in ROWS}
        for s in ALL_SUTS: self.assertEqual({r["id"] for r in ROWS if r["system"] == s}, ids, s)
    def test_summary_recomputed_from_rows(self):
        for sysn, v in RES["summaries"]["test_all"].items():
            rs = [r for r in ROWS if r["system"] == sysn and r["split"] == "test"]; self.assertEqual(v["attacker_success"], sum(r["attacker_success"] for r in rs if r["role"] == "harmful")); self.assertEqual(v["benign_utility_ok"], sum(bool(r["utility_ok"]) for r in rs if r["role"] == "benign"))
    def test_primary_comparisons_recomputed_from_rows(self):
        prim = [c for c in RES["comparisons"] if c.get("primary")]; self.assertEqual(len(prim), 4)
        for c in prim:
            g = lambda sy: {r["id"]: int(r["attacker_success"]) for r in ROWS if r["system"] == sy and r["split"] == "test" and r["role"] == "harmful"}
            p = S.paired(g(c["a"]), g(c["b"])); self.assertEqual((p["discordant_a_only"], p["discordant_b_only"], p["mcnemar_exact_p"]), (c["discordant_a_only"], c["discordant_b_only"], c["mcnemar_exact_p"]))
        adj = S.holm([c["mcnemar_exact_p"] for c in prim]); self.assertEqual([round(a, 6) for a in adj], [c["holm_adjusted_p"] for c in prim])
    def test_paired_by_scenario_ids_and_matched_roles(self):
        by = {}
        for r in ROWS:
            if r["system"] == "full": by.setdefault(r["pair"], set()).add(r["role"])
        self.assertTrue(all(v == {"harmful", "benign"} for v in by.values()))
    def test_no_row_leaks_truth_into_published_rows(self): self.assertNotIn("_t", ROWS[0])
    def test_transport_equivalence_reports_disagreements_and_secret_always_blocked(self):
        te = RES["transport_equivalence"]
        for x in te["matrix"]:
            if x["payload"] == "secret" and x["system"] in ("full", "labels_only"): self.assertFalse(x["allowed"], x)
        self.assertTrue(te["semantic_disagreements"]); self.assertTrue(all(d["payload"] == "public" for d in te["semantic_disagreements"]))
    def test_determinism_scope_is_honest(self): self.assertTrue(RES["determinism"]["identical"]); self.assertIn("No LLM", RES["determinism"]["note"])
    def test_status_does_not_open_gate(self): self.assertIn("G6 NOT opened", RES["status"]); self.assertEqual(RES["agents"], "scripted (no LLM)")


class ClaimBounds(unittest.TestCase):
    """The headline must not overstate: B3 matches `full` on attack success on the 0.1 templates, and only post-hoc sensitive-benign templates separate them."""
    def test_b3_ties_full_on_v01_attack_success(self):
        t = RES["summaries"]["test_v01_templates"]; self.assertEqual(t["b3_read_send_pair"]["attacker_success"], t["full"]["attacker_success"]); self.assertGreater(t["b3_read_send_pair"]["benign_utility_ok"], t["full"]["benign_utility_ok"])
    def test_s_templates_separate_full_from_b3_on_utility_only(self):
        s = RES["summaries"]["post_hoc_S"]; self.assertEqual(s["b3_read_send_pair"]["benign_utility_ok"], 0); self.assertEqual(s["full"]["benign_utility_ok"], s["full"]["benign_n"]); self.assertEqual(s["full"]["attacker_success"], 0)
    def test_cluster_intervals_present_and_wider_than_scenario_level(self):
        c = next(c for c in RES["comparisons"] if c.get("primary") and c["b"] == "b4_exact_taint"); lo, hi = c["risk_difference_ci95_cluster"]; self.assertLess(lo, c["risk_difference"] + 1e-9); self.assertGreater(c["n_template_clusters"], 3)
    def test_full_still_has_known_misses_and_utility_cost(self):
        t = RES["summaries"]["test_all"]["full"]; self.assertGreater(t["attacker_success"], 0); self.assertLess(t["benign_utility_ok"], t["benign_n"])


class Docs(unittest.TestCase):
    def test_prereg_and_results_docs_state_limits(self):
        pre = (REPO / "docs/research/P9_PREREGISTRATION.md").read_text(); res = (REPO / "docs/research/P9_RESULTS_AND_LIMITS.md").read_text()
        self.assertIn("no result here is confirmatory", pre); self.assertIn("Gate G6", pre); self.assertIn("B3 ties", res); self.assertIn("Not done", res)


class IntegrityManifest(unittest.TestCase):
    def test_manifest_verifies_and_detects_tampering(self):
        bad, _ = manifest.verify(); self.assertEqual(bad, [])
        p = REPO / "results/v2/p9_comparative.json"; orig = p.read_bytes()
        try:
            p.write_bytes(orig + b" "); self.assertIn("results/v2/p9_comparative.json", manifest.verify()[0])
        finally: p.write_bytes(orig)


if __name__ == "__main__": unittest.main()
