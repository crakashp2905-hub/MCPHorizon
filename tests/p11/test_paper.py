"""P11 tests: every table/figure/manuscript number derives from result artifacts; claims in the manuscript match the data; equivalence relation properties; documents state their limits."""
import hashlib, itertools, json, re, subprocess, sys, unittest
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO)); sys.path.insert(0, str(REPO / "paper"))
import build as B
from horizon import normalize as N

MS = (REPO / "paper/MANUSCRIPT.md").read_text(); RES = json.loads((REPO / "results/v2/p9_comparative.json").read_text())


class Derivation(unittest.TestCase):
    def test_build_check_passes(self): r = subprocess.run([sys.executable, str(REPO / "paper/build.py"), "--check"], capture_output=True, text=True); self.assertEqual((r.returncode, r.stdout.strip()), (0, "OK"), r.stdout + r.stderr)
    def test_stale_manuscript_table_is_detected(self):
        p = REPO / "paper/MANUSCRIPT.md"; orig = p.read_text()
        try:
            p.write_text(orig.replace("| full | 2/30", "| full | 1/30", 1)); r = subprocess.run([sys.executable, str(REPO / "paper/build.py"), "--check"], capture_output=True, text=True); self.assertEqual(r.returncode, 1); self.assertIn("MANUSCRIPT.md", r.stdout)
        finally: p.write_text(orig)
    def test_tampered_build_manifest_and_missing_marker_are_detected(self):
        mp = REPO / "paper/BUILD_MANIFEST.json"; orig = mp.read_text()
        try:
            mp.write_text(orig.replace('"inputs"', '"inputz"', 1)); r = subprocess.run([sys.executable, str(REPO / "paper/build.py"), "--check"], capture_output=True, text=True); self.assertEqual(r.returncode, 1)
        finally: mp.write_text(orig)
        with self.assertRaises(SystemExit): B.embed(MS.replace("<!-- BEGIN table_main -->", ""), B.generated()[0])
        with self.assertRaises(SystemExit): B.embed(MS + "<!-- BEGIN table_main -->\n<!-- END table_main -->\n", B.generated()[0])
    def test_every_table_row_number_comes_from_the_results(self):
        tabs, _ = B.generated(); T = RES["summaries"]["test_all"]
        for k, v in T.items(): self.assertIn(f"{v['attacker_success']}/{v['harmful_n']}", tabs["table_main"] + tabs["table_ablation"]) if k in B.LABEL else None
    def test_figures_are_valid_svg_with_all_systems_and_matching_counts(self):
        _, figs = B.generated(); T = RES["summaries"]["test_all"]
        import xml.dom.minidom as md
        for name, svg in figs.items():
            md.parseString(svg)
            for k in B.ORDER: self.assertIn(B.LABEL[k], svg)
        for k in B.ORDER: self.assertIn(f"{T[k]['attacker_success']}/{T[k]['harmful_n']}", figs["fig1_attacker_success.svg"])
    def test_inputs_hash_recorded(self):
        m = json.loads((REPO / "paper/BUILD_MANIFEST.json").read_text())
        for p, h in m["inputs"].items(): self.assertEqual(hashlib.sha256((REPO / p).read_bytes()).hexdigest(), h, p)
    def test_prose_has_no_hand_typed_result_numbers(self):
        prose = re.sub(r"<!-- BEGIN (\w+) -->.*?<!-- END \1 -->", "", MS, flags=re.S); prose = re.sub(r"```.*?```", "", prose, flags=re.S)
        self.assertEqual(re.findall(r"\b\d+\s*/\s*\d+\b|\b\d+(?:\.\d+)?\s*%", prose), [])


class ClaimsMatchData(unittest.TestCase):
    def test_manuscript_admits_the_tie_and_data_shows_it(self):
        v = RES["summaries"]["test_v01_templates"]; self.assertEqual(v["b3_read_send_pair"]["attacker_success"], v["full"]["attacker_success"]); self.assertGreater(v["b3_read_send_pair"]["benign_utility_ok"], v["full"]["benign_utility_ok"])
        for phrase in ("ties", "post-hoc", "NOT submitted", "does not survive", "not established", "No independent reader", "were written after"): self.assertIn(phrase.lower(), MS.lower() + " " + (REPO / "docs/research/P11_MOCK_PEER_REVIEW.md").read_text().lower(), phrase)
    def test_s_templates_separate_on_utility_per_data(self):
        s = RES["summaries"]["post_hoc_S"]; self.assertEqual((s["b3_read_send_pair"]["benign_utility_ok"], s["full"]["benign_utility_ok"], s["full"]["attacker_success"]), (0, s["full"]["benign_n"], 0))
    def test_conclusions_do_not_overreach(self):
        for banned in ("state-of-the-art", "outperforms", "provably secure", "guarantees security", "solves", "verified factual"): self.assertNotIn(banned, MS.lower())
    def test_gate_and_status_language(self):
        s = (REPO / "docs/implementation/STATUS.md").read_text() if (REPO / "docs/implementation/STATUS.md").exists() else ""; self.assertNotIn("Gate G9 OPEN", s)


class Equivalence(unittest.TestCase):
    OPS = [("mcp", "resources/read", None), ("mcp", "resources/list", None), ("utcp", "http:GET", None), ("utcp", "http:POST", None), ("utcp", "cli:exec", None), ("code_mode", "fs.readFile", None), ("code_mode", "fetch:POST", None), ("code_mode", "fetch:GET", None), ("mcp", "tools/call", "unregistered"), ("utcp", "http:TRACE", None), ("ws", "send", None)]
    def key(self, op, target="https://api.example.com/a", args={"x": 1}):
        eff = N.logical_operation(*op); return (eff, N.canonical_target("url", target)["canonical_id"], hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest())
    def test_relation_is_equivalence_on_its_domain(self):
        dom = []
        for op in self.OPS:
            try: self.key(op); dom.append(op)
            except N.Unmapped: pass
        rel = lambda a, b, ta="https://api.example.com/a", tb="https://API.example.com:443/b/../a": self.key(a, ta) == self.key(b, tb)
        for a in dom: self.assertTrue(rel(a, a))
        for a, b in itertools.product(dom, dom): self.assertEqual(rel(a, b), rel(b, a))
        for a, b, c in itertools.product(dom, dom, dom):
            if rel(a, b) and rel(b, c): self.assertTrue(rel(a, c))
    def test_equivalent_across_protocols_and_distinct_otherwise(self):
        self.assertEqual(self.key(("utcp", "http:POST", None)), self.key(("code_mode", "fetch:POST", None), "https://API.example.com:443/b/../a")); self.assertNotEqual(self.key(("utcp", "http:POST", None)), self.key(("utcp", "http:GET", None)))
        self.assertNotEqual(self.key(("utcp", "http:POST", None), "https://api.example.com/a"), self.key(("utcp", "http:POST", None), "https://api.example.com/b")); self.assertNotEqual(self.key(("utcp", "http:POST", None), args={"x": 1}), self.key(("utcp", "http:POST", None), args={"x": 2}))
    def test_operations_outside_the_domain_relate_to_nothing(self):
        for op in (("mcp", "tools/call", "unregistered"), ("utcp", "http:TRACE", None), ("ws", "send", None)):
            with self.assertRaises(N.Unmapped): N.logical_operation(*op)
    def test_documented_semantic_disagreements_exist_in_the_data(self):
        dis = RES["transport_equivalence"]["semantic_disagreements"]; self.assertTrue(dis); self.assertTrue(all(d["payload"] == "public" for d in dis))


class DocsState(unittest.TestCase):
    def test_limits_are_stated(self):
        f = (REPO / "docs/formal/P11_FORMALIZATION.md").read_text(); self.assertIn("partial function", f); self.assertIn("NP-hard", f); self.assertIn("EXPTIME", f); self.assertIn("not an s–t minimum cut", f); self.assertIn("needs independent mathematical review", f)
        r = (REPO / "docs/research/P11_RELATED_WORK.md").read_text(); self.assertIn("unverified", r.lower()); self.assertIn("NOT REVIEWED", r)
        self.assertIn("NOT BUILT", (REPO / "replication/Dockerfile").read_text()); self.assertIn("UNVERIFIED", (REPO / "replication/README.md").read_text()); self.assertIn("do not submit", (REPO / "docs/research/P11_MOCK_PEER_REVIEW.md").read_text().lower())
    def test_deviation_record_and_restored_results_match_manifest(self):
        d = REPO / "results/v2/p8-secbench-0.1"; m = json.loads((d / "manifest.json").read_text())
        for sp, h in m["sha256"].items(): self.assertEqual(hashlib.sha256((d / f"{sp}.json").read_bytes()).hexdigest(), h)
        self.assertIn("overwritten", (REPO / "results/v2/DEVIATIONS.md").read_text())


if __name__ == "__main__": unittest.main()
