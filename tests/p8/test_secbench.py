"""P8 tests: the BENCHMARK ITSELF (oracles, validity of every scenario, matched pairs, splits, blinding, freezing, containment) plus the headline comparison."""
import base64, binascii, csv, json, os, shutil, socket, sqlite3, sys, tempfile, unittest
from pathlib import Path
from urllib.parse import quote
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from bench.secbench import spec, freeze, annotate
from bench.secbench.world import World, NetOracle, StateOracle, authorization_oracle, NoRealNetwork, NetworkAttempt, Sut, HOSTS, DNS, KEYWORDS
from bench.secbench.runner import run_one, summarize, wilson, CODE_TEMPLATES
from horizon.codemode.exec import HERE as CM

HAVE_NODE = bool(shutil.which("node")) and (CM / "node_modules" / "isolated-vm").exists()
SC = spec.build()
USABLE = [s for s in SC if HAVE_NODE or s["truth"]["template_code"] not in CODE_TEMPLATES]


class OracleTests(unittest.TestCase):
    """The oracle is the ground truth, so it is tested directly (two real oracle bugs were found while building the runner)."""
    def setUp(self): self.w = World(1); self.n = NetOracle(self.w); self.tok = self.w.tokens["s2"]

    def ev(self, body: bytes, url="https://api.example.com/v1/notes"): self.w.record("utcp", url, body)

    def test_detects_raw_and_every_encoding_and_reversal(self):
        t = self.tok.encode(); cases = {"raw": t, "b64": base64.b64encode(t), "b64url": base64.urlsafe_b64encode(t), "hex": binascii.hexlify(t), "pct": quote(self.tok, safe="").encode(), "rev": t[::-1], "json": json.dumps(self.tok).encode(),
                                         "b64rev": base64.b64encode(t[::-1]), "wrapped": b"prefix " + t + b" suffix"}
        for k, b in cases.items():
            w = World(1); w.record("utcp", "https://x/", b); self.assertEqual(NetOracle(w).leaked_tokens(["s2"]), {"s2"}, k)

    def test_chunks_are_rejoined_including_json_framing(self):
        h = len(self.tok) // 2
        for enc in (lambda s: s.encode(), lambda s: json.dumps(s).encode()):
            w = World(1); w.record("utcp", "https://x/", enc(self.tok[:h])); w.record("utcp", "https://x/", enc(self.tok[h:])); self.assertEqual(NetOracle(w).leaked_tokens(["s2"]), {"s2"})
        w = World(1); w.record("utcp", "https://x/", self.tok[:h].encode()); self.assertEqual(NetOracle(w).leaked_tokens(["s2"]), set())              # half is not a leak

    def test_no_false_positives_on_public_data_and_lookalikes(self):
        for b in (self.w.pub.encode(), b"TKN-" + b"0" * 24, self.tok[:-1].encode(), b"nothing", self.w.data["s1"].encode(), json.dumps(self.w.data["s6p"]).encode()): 
            w = World(1); w.record("utcp", "https://x/", b); self.assertEqual(NetOracle(w).leaked_tokens(["s2", "s6"]), set(), b)

    def test_query_string_filesystem_and_database_channels(self):
        w = World(1); w.record("utcp", f"https://api.example.com/v1/q?x={quote(self.tok, safe='')}", b""); self.assertEqual(NetOracle(w).leaked_tokens(["s2"]), {"s2"})
        w = World(1); Path(w.outbox, "upload.bin").write_text(self.tok); self.assertEqual(NetOracle(w).leaked_tokens(["s2"]), {"s2"})
        w = World(1); c = sqlite3.connect(os.path.join(w.outbox, "outbox.db")); c.execute("create table uploads(data text)"); c.execute("insert into uploads values(?)", (self.tok,)); c.commit(); c.close()
        self.assertEqual(NetOracle(w).leaked_tokens(["s2"]), {"s2"}); self.assertEqual(NetOracle(w).db_rows(), [self.tok])

    def test_state_oracle_diff(self):
        w = World(1); st = StateOracle(w); self.assertEqual(st.diff(), {}); Path(w.outbox, "a.bin").write_text("x"); self.assertEqual(list(st.diff()), ["a.bin"])
        c = sqlite3.connect(os.path.join(w.outbox, "outbox.db")); c.execute("create table uploads(data text)"); c.execute("insert into uploads values('r1')"); c.commit(); c.close(); self.assertEqual(st.diff()["outbox.db"], ["r1"])

    def test_authorization_and_destination_oracles(self):
        truth = {"intent_allows_sources": ["s1"], "intent_allows_dests": ["d1"]}; w = World(1); w.record("utcp", "https://api.example.com/v1/notes", w.pub.encode()); self.assertEqual(authorization_oracle(truth, NetOracle(w), w), {"unauthorized_sources": [], "unintended_dests": []})
        w = World(1); w.record("utcp", "https://other.example.org/v1/notes", w.tokens["s2"].encode()); a = authorization_oracle(truth, NetOracle(w), w); self.assertEqual((a["unauthorized_sources"], a["unintended_dests"]), (["s2"], ["other.example.org"]))

    def test_oracle_module_does_not_import_defence_code(self):
        src = Path(REPO / "bench/secbench/world.py").read_text(); oracle_part = src[src.index("# ---------------- oracles"):src.index("# ---------------- systems under test")]
        for banned in ("detect", "variants", "lineage", "Boundary"): self.assertNotIn(banned, oracle_part)


class BenchmarkValidityTests(unittest.TestCase):
    def test_counts_pairs_and_matching(self):
        by = {}
        for s in SC: by.setdefault(s["truth"]["pair"], {})[s["truth"]["role"]] = s
        self.assertTrue(all(set(v) == {"harmful", "benign"} for v in by.values())); self.assertEqual(len(SC), 128)
        for pair, v in by.items():
            h, b = v["harmful"]["visible"], v["benign"]["visible"]; self.assertEqual((h["intent"], h["tools"], h["template"], len(h["steps"])), (b["intent"], b["tools"], b["template"], len(b["steps"])), pair)
            diff = [(x, y) for x, y in zip(h["steps"], b["steps"]) if x != y]; self.assertTrue(all(set(x) == set(y) for x, y in diff))      # same operations, different parameter values only
            self.assertEqual({k: v for k, v in v["harmful"]["truth"].items() if k in ("template_code", "tracked", "seed_i", "split", "family")}, {k: v for k, v in v["benign"]["truth"].items() if k in ("template_code", "tracked", "seed_i", "split", "family")})

    def test_splits_are_template_disjoint_and_complete(self):
        sp = spec.split(SC); self.assertEqual(sum(map(len, sp.values())), len(SC)); self.assertEqual(len(set(sum(sp.values(), []))), len(SC))
        tpl = {k: {s["visible"]["template"] for s in SC if s["visible"]["id"] in set(v)} for k, v in sp.items()}
        for a in tpl:
            for b in tpl:
                if a < b: self.assertEqual(tpl[a] & tpl[b], set())
        fam = lambda ids: {st["via"] for s in SC if s["visible"]["id"] in set(ids) for st in s["visible"]["steps"] if st["op"] == "send"}
        self.assertTrue(fam(sp["test"]) - fam(sp["train"]) >= {"utcp.get", "ws.send"})                                                        # the test split contains transports unseen in training

    def test_visible_files_have_no_labels_and_blinded_names(self):
        bad = ("harmful", "benign", "attack", "exfil", "secret", "malicious", "truth", "forbidden", "role", "pair", "claim_truth", "expected")
        for s in SC:
            txt = json.dumps(s["visible"]).lower()
            for w in bad: self.assertNotIn(w, txt, (s["visible"]["id"], w))
            self.assertEqual(set(s["visible"]), {"id", "version", "template", "intent", "tools", "steps"})
            self.assertNotIn("claim", json.dumps([k for st in s["visible"]["steps"] for k in st if k == "claim_truth"]))
        self.assertNotIn("s2", "".join(s["visible"]["intent"] for s in SC))

    def test_lexical_classifier_on_visible_text_is_near_chance(self):
        """A bag-of-tokens classifier trained on train+dev visible text must not beat chance by much on test (no trivial label leakage in names)."""
        import collections, math
        tok = lambda s: set(json.dumps({k: v for k, v in s["visible"].items() if k != "id"}).replace('"', " ").replace(":", " ").replace(",", " ").split())
        tr = [s for s in SC if s["truth"]["split"] != "test"]; te = [s for s in SC if s["truth"]["split"] == "test"]; c = {"harmful": collections.Counter(), "benign": collections.Counter()}
        for s in tr: c[s["truth"]["role"]].update(tok(s))
        def pred(s):
            sc = {r: sum(math.log((c[r][w] + 1) / (sum(c[r].values()) + 1)) for w in tok(s)) for r in c}; return max(sc, key=sc.get)
        acc = sum(pred(s) == s["truth"]["role"] for s in te) / len(te); self.assertLessEqual(acc, 0.65, acc)

    def test_unblinded_view_is_trivially_separable_by_keywords(self):
        hit = lambda v: any(k in json.dumps(v).lower() for k in KEYWORDS)
        self.assertTrue(all(hit(spec.unblinded_view(s["visible"], s["truth"])) == (s["truth"]["role"] == "harmful") for s in SC)); self.assertFalse(any(hit(s["visible"]) for s in SC))

    def test_every_scenario_has_evidence_and_independent_truth(self):
        for s in SC:
            t = s["truth"]; self.assertTrue(len(t["label_evidence"]) > 20); self.assertEqual(bool(t["forbidden_effects"]), t["role"] == "harmful"); self.assertEqual(bool(t["authorized_effects"]), t["role"] == "benign")

    def test_hard_cases_present_in_dev_and_test(self):
        self.assertEqual({s["truth"]["hard_case"] for s in SC if s["truth"]["hard_case"]}, set(spec.HARD.values())); self.assertEqual({s["truth"]["split"] for s in SC if s["truth"]["template_code"] in spec.HARD}, {"dev", "test"})


class FreezeTests(unittest.TestCase):
    def test_committed_files_match_regeneration_and_manifest(self): w = []; self.assertEqual(freeze.verify(w), [])
    def test_tampering_is_detected(self):
        p = freeze.DATA / "splits.json"; orig = p.read_text()
        try:
            p.write_text(orig.replace('"test"', '"tezt"', 1)); self.assertTrue(freeze.verify([]))
        finally: p.write_text(orig)
        self.assertEqual(freeze.verify([]), [])
    def test_deterministic_generation(self): self.assertEqual(freeze.render(), freeze.render()); self.assertNotEqual(freeze.render(1)["splits.json"], freeze.render()["splits.json"])


class ContainmentTests(unittest.TestCase):
    def test_real_network_attempt_fails_loudly(self):
        with NoRealNetwork():
            with self.assertRaises(NetworkAttempt): socket.create_connection(("93.184.216.34", 80))
            with self.assertRaises(NetworkAttempt): socket.socket().connect(("127.0.0.1", 9))
        s = socket.socket(); s.close()
    def test_all_destinations_are_fictional_and_resolved_to_the_in_process_receiver(self):
        self.assertTrue(all(h.endswith((".example.com", ".example.org", ".example.net")) for h in HOSTS.values())); self.assertEqual(set(DNS), set(HOSTS.values()))
    def test_full_benchmark_run_makes_no_real_connection(self):
        calls = []; orig = socket.socket.connect
        socket.socket.connect = lambda self, *a, **k: calls.append(a) or (_ for _ in ()).throw(NetworkAttempt("blocked"))
        try:
            rows = [run_one(s, "open", spec.SEED) for s in USABLE[:30]]
        finally: socket.socket.connect = orig
        self.assertEqual(calls, []); self.assertTrue(all(r["outcome"] != "ERROR" for r in rows))
    def test_no_file_descriptor_leak_across_runs(self):
        """Regression: the P3 audit log fd was never closed; ~1000 scenario runs then crashed select() with 'filedescriptor out of range'."""
        n = lambda: len(os.listdir("/proc/self/fd")); sc = next(s for s in SC if s["truth"]["template_code"] == "U1"); run_one(sc, "full", spec.SEED); a = n()
        for _ in range(5): run_one(sc, "full", spec.SEED)
        self.assertEqual(n() - a, 0)
    def test_temp_worlds_are_cleaned_up(self):
        before = set(Path(tempfile.gettempdir()).glob("secbench-*")); run_one(USABLE[0], "open", spec.SEED); self.assertEqual(set(Path(tempfile.gettempdir()).glob("secbench-*")) - before, set())


class ScenarioValidityUnderBaseline(unittest.TestCase):
    """Benchmark acceptance: every harmful scenario really produces its forbidden effect with no defence, every benign twin really completes with no violation."""
    @classmethod
    def setUpClass(cls): cls.rows = [run_one(s, "open", spec.SEED) for s in USABLE]

    def test_every_harmful_scenario_succeeds_without_defence(self):
        bad = [r["id"] + r["template"] for r in self.rows if r["role"] == "harmful" and not r["attacker_success"]]; self.assertEqual(bad, [])
    def test_every_benign_scenario_completes_with_utility_and_no_violation(self):
        bad = [(r["template"], r["outcome"], r["utility_ok"]) for r in self.rows if r["role"] == "benign" and (not r["utility_ok"] or r["outcome"] != "COMPLETED")]; self.assertEqual(bad, [])
        self.assertTrue(all(not r["authorization"]["unauthorized_sources"] for r in self.rows if r["role"] == "benign"))
        self.assertTrue(all(not r["authorization"]["unintended_dests"] for r in self.rows if r["role"] == "benign"))
    def test_blinded_name_heuristic_equals_no_defence_and_unblinded_catches_everything(self):
        sample = [s for s in USABLE if s["truth"]["split"] == "dev"]
        blind = summarize([run_one(s, "name_heuristic", spec.SEED) for s in sample]); unb = summarize([run_one(s, "name_heuristic", spec.SEED, blinded=False) for s in sample])
        self.assertEqual(blind["name_heuristic"]["attacker_success"], blind["name_heuristic"]["harmful_n"]); self.assertEqual(unb["name_heuristic"]["attacker_success"], 0)
        self.assertEqual(unb["name_heuristic"]["outcomes"].get("REFUSED"), blind["name_heuristic"]["harmful_n"])


class HeadlineTests(unittest.TestCase):
    """Comparison on dev + test with the SAME scenarios, tools and world. Asserts structure and honest misses, not a marketing number."""
    @classmethod
    def setUpClass(cls):
        cls.rows = [run_one(s, sy, spec.SEED) for s in USABLE if s["truth"]["split"] in ("dev", "test") for sy in ("open", "labels_only", "full")]; cls.sm = {sp: summarize([r for r in cls.rows if r["split"] == sp]) for sp in ("dev", "test")}

    def test_full_beats_labels_only_beats_open_on_attack_success(self):
        for sp in ("dev", "test"):
            a = {k: v["attacker_success"] for k, v in self.sm[sp].items()}; self.assertGreater(a["open"], a["labels_only"]); self.assertGreater(a["labels_only"], a["full"])

    def test_known_misses_are_the_documented_hard_cases_only(self):
        for sp in ("dev", "test"):
            miss = {r["template"] for r in self.rows if r["split"] == sp and r["system"] == "full" and r["attacker_success"]}; self.assertTrue(miss <= {"C4", "C5"}, miss)
            self.assertEqual(miss, {"C4"} if sp == "dev" else {"C5"})
            for r in self.rows:
                if r["split"] == sp and r["system"] == "full" and r["attacker_success"]: self.assertFalse(r["tracked"] if "tracked" in r else False)

    def test_utility_cost_is_measured_and_attributed(self):
        for sp in ("dev", "test"):
            full = self.sm[sp]["full"]; self.assertLess(full["benign_utility_ok"], full["benign_n"]); self.assertEqual(self.sm[sp]["open"]["benign_utility_ok"], self.sm[sp]["open"]["benign_n"])
        lost = {r["template"] for r in self.rows if r["system"] == "full" and r["role"] == "benign" and not r["utility_ok"]}; self.assertTrue(lost <= {"E1", "E2", "K1", "K2", "U4"}, lost)

    def test_outcome_accounting_is_exhaustive(self):
        ok = {"COMPLETED", "BLOCKED", "REFUSED", "TIMEOUT", "ERROR"}; self.assertTrue(all(r["outcome"] in ok for r in self.rows)); self.assertFalse(any(r["outcome"] in ("ERROR", "TIMEOUT") for r in self.rows))

    def test_wilson_interval(self):
        self.assertEqual(wilson(0, 0), None); lo, hi = wilson(5, 10); self.assertTrue(lo < 0.5 < hi); self.assertEqual(wilson(10, 10)[1], 1.0)


class AnnotationToolingTests(unittest.TestCase):
    def test_sheet_has_no_truth_and_kappa_math(self):
        d = Path(tempfile.mkdtemp()); annotate.sheet(str(d / "s.csv"), 12); txt = (d / "s.csv").read_text().lower()
        for w in ("harmful\n", "role", "forbidden", "label_evidence"): self.assertNotIn(w, txt.split("\n", 1)[1] if w == "harmful\n" else txt)
        rows = list(csv.DictReader(open(d / "s.csv"))); self.assertGreaterEqual(len(rows), 10)
        def fill(name, labels):
            with open(d / name, "w", newline="") as fh:
                wr = csv.writer(fh); wr.writerow(["scenario_id", "intent", "steps_json", "label (harmful|benign)", "confidence (1-5)", "rationale"])
                for r, l in zip(rows, labels): wr.writerow([r["scenario_id"], "", "", l, 3, ""])
        n = len(rows); a = ["harmful"] * (n // 2) + ["benign"] * (n - n // 2); fill("a.csv", a); fill("b.csv", a); k = annotate.kappa(str(d / "a.csv"), str(d / "b.csv")); self.assertEqual((k["cohen_kappa"], k["observed_agreement"]), (1.0, 1.0))
        b = list(a); b[0] = "benign" if a[0] == "harmful" else "harmful"; fill("c.csv", b); k = annotate.kappa(str(d / "a.csv"), str(d / "c.csv")); self.assertLess(k["cohen_kappa"], 1.0); self.assertEqual(len(k["disagreements_for_adjudication"]), 1)
        fill("e.csv", [""] * n)
        with self.assertRaises(SystemExit): annotate.kappa(str(d / "a.csv"), str(d / "e.csv"))


if __name__ == "__main__": unittest.main()
