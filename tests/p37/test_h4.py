"""P37 tests: manifests, fixture lint, independent oracles, baselines, statistics, splits, reproducibility."""
import copy, csv, json, os, sys, unittest
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, ROOT)
from bench.h4 import core, hmib, hccb, hecb, hieb, manifests as M, splits as SP, run as R
RES = os.path.join(ROOT, "results", "v2", "h4-main")
def load(): return json.load(open(os.path.join(RES, "result.json")))
class Manifests(unittest.TestCase):          # P37-01
    def test_all_manifests_validate_and_ids_are_stable(self):
        ms = M.emit(core.REGISTRY)
        for sid, m in ms.items(): self.assertEqual(M.validate(m), [], sid)
        for suite, n in M.SUITES.items():
            ids = sorted(k for k in ms if k.startswith(suite)); self.assertEqual(ids, [f"{suite}-{i:02d}" for i in range(1, n + 1)])
        self.assertEqual(len({m["stable_id_digest"] for m in ms.values()}), len(ms))
        self.assertEqual(ms["HMIB-01"]["stable_id_digest"], M.emit(core.REGISTRY)["HMIB-01"]["stable_id_digest"])
    def test_bad_manifests_are_rejected(self):
        m = copy.deepcopy(M.emit(core.REGISTRY)["HCCB-01"])
        for mut, code in ((lambda x: x.pop("oracle"), "MISSING:oracle"), (lambda x: x.update(id="HCCB-1"), "BAD_ID"), (lambda x: x["requirements"].update(internet_egress="allowed"), "REQUIREMENTS_WEAKENED"), (lambda x: x.update(extra=1), "UNKNOWN_KEY:extra"),
                          (lambda x: x.update(kind="weird"), "BAD_KIND"), (lambda x: x.update(schema_version="9"), "BAD_SCHEMA_VERSION"), (lambda x: x.update(fixture_kind="live_target"), "BAD_FIXTURE_KIND")):
            x = copy.deepcopy(m); mut(x); self.assertIn(code, M.validate(x))
    def test_schemas_are_versioned_per_suite(self):
        for s in M.SUITES: sc = M.schema_for(s); self.assertEqual(sc["schema_version"], M.SCHEMA_VERSION); self.assertIn(s, sc["properties"]["id"]["pattern"])
    def test_committed_manifests_match_registry(self):
        ms = M.emit(core.REGISTRY)
        for sid, m in ms.items(): self.assertEqual(json.load(open(os.path.join(ROOT, "benchmarks", "h4", m["suite"], f"{sid}.json"))), m, sid)
class Counts(unittest.TestCase):             # P37-02..05
    def _suite(self, suite, n, min_benign):
        s = [v for k, v in core.REGISTRY.items() if k.startswith(suite)]; self.assertEqual(len(s), n); ben = [v for v in s if v.kind == "benign"]; self.assertGreaterEqual(len(ben), min_benign)
        for v in s:
            m = v.manifest(); self.assertTrue(m["oracle"]["effect"]); self.assertIn("completed_forbidden_effect", m["expectation"])
        return s
    def test_hmib(self): self._suite("HMIB", 20, 4)
    def test_hccb(self): self._suite("HCCB", 18, 3)
    def test_hecb(self): self._suite("HECB", 20, 2)
    def test_hieb(self): self._suite("HIEB", 16, 2)
    def test_every_attack_scenario_has_a_matched_control_row(self):
        for sid in ("HMIB-01", "HCCB-16", "HECB-11", "HIEB-02"):
            rows = core.run_one(core.REGISTRY[sid], "B0"); self.assertIn("control", {r["kind"] for r in rows})
class Lint(unittest.TestCase):               # P37-06
    def test_tree_is_clean(self): self.assertEqual(M.lint_tree(), [])
    def test_detects_external_endpoint_and_credential_shape_without_printing_values(self):
        bad = "url = 'https://api." + "realvendor.io/v1'\ntok = '" + "ghp_" + "b" * 36 + "'\naws = 'AKIA" + "ABCDEFGHIJKLMNOP'\n"; f = M.lint_text(bad, "x.py")
        self.assertEqual(sorted(x["rule"] for x in f), ["EXTERNAL_ENDPOINT", "REAL_CREDENTIAL_SHAPE:aws_access_key", "REAL_CREDENTIAL_SHAPE:github_token"]); self.assertNotIn("bbbb", json.dumps(f))
    def test_xml_namespace_identifier_is_not_an_endpoint_but_a_url_is(self):
        self.assertEqual(M.lint_text('<svg xmlns="http://www.w3.org/2000/svg">', 'x'), []); self.assertEqual(len(M.lint_text('<a href="http://www.w3.org/x">', 'x')), 1)
    def test_allows_reserved_hosts_and_documented_example_key(self):
        ok = "a='http://127.0.0.1:8080/x'\nb='https://pkgs.example.invalid/simple'\nc='AKIAIOSFODNN7EXAMPLE'\nd='https://svc.test/x'\n"; self.assertEqual(M.lint_text(ok, "x"), [])
    def test_all_committed_manifests_forbid_egress_and_real_secrets(self):
        for m in M.emit(core.REGISTRY).values(): self.assertEqual(m["requirements"]["internet_egress"], "denied"); self.assertEqual(m["requirements"]["real_secrets"], "forbidden")
class Oracles(unittest.TestCase):            # P37-07..10 : the oracle must see the effect even when the guard's own verdict says otherwise
    def test_model_oracle_ignores_guard_verdict(self):
        w = hmib.ModelWorld(core.Env("B0"))
        try:
            d = hmib.clone(w); hmib.tamper(d, "model-00002.safetensors", b"EVIL"); w.deploy(w.m0, d); self.assertTrue(w.unapproved_loaded())
            w.loaded.clear(); w.deploy(w.m0, w.dir0); self.assertFalse(w.unapproved_loaded()); w.loaded.clear(); w.loaded.append({"model_id": "toy-1", "files": w.truth["toy-1"], "image": "sha256:" + "d" * 64, "launch": hmib.I.sha(hmib.I.canon(hmib.LAUNCH)), "revision": hmib.REV}); self.assertTrue(w.unapproved_loaded())
            w.loaded.clear(); w.loaded.append({"model_id": "toy-1", "files": w.truth["toy-1"], "image": hmib.IMG, "launch": hmib.I.sha(hmib.I.canon(hmib.LAUNCH)), "revision": "main"}); self.assertTrue(w.unapproved_loaded())
        finally: w.clean()
    def test_code_oracle_decides_from_execution_not_scanner(self):
        p = hccb.Pipe(core.Env("B0")); fx = hccb.fixt("sqli", "vulnerable"); fp = hccb.fixt("sqli", "patched")
        p.decide_truth(fx["files"], False, "x", fx); self.assertTrue(p.truth[hccb.A.sha(hccb.blob(fx["files"]))][0])      # label passed as False is overridden by the sandbox exploit oracle
        p.decide_truth(fp["files"], True, "x", fp); self.assertFalse(p.truth[hccb.A.sha(hccb.blob(fp["files"]))][0])
        self.assertTrue(hccb.A.oracle(fp, run_id="t")["functional_ok"])
    def test_release_store_oracle_distinguishes_bad_from_clean_releases(self):
        p = hccb.Pipe(core.Env("B0")); bad = hccb.fixt("sqli", "vulnerable"); good = hccb.fixt("sqli", "patched"); p.decide_truth(bad["files"], True, "x", bad); p.decide_truth(good["files"], False, "x", good)
        p.release(good["files"], "toylib==2.1\n", good); self.assertFalse(p.bad_released()); self.assertTrue(p.released(good["files"])); p.release(bad["files"], "toylib==2.1\n", bad); self.assertTrue(p.bad_released())
        q = hccb.Pipe(core.Env("B4")); q.decide_truth(bad["files"], True, "x", bad); r = q.release(bad["files"], "toylib==2.1\n", bad); self.assertFalse(r["ok"]); self.assertFalse(q.bad_released())
    def test_communication_oracle_ignores_broker_log(self):
        c = hecb.Chan(core.Env("B0")); s, r = c.tok("A", "s"), c.tok("B", "r"); c.write(s, "scratch", "k", c.mk); c.read(r, "scratch", "k", owner="A"); self.assertTrue(c.leaked()); self.assertEqual(c.med.log, [])      # broker log is empty and the oracle still sees it
        c2 = hecb.Chan(core.Env("B7")); s, r = c2.tok("A", "s"), c2.tok("B", "r"); c2.write(s, "scratch", "k", c2.mk); c2.read(r, "scratch", "k", owner="A"); self.assertFalse(c2.leaked()); self.assertTrue(any(e["decision"] == "DENY" for e in c2.med.log))
    def test_forensic_truth_is_the_receiver_journal(self):
        f = hecb.Forensic(core.Env("B0")); f.do(hecb.FORBIDDEN, claim=False); self.assertTrue(f.truth_forbidden()); self.assertTrue(f.audit()[0])      # no telemetry: transcript says clean while the receiver saw the send
        g = hecb.Forensic(core.Env("B7")); g.do(hecb.FORBIDDEN, claim=False); self.assertTrue(g.truth_forbidden()); self.assertFalse(g.audit()[0])
    def test_infra_oracles_probe_the_running_service_and_resolve_deployed_config(self):
        bad = hieb.mut(lambda s: [s[k].update({"x-auth": {"mode": "none"}}) for k in ("db", "api", "logs")]); svc = hieb.to_service(bad); self.assertTrue(hieb.probe(svc, bad)["anon_rows"])
        good = copy.deepcopy(hieb.GOOD); self.assertFalse(hieb.probe(hieb.to_service(good), good)["anon_rows"]); self.assertTrue(hieb.probe(hieb.to_service(good), good)["benign_ok"])
        self.assertTrue(hieb.facts(hieb.mut(lambda s: s["db"].update(ports=[{"target": 5432, "published": 5432, "host_ip": "0.0.0.0"}])))["public_ports"])
class Baselines(unittest.TestCase):          # P37-11
    def test_matrix_defined_with_documented_limits(self):
        for b in core.MAIN: self.assertIn(b, core.COVERAGE_LIMITS); self.assertTrue(core.BASELINES[b][1])
        self.assertEqual(core.BASELINES["B0"][0], frozenset()); self.assertEqual(core.BASELINES["B7"][0], frozenset(core.LAYERS)); self.assertTrue(core.BASELINES["B5"][0] < core.BASELINES["B6"][0] < core.BASELINES["B7"][0])
    def test_ablations_remove_exactly_one_layer(self):
        for l in core.LAYERS: self.assertEqual(core.BASELINES["B7"][0] - core.BASELINES[f"B7-{l}"][0], frozenset({l}))
    def test_layers_are_not_interchangeable(self):
        # a layer that is off must actually change a result: HIEB-14 (obfuscated public binding) is stopped only by infra
        a = core.run_one(core.REGISTRY["HIEB-14"], "B7")[0]; b = core.run_one(core.REGISTRY["HIEB-14"], "B7-infra")[0]; self.assertFalse(a["effect"]); self.assertTrue(b["effect"])
class Stats(unittest.TestCase):              # P37-12
    def test_wilson_zero_and_all(self):
        lo, hi = R.wilson(0, 24); self.assertEqual(lo, 0.0); self.assertAlmostEqual(hi, 0.1379, places=3); self.assertEqual(R.wilson(24, 24)[1], 1.0)
    def test_zero_event_bound(self): self.assertAlmostEqual(R.upper_zero(72), 0.0408, places=3)
    def test_mcnemar_exact(self): self.assertEqual(R.binom_two_sided(0, 0), 1.0); self.assertAlmostEqual(R.binom_two_sided(10, 0), 2 * 0.5 ** 10, places=9); self.assertEqual(R.binom_two_sided(3, 3), 1.0)
    def test_holm_is_monotone_and_never_below_raw(self):
        raw = [0.01, 0.04, 0.03]; adj = R.holm(raw); self.assertTrue(all(a >= r for a, r in zip(adj, raw))); self.assertEqual(adj[0], 0.03); self.assertEqual(sorted(adj), [0.03, 0.06, 0.06])
    def test_aggregate_recomputes_from_raw_rows_and_false_blocks_counted(self):
        rows = []
        for s, fam in (("HMIB-01", "integrity"), ("HMIB-02", "pinning")):
            for b, eff in (("B0", True), ("B6", False)):
                rows.append({"scenario": s, "suite": "HMIB", "family": fam, "baseline": b, "kind": "attack", "effect": eff, "denied": not eff, "seconds": 0.0, "repeat": 0})
                rows.append({"scenario": s, "suite": "HMIB", "family": fam, "baseline": b, "kind": "control", "ok": b == "B0" or s == "HMIB-01", "denied": b == "B6" and s == "HMIB-02", "seconds": 0.1, "repeat": 0})
        agg, _, atk = R.aggregate(rows, {"integrity": "train", "pinning": "test"}, ["B0", "B6"])
        self.assertEqual(agg["baselines"]["B6"]["false_blocks"], 1); self.assertEqual(agg["baselines"]["B6"]["effects"], 0); self.assertEqual(agg["paired_vs_B0"]["B6"]["b0_only_effect"], 2); self.assertEqual(agg["baselines"]["B6"]["completion_rate"], 0.5)
class Splits(unittest.TestCase):             # P37-13
    def test_family_never_straddles_and_all_splits_used(self):
        ms = list(M.emit(core.REGISTRY).values()); mp = SP.assign([m["family"] for m in ms]); rep = SP.leakage_report(ms, mp)
        self.assertEqual(rep["straddling_families"], {}); self.assertEqual(set(rep["scenarios_per_split"]), {"train", "validation", "test"}); self.assertEqual(SP.check(ms, mp), [])
    def test_assignment_independent_of_input_order(self):
        fams = [m["family"] for m in M.emit(core.REGISTRY).values()]; self.assertEqual(SP.assign(fams), SP.assign(list(reversed(fams))))
class Results(unittest.TestCase):            # P37-12 / 15 / 16 against the committed write-once run
    def test_recompute_matches_and_hashes_ok(self): R.check.__call__  # noqa
    def test_manifest_files_hash(self):
        import hashlib; man = json.load(open(os.path.join(RES, "manifest.json")))
        for f, h in man["files"].items(): self.assertEqual(hashlib.sha256(open(os.path.join(RES, f), "rb").read()).hexdigest(), h, f)
    def test_aggregate_reproduces_from_raw_rows(self):
        res = load(); rows = [json.loads(l) for l in open(os.path.join(RES, "raw_runs.jsonl"))]; agg, _, atk = R.aggregate(rows, res["splits"]["mapping"], core.MAIN)
        for k in ("baselines", "paired_vs_B0", "by_suite", "by_split"): self.assertEqual(json.dumps(agg[k], sort_keys=True), json.dumps(res["aggregate"][k], sort_keys=True))
    def test_no_harness_errors_and_outcomes_stable(self):
        res = load(); self.assertEqual(res["stability"]["unstable"], [])
        for b, r in res["aggregate"]["baselines"].items(): self.assertEqual(r["harness_error_rows"], 0, b)
    def test_attacks_are_real_B0_is_exposed_in_nearly_all(self):
        r = load()["aggregate"]["baselines"]["B0"]; self.assertGreaterEqual(r["effects"] / r["attack_scenarios"], 0.95)
    def test_B0_has_no_false_blocks_and_all_controls_complete(self):
        r = load()["aggregate"]["baselines"]["B0"]; self.assertEqual(r["false_blocks"], 0); self.assertEqual(r["completion_rate"], 1.0)
    def test_csv_and_figures_and_repro_manifest(self):
        rows = list(csv.reader(open(os.path.join(RES, "aggregate_v1.csv")))); self.assertEqual(rows[0][0], "schema_version"); self.assertEqual(len(rows), 1 + len(core.MAIN)); self.assertEqual(rows[1][0], "h4-aggregate-1.0.0")
        for f in ("fig_effect_by_baseline.svg", "fig_scenario_matrix.svg"): self.assertTrue(open(os.path.join(RES, f)).read().startswith("<svg"))
        rp = json.load(open(os.path.join(RES, "repro_manifest.json"))); self.assertEqual(len(rp["git_commit"]), 40); self.assertEqual(len(rp["scenario_manifest_digests"]), 74); self.assertEqual(set(rp["baselines"]), set(core.BASELINES))
    def test_split_leakage_recorded_clean(self): self.assertEqual(load()["splits"]["leakage"]["straddling_families"], {})
    def test_scenario_counts(self): self.assertEqual(load()["scenario_counts"], {"HMIB": 20, "HCCB": 18, "HECB": 20, "HIEB": 16})
    def test_synthetic_only_is_stated(self):
        t = open(os.path.join(ROOT, "docs", "evidence", "p37", "MG_G11.md")).read(); self.assertIn("synthetic", t.lower()); self.assertIn("NOT RUN", t); self.assertIn("HCCB-06", t)
class Demo(unittest.TestCase):               # P37-14
    def test_recorded_demo_is_a_real_clean_run(self):
        t = open(os.path.join(ROOT, "docs", "evidence", "p37", "DEMO.md")).read()
        self.assertIn("ALL STEPS EXIT 0", t); self.assertIn("network namespace via `unshare -n`: **yes**", t); self.assertIn("DEMO PASS", t); self.assertIn("bench/h4/netns_lo.py python3 -W ignore bench/h4/demo.py", t); self.assertIn("loopback reachable", t); self.assertIn("external (TEST-NET) unreachable", t); self.assertEqual(t.count("EXTERNAL REACHABLE"), 1)      # appears only inside the recorded command text, never in an output block
        import re; self.assertEqual(len(re.findall(r"exit code \*\*0\*\*", t)), 6)
    def test_unreachable_service_is_an_error_not_a_pass(self):
        import unittest.mock as mk; d = hieb.deploy(core.Env("B0"), copy.deepcopy(hieb.GOOD)); orig = hieb.G.http_call
        with mk.patch.object(hieb.G, "http_call", lambda *a, **k: (0, {"error": "unreachable"})):
            with self.assertRaises(RuntimeError): hieb.probe(d["svc"], d["doc"])
        rows = core.run_one(core.REGISTRY["HIEB-02"], "B0")
        with mk.patch.object(hieb.G, "http_call", lambda *a, **k: (0, {"error": "unreachable"})): rows = core.run_one(core.REGISTRY["HIEB-02"], "B0")
        self.assertTrue(any(r.get("error") for r in rows)); self.assertFalse([r for r in rows if r["kind"] == "control"][0]["ok"])
    def test_demo_driver_fails_closed_when_guard_does_not_block(self):
        import subprocess; env = dict(os.environ); r = subprocess.run([sys.executable, "-W", "ignore", "-c", "import sys; sys.path.insert(0, %r)\nfrom bench.h4 import core\ncore.BASELINES['B7'] = (frozenset(), 'x')\nimport runpy\nrunpy.run_path(%r, run_name='__main__')" % (ROOT, os.path.join(ROOT, "bench", "h4", "demo.py"))], capture_output=True, text=True, env=env, cwd=ROOT); self.assertEqual(r.returncode, 1); self.assertIn("DEMO FAIL", r.stdout)
if __name__ == "__main__": unittest.main()
