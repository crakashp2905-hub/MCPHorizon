import ast, json, os, re, subprocess, sys, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bench.haa import aggregate as AG, adaptive as AD, modelrunner as MR, meta as MT, run as R
def J(p): return json.load(open(os.path.join(ROOT, p)))
def row(s, b, kind, rep=0, **k): return {"scenario": s, "baseline": b, "kind": kind, "rep": rep, **k}

class Manifest(unittest.TestCase):
    def test_24_scenarios_validate(self):
        sch = J("benchmarks/horizon-agent-anomaly/scenario.schema.json"); req = sch.get("required", [])
        fs = sorted(f for f in os.listdir(os.path.join(ROOT, "benchmarks/horizon-agent-anomaly/scenarios")) if re.match(r"HAA-\d\d\.json", f)); self.assertEqual(len(fs), 24)
        for f in fs:
            d = J("benchmarks/horizon-agent-anomaly/scenarios/" + f)
            for k in req: self.assertIn(k, d, f)
    def test_prereg_not_executed_and_hash_pinned(self):
        pr = J("benchmarks/horizon-agent-anomaly/PREREGISTRATION.json"); self.assertIn("NOT EXECUTED", json.dumps(pr))
        m = J("benchmarks/horizon-agent-anomaly/manifest.json"); self.assertTrue(m)
    def test_l0_l1_all_pass(self):
        for s in MT.META: self.assertTrue(MT.l0(s)["pass"] if isinstance(MT.l0(s), dict) and "pass" in MT.l0(s) else MT.l0(s), s); self.assertTrue(MT.l1(s)["pass"] if isinstance(MT.l1(s), dict) and "pass" in MT.l1(s) else MT.l1(s), s)

class Aggregate(unittest.TestCase):
    def synth(self):
        rows = []
        for s in ("HAA-01", "HAA-02", "HAA-03"):
            for b in ("B0", "B1", "B2", "B3", "B4", "B5", "B6"):
                eff = b in ("B0", "B1") or (b == "B5" and s == "HAA-03")
                rows += [row(s, b, "attack", effect=eff, denied=not eff), row(s, b, "control", ok=True, denied=False)]
        return rows
    def test_synthetic_counts(self):
        g = AG.aggregate(self.synth()); pb = g["per_baseline"]
        self.assertEqual(pb["B0"]["uer"]["k"], 3); self.assertEqual(pb["B6"]["uer"]["k"], 0); self.assertEqual(pb["B5"]["effects"], ["HAA-03"])
        self.assertEqual(g["eligible_by_B0_effect"], ["HAA-01", "HAA-02", "HAA-03"])
    def test_ineligible_when_b0_has_no_effect(self):
        rows = self.synth(); [r.update(effect=False) for r in rows if r["scenario"] == "HAA-02" and r["baseline"] == "B0" and r["kind"] == "attack"]
        g = AG.aggregate(rows); self.assertIn("HAA-02", g["ineligible"]); self.assertNotIn("HAA-02", g["eligible_by_B0_effect"])
    def test_deterministic(self):
        a = json.dumps(AG.aggregate(self.synth()), sort_keys=True); b = json.dumps(AG.aggregate(list(reversed(self.synth()))), sort_keys=True); self.assertEqual(a, b)
    def test_committed_results_reproduce(self):
        for n in ("main",):
            r = subprocess.run([sys.executable, "bench/haa/aggregate.py", f"results/v2/haa-{n}", "--check"], cwd=ROOT, capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
    def test_report_is_current(self):
        r = subprocess.run([sys.executable, "bench/haa/report.py", "--check"], cwd=ROOT, capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stdout)

class Committed(unittest.TestCase):
    def test_write_once_manifests_match_files(self):
        import hashlib
        for n in ("main", "heldout", "adaptive", "latency"):
            d = os.path.join(ROOT, "results/v2/haa-" + n); m = json.load(open(d + "/manifest.json")); self.assertTrue(m["write_once"])
            for f, h in m["files"].items(): self.assertEqual(hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest(), h, f"{n}/{f}")
    def test_outdir_refuses_overwrite(self):
        with self.assertRaises(SystemExit): R.outdir("main")
    def test_raw_rows_have_digests(self):
        for l in open(os.path.join(ROOT, "results/v2/haa-main/raw_runs.jsonl")):
            r = json.loads(l); self.assertIn("raw_trace_digest", r); self.assertEqual(r["layer"], "L2")
    def test_all_baselines_same_eligible_manifest(self):
        rows = [json.loads(l) for l in open(os.path.join(ROOT, "results/v2/haa-main/raw_runs.jsonl"))]
        sets = {b: {r["scenario"] for r in rows if r["baseline"] == b} for b in {r["baseline"] for r in rows}}; self.assertEqual(len({frozenset(v) for v in sets.values()}), 1); self.assertEqual(len(sets), 7)

class Adaptive(unittest.TestCase):
    def test_deterministic_given_seed(self):
        f = lambda code: "urllib" in code and "127.0.0.1" in code
        self.assertEqual(AD.campaign(3, 40, lambda c: "{host}" in c), AD.campaign(3, 40, lambda c: "{host}" in c)); self.assertEqual(AD.campaign(3, 40, f), AD.campaign(3, 40, f))
        self.assertNotEqual([x["channel"] for x in AD.campaign(3, 20, lambda c: False)], [x["channel"] for x in AD.campaign(4, 20, lambda c: False)])
    def test_programs_parse_and_budget_respected(self):
        for c in AD.CHANNELS:
            for f in AD.FORMS: ast.parse(AD.program(c, f).replace("@BAD@", "1").replace("@CAN@", "x").replace("@OK@", "2"))
        self.assertEqual(len(AD.campaign(1, 7, lambda c: False)), 7)
    def test_replans_toward_neighbours_after_failure(self):
        log = AD.campaign(5, 5, lambda c: False); self.assertTrue(any(a["channel"] == b["channel"] or a["form"] == b["form"] for a, b in zip(log, log[1:])))

class ModelRunner(unittest.TestCase):
    def test_live_runner_is_not_available_here(self):
        with self.assertRaises(MR.NotAvailable): MR.LiveModelRunner().propose("x", MR.Checkpoint("m", "0" * 64, "p", 0.0, 1.0, 10, 1, "0" * 64, "0" * 64))
    def test_checkpoint_metadata_required(self):
        with self.assertRaises(ValueError): MR.Checkpoint("", "short", "p", 0.0, 1.0, 10, 1, "0" * 64, "0" * 64).validate()
    def test_no_l3_claims_in_results(self):
        self.assertIn("NOT RUN", json.dumps(J("results/v2/haa-main/result.json")["layers"]["L3"]))

class Safety(unittest.TestCase):
    def test_no_nonlocal_hosts_in_harness(self):
        bad = re.compile(r"https?://(?!pypi\.org|files\.pythonhosted\.org|[a-z.]*example\.(com|net|org)|127\.0\.0\.1|localhost|169\.254\.169\.254|approved\.test|evil\.test|meta\.test|registry\.test|labelled\.test|rebind\.test|partner\.test|anything\.invalid|\{|%|\")[A-Za-z0-9.-]+\.(com|net|org|io|ai|cloud)\b")
        for dp in ("bench/haa", "horizon/runtime"):
            for f in os.listdir(os.path.join(ROOT, dp)):
                if f.endswith(".py"): self.assertIsNone(bad.search(open(os.path.join(ROOT, dp, f)).read()), f)
    def test_no_cohere_hosts(self):
        for dp in ("bench/haa", "horizon/runtime", "scripts"):
            for f in os.listdir(os.path.join(ROOT, dp)):
                if f.endswith(".py") and f != "p30_no_external.py": self.assertNotRegex(open(os.path.join(ROOT, dp, f)).read(), r"cohere\.(com|ai)")
if __name__ == "__main__": unittest.main()
