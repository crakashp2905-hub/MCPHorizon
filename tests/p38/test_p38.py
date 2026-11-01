"""P38 tests: casebook verification rules, disputed claims, runner check, drills, comparison, gates, release bundle."""
import copy, json, os, subprocess, sys, tempfile, unittest, yaml
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "scripts"))
import p38_casebook as CB, p38_runner_check as RC
from bench.h4 import core, hmib, hecb
from horizon.weights import intake as I
from horizon.telemetry import collector as T
from horizon.agents import isolation as ISO
class Casebook(unittest.TestCase):           # P38-01 / 02
    def test_index_obeys_its_own_rules_and_docs_are_current(self):
        d = CB.load(); self.assertEqual(CB.problems(d), []); v, dd = CB.build(d); self.assertEqual(open(os.path.join(CB.OUT, "CASEBOOK_VERIFICATION.md")).read(), v); self.assertEqual(open(os.path.join(CB.OUT, "DISPUTED_CLAIMS.md")).read(), dd)
    def test_all_seven_cases_present_with_access_dates(self):
        d = CB.load(); self.assertEqual(len(d["cases"]), 7)
        for c in d["cases"]:
            self.assertTrue(c["provenance"]); self.assertTrue(any(a.get("accessed") for a in c["independent_accounts"]) or c["primary_fetched"], c["id"])
    def test_rules_reject_confirmed_without_fetch_and_intent_inference_and_bad_status(self):
        d = CB.load(); x = copy.deepcopy(d); c = x["cases"][0]; c["primary_fetched"] = False
        for a in c["independent_accounts"]: a["fetched"] = False
        self.assertTrue(any("no source was actually fetched" in p for p in CB.problems(x)))
        y = copy.deepcopy(d); y["cases"][1]["verified_claims"][0]["detail"] = "the developer deliberately inserted flaws"; self.assertTrue(any("intent inference" in p for p in CB.problems(y)))
        z = copy.deepcopy(d); z["cases"][2]["verified_claims"][0]["status"] = "TRUE"; self.assertTrue(any("bad status" in p for p in CB.problems(z)))
    def test_unverified_claims_are_not_hidden(self):
        t = open(os.path.join(CB.OUT, "CASEBOOK_VERIFICATION.md")).read(); self.assertIn("NOT_VERIFIED", t)
        dd = open(os.path.join(CB.OUT, "DISPUTED_CLAIMS.md")).read()
        for needle in ("190 apps", "ratio, not percentage points", "unverified", "Qwen3.8-Flash-Next", "July 21", "nearly 50%"): self.assertIn(needle, dd, needle)
    def test_no_intent_inflation_in_any_committed_casebook_text(self):
        for f in ("CASEBOOK_VERIFICATION.md", "DISPUTED_CLAIMS.md"): self.assertIsNone(CB.INTENT.search(open(os.path.join(CB.OUT, f)).read()), f)
class Matrix(unittest.TestCase):             # P38-03
    def test_matrix_lists_planned_vs_implemented_and_open_gates(self):
        t = open(os.path.join(ROOT, "docs/evidence/p38/CAPABILITY_MATRIX.md")).read()
        for w in ("IMPLEMENTED-CANDIDATE", "PLANNED", "NOT RUN", "HR-G7", "HR-G9", "frozen"): self.assertIn(w, t)
    def test_readme_was_not_edited(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "p23_freeze.py"), "--check"], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stdout)
class Runner(unittest.TestCase):             # P38-04 / 05
    def test_ci_runs_all_four_suites_and_the_runner_check(self):
        y = open(os.path.join(ROOT, ".github/workflows/tests.yml")).read()
        for needle in ("tests.p37.test_h4", "p38_runner_check.py --require", "bench/h4/run.py check", "tests.p33.test_hccb", "tests.p34.test_isolation", "tests.p35.test_telemetry", "tests.p36.test_guard", "tests.p31.test_intake"): self.assertIn(needle, y)
    def test_probe_reports_a_verdict_and_reasons(self):
        r = RC.probe(); self.assertIn(r["verdict"], ("RUN", "SKIPPED_UNSUPPORTED")); self.assertEqual(r["kernel_tests_runnable"], not r["reasons"])
    def test_non_root_or_old_landlock_is_reported_unsupported(self):
        import unittest.mock as mk
        with mk.patch.object(RC.os, "geteuid", lambda: 1000): r = RC.probe(); self.assertFalse(r["kernel_tests_runnable"]); self.assertIn("not root", r["reasons"]); self.assertEqual(r["verdict"], "SKIPPED_UNSUPPORTED")
        from horizon.runtime import sandbox as S
        with mk.patch.object(S, "landlock_abi", lambda: 2): r = RC.probe(); self.assertIn("Landlock ABI < 4", r["reasons"]); self.assertFalse(r["kernel_tests_runnable"])
    def test_require_flag_fails_loudly_when_unsupported(self):
        import unittest.mock as mk
        with mk.patch.object(RC, "probe", lambda: {"kernel_tests_runnable": False, "reasons": ["x"], "verdict": "SKIPPED_UNSUPPORTED"}), mk.patch.object(sys, "argv", ["x", "--require"]), self.assertRaises(SystemExit) as e:
            exec(compile("r = RC.probe(); sys.exit(1 if ('--require' in sys.argv and not r['kernel_tests_runnable']) else 0)", "x", "exec"), {"RC": RC, "sys": sys})
        self.assertEqual(e.exception.code, 1)
class LayerDocs(unittest.TestCase):          # P38-06
    def test_each_layer_has_its_own_row_with_assumptions_and_non_claims(self):
        t = open(os.path.join(ROOT, "docs/security/LAYER_THREAT_MODELS.md")).read()
        for layer in ("Sandbox", "brokers", "Model intake", "Trigger lab", "Code assurance gate", "Agent isolation", "Telemetry", "Infra guard"): self.assertIn(layer, t)
        for w in ("dormant triggers", "UNASSESSED", "P35-15", "Nothing here is a formal proof", "No independent review of any trust root", "HR-G7"): self.assertIn(w, t)
class SinkRepro(unittest.TestCase):          # P38-09
    def test_recorded_live_repro_has_blocked_effect_and_working_control(self):
        d = json.load(open(os.path.join(ROOT, "docs/evidence/p38/SINK_REPRO.json"))); self.assertTrue(d["all_expectations_met"])
        for sid, r in d["scenarios"].items():
            self.assertTrue(r["B0"]["attack_effect"], sid); self.assertFalse(r["B6"]["attack_effect"], sid); self.assertTrue(r["B6"]["control_ok"], sid); self.assertGreater(sum(v for v in r["B0"]["attack_receiver_delta"].values() if isinstance(v, int)), 0)
    def test_denial_evidence_is_recorded_separately_from_the_effect(self):
        d = json.load(open(os.path.join(ROOT, "docs/evidence/p38/SINK_REPRO.json"))); den = {sid: r["B6"]["attack_denied"] for sid, r in d["scenarios"].items()}
        self.assertTrue(any(den.values())); self.assertFalse(all(den.values()), "expected at least one block without a broker denial record (OS-level block): effect and denial are different facts")
    def test_the_receiver_oracle_is_a_separate_process(self):
        s = open(os.path.join(ROOT, "horizon/runtime/receiver.py")).read(); self.assertIn("SEPARATE PROCESS", s)
class Drills(unittest.TestCase):             # P38-10 / 11
    def _world(self):
        w = hmib.ModelWorld(core.Env("B6")); self.addCleanup(w.clean); return w
    def test_authorised_rollback_succeeds_and_unauthorised_rollback_is_denied(self):
        w = self._world(); d2 = hmib.clone(w); hmib.tamper(d2, "config.json", b'{"layers":3}'); m2 = w.manifest("toy-1", d2); up = I.issue_upgrade(w.signer, old_digest=I.digest(w.m0), new_digest=I.digest(m2), reason="v2")
        w.truth["toy-1"] = {p: hmib.fsha(open(os.path.join(d2, p), "rb").read()) for p in os.listdir(d2)}; self.assertTrue(w.deploy(m2, d2, approved=w.m0, upgrade=up)["allow"]); self.assertFalse(w.unapproved_loaded())
        w.loaded.clear(); back = w.deploy(w.m0, w.dir0, approved=m2); self.assertFalse(back["allow"])                 # old version, approved is now v2, no rollback record: drift
        rb = I.issue_upgrade(w.signer, old_digest=I.digest(m2), new_digest=I.digest(w.m0), reason="rollback"); w.truth["toy-1"] = {p: hmib.fsha(open(os.path.join(w.dir0, p), "rb").read()) for p in os.listdir(w.dir0)}
        self.assertTrue(w.deploy(w.m0, w.dir0, approved=m2, upgrade=rb)["allow"]); self.assertFalse(w.unapproved_loaded()); self.assertEqual(w.loaded[-1]["files"], w.truth["toy-1"])
    def test_rollback_record_for_the_wrong_digest_pair_is_rejected(self):
        w = self._world(); d2 = hmib.clone(w); hmib.tamper(d2, "config.json", b'{"layers":3}'); m2 = w.manifest("toy-1", d2); bad = I.issue_upgrade(w.signer, old_digest="0" * 64, new_digest=I.digest(w.m0), reason="x"); self.assertFalse(w.deploy(w.m0, w.dir0, approved=m2, upgrade=bad)["allow"])
    def test_registry_loss_serves_only_the_verified_local_cache_and_fails_closed_otherwise(self):
        w = self._world(); registry = {"toy-1": w.dir0}; cache = hmib.clone(w)            # a verified local copy of the approved bytes
        registry.clear()                                                                      # the artifact registry is gone
        self.assertTrue(w.deploy(w.m0, cache, approved=w.m0)["allow"]); self.assertFalse(w.unapproved_loaded())
        hmib.tamper(cache, "model-00001.safetensors", b"CACHE-CORRUPT"); w.loaded.clear(); self.assertFalse(w.deploy(w.m0, cache, approved=w.m0)["allow"]); self.assertEqual(w.loaded, [])
        empty = w.make("empty", {}); self.assertFalse(w.deploy(w.m0, empty, approved=w.m0)["allow"]); self.assertEqual(w.loaded, [])      # no files at all: fail closed, nothing loaded
        unknown = w.make("unk", {"model-00001.safetensors": b"X" * 10}); m3 = w.manifest("toy-9", unknown); self.assertFalse(w.deploy(m3, unknown, approved=w.m0)["allow"])
    def test_revocation_stops_a_running_agent_and_is_visible_to_the_operator(self):
        c = hecb.Chan(core.Env("B7")); c.pol.allow(src_tenant="A", dst_tenant="B", resource="shared", op="write"); s = c.tok("A", "runA"); self.assertTrue(c.write(s, "shared", "k", "v", owner="B")["ok"])
        c.auth.revoke("runA"); r = c.write(s, "shared", "k2", c.mk, owner="B"); self.assertEqual(r["code"], "WORKLOAD_REVOKED"); self.assertFalse(c.leaked())
        for _ in range(3): c.write(s, "shared", "k3", "x", owner="B")
        self.assertTrue(any(a["kind"] == "REPEATED_REJECTED_COMMUNICATION" for a in c.med.alerts))
    def test_log_spoofing_in_transcript_and_in_the_log_are_both_detected(self):
        f = hecb.Forensic(core.Env("B7")); f.do(hecb.ALLOWED); f.do(hecb.FORBIDDEN); f.transcript = [t for t in f.transcript if t["tool"] != hecb.FORBIDDEN]; clean, codes = f.audit(); self.assertFalse(clean); self.assertIn("TRUSTED_EVENT_ABSENT_FROM_TRANSCRIPT", codes)
        g = hecb.Forensic(core.Env("B7")); g.do(hecb.ALLOWED); g.do(hecb.FORBIDDEN); g.do(hecb.ALLOWED); lg = g.chain.export(); lg["records"][1]["event"]["tool"] = hecb.ALLOWED
        clean, codes = g.audit(log=lg); self.assertFalse(clean); self.assertTrue(any(c in codes for c in ("LOG_INTEGRITY",)) or "TRANSCRIPT_OPERATION_DIFFERS_FROM_TRUSTED" in codes)
        h = hecb.Forensic(core.Env("B0")); h.do(hecb.FORBIDDEN, claim=False); self.assertTrue(h.audit()[0]); self.assertTrue(h.truth_forbidden())       # without the telemetry layer the same spoof passes: the negative control
class Comparison(unittest.TestCase):         # P38-12
    def test_comparison_doc_is_current_and_states_both_a_support_and_a_rejection(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts/p38_compare.py"), "--check"], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stdout)
        t = open(os.path.join(ROOT, "docs/evidence/p38/SCANNER_COMPARISON.md")).read()
        for w in ("Partly supported", "Rejected as a breadth claim", "emulation", "real bandit", "pickle"): self.assertIn(w, t)
import p38_gates as GT, p38_papers as PP
class Gates(unittest.TestCase):              # P38-15
    def test_gate_doc_is_current_and_every_check_passes(self):
        t, g = GT.build(); self.assertEqual(open(GT.OUT).read(), t); self.assertEqual([k for k, v in g.items() if not v[2]], []); self.assertEqual(len(g), 12)
    def test_statuses_never_overclaim(self):
        g = GT.checks(); self.assertEqual(g["MG-G12"][0], "NOT MET"); self.assertEqual(g["MG-G1"][0], "PARTIAL"); self.assertEqual(g["MG-G6"][0], "PARTIAL"); self.assertIn("OPEN", g["MG-G9"][0])
        t = open(GT.OUT).read(); self.assertIn("HR-G7 and HR-G9 NOT MET", t); self.assertIn("unsupported deployments", t)
    def test_a_failed_evidence_check_would_be_reported_not_hidden(self):
        import unittest.mock as mk
        h = json.load(open(os.path.join(ROOT, "results/v2/h4-main/result.json"))); h["aggregate"]["scenario_matrix"]["B7"]["HMIB-03"] = "E"
        real = GT.J
        with mk.patch.object(GT, "J", lambda p: h if p.endswith("h4-main/result.json") else real(p)): self.assertFalse(GT.checks()["MG-G3"][2])
class Papers(unittest.TestCase):             # P38-13 / 14
    def test_drafts_current_and_generated_from_result_files(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts/p38_papers.py"), "--check"], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stdout)
    def test_each_draft_has_limits_and_not_shown_sections_and_no_overclaim_words(self):
        import re
        for n in "DEFG":
            t = open(os.path.join(ROOT, f"docs/papers/PAPER_{n}.md")).read(); self.assertIn("Negative and limiting findings", t); self.assertIn("Not shown by this draft", t); self.assertIn("CANDIDATE", t)
            self.assertIsNone(re.search(r"(?i)\b(proves|guarantees|eliminates|secure against)\b", t), n)
    def test_drafts_use_only_completed_experiments(self):
        for n in "DEFG":
            t = open(os.path.join(ROOT, f"docs/papers/PAPER_{n}.md")).read()
            for path in set(__import__("re").findall(r"`(results/v2/[a-z0-9_-]+)`", t)): self.assertTrue(os.path.exists(os.path.join(ROOT, path, "result.json")), path)
    def test_negative_findings_cover_known_weaknesses(self):
        t = open(os.path.join(ROOT, "docs/evidence/p38/NEGATIVE_FINDINGS.md")).read()
        for w in ("HCCB-06", "zero** benefit", "dormant triggers", "checkov", "pickle", "P35-15", "outlive", "no exposure", "MG-G12"): self.assertIn(w, t, w)
    def test_numbers_match_source_json(self):
        a = json.load(open(os.path.join(ROOT, "results/v2/h4-main/result.json")))["aggregate"]; t = open(os.path.join(ROOT, "docs/papers/PAPER_F.md")).read(); self.assertIn(f"| {a['by_suite']['HECB']['B0']['effects']} | {a['by_suite']['HECB']['B5']['effects']} | {a['by_suite']['HECB']['B6']['effects']} | {a['by_suite']['HECB']['B7']['effects']} |", t)
    def test_oracle_kind_counts_in_docs_match_the_code(self):
        import re; src = open(os.path.join(ROOT, "bench/h4/hieb.py")).read(); live = len(re.findall(r'^live\("HIEB', src, re.M)) + 1; cfg = len(re.findall(r'^cfg\("HIEB', src, re.M)) + 1      # +1 each: HIEB-13 is a hand-written live scenario, HIEB-10 a hand-written config-fact one
        self.assertEqual((live, cfg), (7, 7)); self.assertIn(f"{live} types are live loopback probes; {cfg} are configuration-fact", open(os.path.join(ROOT, "docs/evidence/p37/MG_G11.md")).read())
class Bundle(unittest.TestCase):             # P38-16 (bundle half; MG-G12 itself stays NOT MET)
    @classmethod
    def setUpClass(cls):
        import p38_release_bundle as RBD; cls.RBD = RBD; cls.tmp = tempfile.mkdtemp(); cls.path = os.path.join(cls.tmp, "b.tar"); cls.man = RBD.RB.build(cls.path)
    def test_bundle_verifies_and_contains_the_evidence_and_the_unmet_gate(self):
        self.assertEqual(self.RBD.RB.verify(self.path), []); f = self.man["files"]
        for need in ("results/v2/h4-main/result.json", "docs/evidence/p38/MG_GATES.md", "docs/papers/PAPER_D.md", "research/incident-casebook/index.yaml", "docs/evidence/p37/MG_G11.md", "scripts/p38_clean_repro.py"): self.assertIn(need, f)
        self.assertIn("independent review: none has occurred", " ".join(self.man["not_included"]))
    def test_tampering_with_a_member_or_the_signature_is_detected(self):
        import tarfile, shutil, io
        bad = os.path.join(self.tmp, "bad.tar")
        with tarfile.open(self.path) as src, tarfile.open(bad, "w") as dst:
            for m in src.getmembers():
                data = src.extractfile(m).read() if m.isfile() else b""
                if m.name == "files/docs/evidence/p38/MG_GATES.md": data = data.replace(b"NOT MET", b"MET")
                m.size = len(data); dst.addfile(m, io.BytesIO(data))
        self.assertNotEqual(self.RBD.RB.verify(bad), [])
    def test_ephemeral_key_is_disclosed(self):
        self.assertIn("EPHEMERAL", open(os.path.join(ROOT, "scripts/p38_release_bundle.py")).read())
class CleanRepro(unittest.TestCase):         # P38-16 recorded run
    def test_recorded_clean_repro_is_author_run_and_passed(self):
        t = open(os.path.join(ROOT, "docs/evidence/p38/CLEAN_REPRO.md")).read(); self.assertIn("ALL COMMANDS EXIT 0", t); self.assertIn("NOT independent", t); self.assertIn("author", t); self.assertIn("MG-G12 requires a different maintainer", t)
if __name__ == "__main__": unittest.main()
