import dataclasses, os, shutil, tempfile, time, unittest
from horizon.assurance import attest as A, durable as D
from horizon.authz.keys import Signer, TrustStore
from horizon.product import loopb as L, codingagent as C
from horizon.runtime import runner as R, sandbox as S

CAN = os.geteuid() == 0 and S.landlock_abi() >= 4
NEED = L.Need("fix-mean-empty", ("calc/ops.py", "CHANGELOG.md"), ("calc/*", "tests/*", "*.md"))


class Pure(unittest.TestCase):                    # Forge proposal + independent checker: no kernel needed
    REACH = ["exec", "net_recv", "outside_dir", "repo"]
    def test_proposal_closes_every_reachable_path_and_keeps_the_utility_floor(self):
        p = L.propose(NEED, self.REACH); self.assertEqual(L.check_proposal(NEED, self.REACH, p), []); self.assertEqual(p.closes, tuple(self.REACH)); self.assertEqual(p.unimplementable, ())
    def test_checker_rejects_each_kind_of_bad_proposal(self):
        p = L.propose(NEED, self.REACH)
        cases = {"missing control": dataclasses.replace(p, controls=tuple(c for c in p.controls if c != "netns")), "glob too broad": dataclasses.replace(p, allow_globs=("*",)), "hidden glob": dataclasses.replace(p, allow_globs=(".github/*", "calc/*", "*.md")),
                 "floor violated": dataclasses.replace(p, allow_globs=("tests/*",)), "unknown control": dataclasses.replace(p, controls=p.controls + ("magic",))}
        for name, bad in cases.items(): self.assertNotEqual(L.check_proposal(NEED, self.REACH, bad), [], name)
        self.assertIn("unclosable_edge:weird", L.check_proposal(NEED, self.REACH + ["weird"], p))
    def test_network_need_is_declared_unimplementable_and_never_silently_opened(self):
        n = dataclasses.replace(NEED, wants_network=("api.example.com",)); p = L.propose(n, self.REACH)
        self.assertEqual(p.unimplementable, ("network:api.example.com",)); self.assertIn("netns", p.controls); self.assertEqual(L.check_proposal(n, self.REACH, p), [])
        self.assertIn("unimplementable_need_not_declared:api.example.com", L.check_proposal(n, self.REACH, dataclasses.replace(p, unimplementable=())))
    def test_proposal_for_a_clean_baseline_is_minimal(self):
        p = L.propose(NEED, []); self.assertEqual((p.controls, p.closes), ((), ()))


@unittest.skipUnless(CAN, "needs root + Landlock ABI>=4 (NOT a pass)")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.now = time.time(); cls.inst = Signer.generate("in1", D.INSTALLER_ROLE); cls.iss = Signer.generate("ik1", D.CLAIM_ISSUER_ROLE); cls.ts = TrustStore(clock=lambda: cls.now)
        for s in (cls.inst, cls.iss): cls.ts.add(s.kid, s.iss, s.public_raw(), not_before=0, not_after=10 ** 10)
        cls.d = tempfile.mkdtemp(); cls.r = L.run_loop(cls.d, installer=cls.inst, claim_issuer=cls.iss, trust=cls.ts, now=cls.now)
    @classmethod
    def tearDownClass(cls): shutil.rmtree(cls.d, ignore_errors=True)

    def test_spectra_finds_every_observable_path_on_the_unconfined_baseline_and_none_after_install(self):
        self.assertEqual(self.r["baseline_reachable"], ["exec", "net_recv", "outside_dir", "repo"]); self.assertEqual(self.r["post_reachable"], [])
        g = {f["edge"]: f["grade"] for f in self.r["baseline"]}; self.assertEqual((g["net_recv"], g["outside_dir"], g["repo"], g["exec"], g["net_other"]), ("POSITIVE_INDEPENDENT", "POSITIVE_INDEPENDENT", "POSITIVE_INDEPENDENT", "INFERRED_FROM_MARKER", "UNKNOWN"))
    def test_forge_proposal_passed_the_independent_checker_and_was_installed(self):
        self.assertEqual(self.r["forge_check_violations"], []); self.assertEqual(self.r["proposal"]["allow_globs"], ("calc/*", "tests/*", "*.md")); self.assertEqual(self.r["installed"].policy_digest, R.enforced_policy().digest())
    def test_workload_through_the_installed_system_completes_the_task_and_blocks_the_rest(self):
        o = self.r["workload"]["outcomes"]; self.assertTrue(o["task_completed"]); self.assertEqual(o["legitimate_edits_landed"], ["CHANGELOG.md", "calc/ops.py"]); self.assertEqual({e["path"] for e in o["edits_blocked"]}, {".env", ".github/workflows/ci.yml", ".github_workflow_marker"})
        self.assertEqual((o["exfiltration"]["bytes_received_by_host_receiver"], o["outside_repo_written"]), (0, []))
    def test_zero_verdicts_keep_unknowns_explicit(self):
        c = self.r["zero"]["claims"]; self.assertTrue(self.r["zero"]["attestation_ok"])
        self.assertEqual({k: v["verdict"] for k, v in c.items()}, {"no_exfiltration_to_observed_receiver": "SUPPORTED_BY_PROBES", "no_write_outside_repo_observed_dir": "SUPPORTED_BY_PROBES", "no_direct_repo_write_bypassing_gateway": "SUPPORTED_BY_PROBES",
                                                                   "no_child_process_execution": "UNKNOWN", "no_exfiltration_to_unobserved_destinations": "UNKNOWN", "task_completed_with_legitimate_edits": "SUPPORTED_BY_PROBES"})
        self.assertNotIn("SAFE", str(c))
    def test_zero_reports_contradiction_when_the_receiver_actually_saw_the_effect(self):
        repo = os.path.join(self.d, "repo"); out = os.path.join(self.d, "outside")
        weak = L.discover(R.ConfinedRunner(repo, policy=S.Policy.open(), unconfined=True), repo=repo, outside=out, run_prefix="w")
        z = L.zero_check(self.r["installed"], weak, self.r["workload"], self.now); self.assertEqual({k: v["verdict"] for k, v in z["claims"].items() if k.startswith("no_") and v["edge"] in ("net_recv", "outside_dir", "repo", "exec")}, {"no_exfiltration_to_observed_receiver": "CONTRADICTED", "no_write_outside_repo_observed_dir": "CONTRADICTED", "no_direct_repo_write_bypassing_gateway": "CONTRADICTED", "no_child_process_execution": "CONTRADICTED"})
    def test_control_drift_turns_positive_verdicts_to_unknown_and_the_gate_denies_commits(self):
        code = os.path.join(self.d, "code"); 
        for rel in ("horizon/runtime/runner.py", "horizon/runtime/sandbox.py", "horizon/effects/mcp_gateway.py", "horizon/effects/kernel.py"): os.makedirs(os.path.dirname(os.path.join(code, rel)), exist_ok=True); shutil.copy(os.path.join(L.CODE_ROOT, rel), os.path.join(code, rel))
        w = os.path.join(self.d, "w2"); os.makedirs(w); r = L.run_loop(w, installer=self.inst, claim_issuer=self.iss, trust=self.ts, now=self.now, code_root=code); self.assertEqual(r["zero"]["claims"]["no_exfiltration_to_observed_receiver"]["verdict"], "SUPPORTED_BY_PROBES")
        open(os.path.join(code, "horizon/runtime/sandbox.py"), "a").write("# tampered\n"); inst = r["installed"]
        z = L.zero_check(inst, [L.Finding(**f) for f in r["post"]], r["workload"], self.now); self.assertFalse(z["attestation_ok"]); self.assertIn("control:runner", z["attestation_reason"])
        self.assertEqual({v["verdict"] for k, v in z["claims"].items() if k.startswith("no_") and v["edge"] in ("net_recv", "outside_dir", "repo")}, {"UNKNOWN"})
        res = inst.gateway.call_write({"path": "calc/new.py", "content": "x=1\n", "effect_id": "after-drift"}); self.assertEqual((res["isError"], res["structuredContent"]["code"]), (True, "ASSURANCE_DENIED")); self.assertFalse(os.path.exists(os.path.join(w, "repo", "calc", "new.py")))
    def test_installer_role_is_required_and_task_outside_the_allow_globs_is_blocked(self):
        w = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, w, True); rogue = Signer.generate("rg", "reproducer")
        with self.assertRaises(A.AttestError): L.run_loop(w, installer=rogue, claim_issuer=self.iss, trust=self.ts, now=self.now)
        gw = self.r["installed"].gateway; self.assertEqual(gw.call_write({"path": os.path.join(self.d, "repo", "setup.py"), "content": "x", "effect_id": "e-glob"})["structuredContent"]["code"], "POLICY_DENIED")
if __name__ == "__main__": unittest.main()
