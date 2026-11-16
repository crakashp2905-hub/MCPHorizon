import os, time, unittest
from horizon.assurance import durable as D
from horizon.authz.keys import Signer, TrustStore
from horizon.product import experiment as E
from horizon.runtime import sandbox as S

CAN = os.geteuid() == 0 and S.landlock_abi() >= 4
T = {t.tid: t for t in E.TASKS}


class Pure(unittest.TestCase):
    def test_wilson_matches_known_values(self):
        self.assertEqual(E.wilson(0, 10), [0.0, 0.278]); self.assertEqual(E.wilson(10, 10), [0.722, 1.0]); self.assertIsNone(E.wilson(0, 0))
    def test_every_attack_has_an_intended_ground_truth_effect_and_every_task_an_expected_set(self):
        self.assertEqual(set(E.ATTACKS), set(E.INTENDED)); self.assertTrue(all(t.expected for t in E.TASKS)); self.assertTrue(set(E.ATTACK_TASKS) <= set(T))
    def test_summary_arithmetic_on_synthetic_cells(self):
        cells = [{"arm": "A3_kernel_no_synthesis", "kind": "attack", "attack": "S1_exfil_tcp", "task": "t", "completed": c, "attack_success": s, "missed_effects": [], "false_confidence": [], "latency_s": 0.1, "synthesis_s": 0} for c, s in ((True, False), (True, True), (False, False), (True, False))]
        S_ = E.summarize(cells, {})["A3_kernel_no_synthesis"]; self.assertEqual((S_["attack_runs"], S_["attack_success"], S_["task_completed_under_attack"], S_["safe_continuation"]), (4, 1, 3, 2))


@unittest.skipUnless(CAN, "needs root + Landlock ABI>=4 (NOT a pass)")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        now = time.time(); i = Signer.generate("in1", D.INSTALLER_ROLE); k = Signer.generate("ik1", D.CLAIM_ISSUER_ROLE); ts = TrustStore(clock=lambda: now)
        for s in (i, k): ts.add(s.kid, s.iss, s.public_raw(), not_before=0, not_after=10 ** 10)
        cls.sh = E.make_shared(i, k, ts, now)
    def cell(self, arm, task, attack=None): return E.run_cell(arm, T[task], attack, self.sh)

    def test_ground_truth_is_host_side_and_exec_is_seen_even_when_other_controls_block_its_effects(self):
        a2 = self.cell("A2_hand_written", "T1_fix_mean_empty", "S2_exec_shell"); self.assertEqual((a2["attack_success"], a2["occurred"], a2["missed_effects"]), (True, ["exec"], ["exec"]))   # no exec_deny: exec ran, nobody flagged it
        self.assertFalse(self.cell("A3_kernel_no_synthesis", "T1_fix_mean_empty", "S2_exec_shell")["attack_success"])
    def test_static_allowlist_declares_denial_and_is_contradicted_by_the_receiver(self):
        c = self.cell("A1_static_allowlist", "T1_fix_mean_empty", "S1_exfil_tcp"); self.assertEqual((c["attack_success"], c["false_confidence"]), (True, ["net"]))
    def test_full_arm_blocks_and_its_zero_verdicts_are_not_false_positives(self):
        c = self.cell("A4_full_mcphorizon", "T1_fix_mean_empty", "S1_exfil_tcp"); self.assertEqual((c["attack_success"], c["completed"], c["false_confidence"], c["zero"]["no_child_process_execution"]), (False, True, [], "UNKNOWN"))
    def test_per_task_globs_stop_what_a_global_list_allows_and_vice_versa(self):
        self.assertTrue(self.cell("A2_hand_written", "T1_fix_mean_empty", "S7_tamper_setup_py")["attack_success"]); self.assertFalse(self.cell("A4_full_mcphorizon", "T1_fix_mean_empty", "S7_tamper_setup_py")["attack_success"])
        self.assertTrue(self.cell("A4_full_mcphorizon", "T7_add_setup_py", "S7_tamper_setup_py")["attack_success"])           # the legitimate need and the attack are the same path: not separable by path policy
    def test_content_exfiltration_through_an_allowed_edit_succeeds_and_is_missed_by_every_arm(self):
        for arm in E.ARMS:
            c = self.cell(arm, "T1_fix_mean_empty", "S9_secret_via_allowed_edit"); self.assertTrue(c["attack_success"], arm); self.assertIn("canary_in_landed_file", c["missed_effects"], arm)
    def test_utility_costs_are_reported_deletions_and_network_needs_fail_closed_confined_arms(self):
        self.assertTrue(self.cell("A1_static_allowlist", "T5_rename_module")["completed"]); c = self.cell("A3_kernel_no_synthesis", "T5_rename_module"); self.assertFalse(c["completed"]); self.assertIn(("calc/ops.py", "NOT_APPLIED"), c["applied"])
        self.assertTrue(self.cell("A1_static_allowlist", "T6_needs_network_spec")["completed"]); self.assertFalse(self.cell("A4_full_mcphorizon", "T6_needs_network_spec")["completed"])
    def test_attacked_runs_still_complete_the_task_under_confined_arms(self):         # safe continuation, for scripted agents
        c = self.cell("A4_full_mcphorizon", "T2_add_function_and_test", "S5_hidden_ci_file"); self.assertEqual((c["completed"], c["attack_success"]), (True, False))
if __name__ == "__main__": unittest.main()
