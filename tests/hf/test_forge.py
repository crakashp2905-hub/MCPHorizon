import dataclasses, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from horizon.forge import checker, synth, worlds
from horizon.forge.ir import Task, Plan, CONTROLS, WITNESSES
ALL_C, ALL_W = tuple(CONTROLS), tuple(WITNESSES)
def T(**k):
    d = dict(data_label="SECRET", aggregate_ok=True, remote_trust="opaque", available_controls=ALL_C, available_witnesses=ALL_W); d.update(k); return Task(**d)
class Forge(unittest.TestCase):
    def test_A_opaque_remote_raw_secret_is_not_certifiable(self):
        t = T(aggregate_ok=False, available_controls=("egress_contract_enforcer",))   # no sandbox, no enclave, remote opaque, raw required
        r = synth.synthesize(t); self.assertEqual(r["result"], "NOT_CERTIFIABLE_WITHIN_MODEL"); self.assertTrue(synth.verify_negative_certificate(t, r))
        self.assertIn("scope", r); self.assertIn("NOT a proof", r["scope"])
    def test_B_relocation_found_and_checked(self):
        t = T(); r = synth.synthesize(t); self.assertEqual(r["result"], "CERTIFIABLE_AFTER_RELOCATION"); self.assertTrue(checker.check(t, r["plan"]))
        self.assertNotEqual(r["plan"].placement, "remote")
    def test_minimal_cost_among_enumerated(self):
        t = T(); r = synth.synthesize(t); best = min(p.cost() for p in synth.enumerate_plans(t) if checker.check(t, p)); self.assertEqual(r["cost"], best)
    def test_public_data_certified_as_is(self):
        t = T(data_label="PUBLIC"); r = synth.synthesize(t); self.assertEqual(r["result"], "CERTIFIED_WITH_SCOPE"); self.assertEqual(r["cost"], 0)
    def test_contracted_remote_with_enforcer_allows_raw(self):
        t = T(remote_trust="contracted", aggregate_ok=False, available_controls=("egress_contract_enforcer",)); r = synth.synthesize(t)
        self.assertEqual(r["plan"], Plan("remote", "raw", ("egress_contract_enforcer",), ())); self.assertEqual(r["result"], "CERTIFIABLE_AFTER_RELOCATION")
    def test_contract_without_enforcer_installed_is_rejected(self):
        t = T(remote_trust="contracted"); self.assertIn("RAW_PROTECTED_DATA_TO_UNENFORCED_REMOTE", checker.violations(t, Plan("remote", "raw", (), ())))
    def test_forged_plan_rejected_by_checker(self):
        t = T(available_controls=()); self.assertFalse(checker.check(t, Plan("local_sandbox", "raw", ("local_sandbox",), ()))); self.assertIn("CONTROL_NOT_AVAILABLE", checker.violations(t, Plan("local_sandbox", "raw", ("local_sandbox",), ())))
    def test_local_sandbox_requires_installed_control(self): self.assertIn("LOCAL_SANDBOX_NOT_INSTALLED", checker.violations(T(), Plan("local_sandbox", "raw", (), ())))
    def test_aggregate_only_if_task_permits(self): self.assertIn("AGGREGATE_NOT_PERMITTED_BY_TASK", checker.violations(T(aggregate_ok=False), Plan("remote", "aggregate", (), ())))
    def test_enclave_needs_attestation(self):
        t = T(); self.assertIn("ENCLAVE_NOT_ATTESTED", checker.violations(t, Plan("attested_enclave", "raw", (), ()))); self.assertTrue(checker.check(t, Plan("attested_enclave", "raw", ("enclave_attestation",), ())))
    def test_unknown_plan_value_fails_closed(self): self.assertEqual(checker.violations(T(), Plan("mars", "raw", (), ())), ["UNKNOWN_PLAN_VALUE"])
    def test_unknown_label_rejected(self):
        with self.assertRaises(ValueError): synth.synthesize(T(data_label="TOPSECRET"))
    def test_effect_witness_required_remote(self):
        t = T(need_effect_witness=True, remote_trust="contracted", aggregate_ok=False, available_controls=("egress_contract_enforcer",), available_witnesses=("receiver_journal",))
        r = synth.synthesize(t); self.assertEqual(r["plan"].witnesses, ("receiver_journal",))
    def test_effect_witness_missing_makes_remote_uncertifiable(self):
        t = T(need_effect_witness=True, remote_trust="contracted", aggregate_ok=False, available_controls=("egress_contract_enforcer",), available_witnesses=())
        self.assertEqual(synth.synthesize(t)["result"], "NOT_CERTIFIABLE_WITHIN_MODEL")
    def test_deterministic(self): self.assertEqual(synth.synthesize(T()), synth.synthesize(T()))
    def test_tampered_negative_certificate_rejected(self):
        t = T(aggregate_ok=False, available_controls=()); r = synth.synthesize(t); self.assertTrue(synth.verify_negative_certificate(t, r))
        k = next(iter(r["refutations"])); bad = dict(r, refutations=dict(r["refutations"], **{k: []})); self.assertFalse(synth.verify_negative_certificate(t, bad))
        bad2 = dict(r, bounds={"plans_enumerated": 1}); self.assertFalse(synth.verify_negative_certificate(t, bad2))
        self.assertFalse(synth.verify_negative_certificate(t, dict(r, refutations={k: r["refutations"][k]})))
        self.assertFalse(synth.verify_negative_certificate(t, dict(r, refutations=dict(r["refutations"], **{k: ["MADE_UP"]}))))
    def test_certificate_not_valid_for_a_different_task(self):
        t = T(aggregate_ok=False, available_controls=()); r = synth.synthesize(t); self.assertFalse(synth.verify_negative_certificate(T(), r))
    def test_positive_result_is_not_a_negative_certificate(self): self.assertFalse(synth.verify_negative_certificate(T(), synth.synthesize(T())))
    # indistinguishable worlds (T3 / Experiment A)
    W_SAFE = worlds.World("safe", (("send_to_svc", "agent"), ("reply", "agent")), False)
    W_LEAK = worlds.World("leak", (("send_to_svc", "agent"), ("reply", "agent"), ("forward_to_third", "offhost")), True)
    def test_indistinguishable_pair_certificate_verifies(self):
        c = worlds.indistinguishable(self.W_SAFE, self.W_LEAK, {"agent"}); self.assertIsNotNone(c); self.assertTrue(worlds.verify_certificate(c, self.W_SAFE, self.W_LEAK)); self.assertEqual(c["leak"], "leak")
    def test_independent_witness_separates_pair(self): self.assertIsNone(worlds.indistinguishable(self.W_SAFE, self.W_LEAK, {"agent", "offhost"}))
    def test_missing_witness_named(self): self.assertEqual(worlds.missing_witness(self.W_SAFE, self.W_LEAK, {"agent"}, ["agent", "offhost", "other"]), ["offhost"])
    def test_equal_violation_is_not_counterexample(self): self.assertIsNone(worlds.indistinguishable(self.W_SAFE, worlds.World("s2", self.W_SAFE.events, False), {"agent"}))
    def test_forged_certificate_rejected(self):
        c = worlds.indistinguishable(self.W_SAFE, self.W_LEAK, {"agent"}); self.assertFalse(worlds.verify_certificate(dict(c, visible=["agent", "offhost"]), self.W_SAFE, self.W_LEAK)); self.assertFalse(worlds.verify_certificate(None, self.W_SAFE, self.W_LEAK)); self.assertFalse(worlds.verify_certificate(dict(c, safe="x"), self.W_SAFE, self.W_LEAK))
if __name__ == "__main__": unittest.main()
