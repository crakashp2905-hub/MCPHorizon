import json, unittest
from horizon.txn.engine import Contract, Fault, Ledger, Resource, Txn, NEEDS_APPROVAL

REV = Contract("COMPENSABLE", idempotent=True, compensation="restore"); PUB = Contract("IRREVERSIBLE"); NONIDEM = Contract("COMPENSABLE", idempotent=False, compensation="restore")


def mk(policy=lambda p, k, v: None, authz=lambda p, k: True, pv=lambda: 1, **kw): r = Resource({"k": "old"}); return r, Txn(r, policy, authz, pv and None or kw.get("approvals"), policy_version=pv)


class T(unittest.TestCase):
    def test_contract_validation(self):
        with self.assertRaises(ValueError): Contract("COMPENSABLE")
        with self.assertRaises(ValueError): Contract("NOPE")
    def test_prepare_does_not_mutate_commit_does(self):
        r, t = mk(); h = t.prepare("a", "k", "new", REV); self.assertEqual(r.read("k")[0], "old"); out = t.commit(h); self.assertEqual((r.read("k")[0], out["outcome"]), ("new", "APPLIED"))
    def test_policy_denial_at_prepare_and_nothing_lands(self):
        r, t = mk(policy=lambda p, k, v: "NO"); out = t.commit(t.prepare("a", "k", "new", REV)); self.assertEqual((out["status"], out["why"]), ("REFUSED", "NO")); self.assertEqual(r.ledger.rows, [])
    def test_policy_version_and_authz_rebound_at_commit(self):
        pv = [1]; ok = [True]; r, t = mk(pv=lambda: pv[0], authz=lambda p, k: ok[0]); h = t.prepare("a", "k", "n", REV); pv[0] = 2; self.assertEqual(t.commit(h)["why"], "POLICY_CHANGED")
        pv[0] = 1; h = t.prepare("a", "k", "n", REV); ok[0] = False; self.assertEqual(t.commit(h)["why"], "AUTHZ_REVOKED"); self.assertEqual(r.ledger.rows, [])
    def test_policy_reevaluated_at_commit(self):
        deny = [False]; r, t = mk(policy=lambda p, k, v: "LATE" if deny[0] else None); h = t.prepare("a", "k", "n", REV); deny[0] = True; self.assertEqual(t.commit(h)["why"], "LATE")
    def test_cas_conflict_is_not_applied(self):
        r, t = mk(); h = t.prepare("a", "k", "n", REV); r.apply("k", "other"); out = t.commit(h); self.assertEqual(out["transport_error"], "CAS_CONFLICT"); self.assertEqual((r.read("k")[0], out["outcome"]), ("other", "PARTIAL_OR_CONFLICT"))
    def test_outcome_independent_of_exception(self):
        r, t = mk(); r.faults.add("timeout_after_apply"); out = t.commit(t.prepare("a", "k", "n", REV)); self.assertEqual((out["transport_error"], out["outcome"]), ("timeout", "APPLIED"))      # error yet applied
        r2, t2 = mk(); r2.faults.add("crash_before_apply"); o2 = t2.commit(t2.prepare("a", "k", "n", REV)); self.assertEqual((o2["transport_error"], o2["outcome"]), ("crash", "NOT_APPLIED"))
    def test_idempotent_retry_applies_once(self):
        r, t = mk(); r.faults.add("timeout_after_apply"); out = t.retry(t.prepare("a", "k", "n", REV)); self.assertEqual(out["outcome"], "APPLIED"); self.assertEqual(len(r.ledger.effects("k")), 1)
    def test_crash_then_retry_succeeds_for_idempotent(self):
        r, t = mk(); r.faults.add("crash_before_apply"); out = t.retry(t.prepare("a", "k", "n", REV)); self.assertEqual((r.read("k")[0], out["outcome"]), ("n", "APPLIED"))
    def test_non_idempotent_never_blindly_retried(self):
        r, t = mk(); r.faults.add("crash_before_apply"); out = t.retry(t.prepare("a", "k", "n", NONIDEM)); self.assertEqual(out.get("retry"), "REFUSED_NON_IDEMPOTENT"); self.assertEqual(r.ledger.rows, [])
    def test_double_commit_detected(self):
        r, t = mk(); r.faults.add("double_apply"); h = t.prepare("a", "k", "n", NONIDEM); h["ledger_before"] = 0; out = t.commit(h); self.assertEqual(out["outcome"], "DUPLICATED")
        h2 = t.prepare("a", "z", "n", REV); t.commit(h2); self.assertEqual(t.commit(dict(h2, read_version=r.read("z")[1]))["outcome"], "APPLIED"); self.assertEqual(len(r.ledger.effects("z")), 1)      # token dedupes second commit
    def test_compensation_verified(self):
        r, t = mk(); h = t.prepare("a", "k", "n", REV); t.commit(h); self.assertEqual(t.compensate(h), "RESTORED"); self.assertEqual(r.read("k")[0], "old")
        h = t.prepare("a", "new", "x", REV); t.commit(h); self.assertEqual(t.compensate(h), "RESTORED"); self.assertEqual(r.read("new")[0], None)
    def test_compensation_failure_detected_not_assumed(self):
        r, t = mk(); h = t.prepare("a", "k", "n", REV); t.commit(h); orig = r.apply; r.apply = lambda *a, **k: None; self.assertEqual(t.compensate(h), "RESTORE_FAILED"); r.apply = orig
    def test_irreversible_needs_approval_and_cannot_be_undone(self):
        r, t = mk(); h = t.prepare("a", "k", "msg", PUB); self.assertEqual(t.commit(h)["status"], "NEEDS_APPROVAL"); self.assertEqual(r.ledger.rows, [])
        t.approvals.add(h["id"]); t.commit(h); self.assertEqual(r.published, [("k", "msg")]); self.assertEqual(t.compensate(h), "CANNOT_COMPENSATE"); self.assertEqual(r.published, [("k", "msg")])
        self.assertTrue({"IRREVERSIBLE", "UNKNOWN", "EXTERNAL_VISIBLE", "DELAYED"} <= NEEDS_APPROVAL)
    def test_no_compensation_declared(self):
        r, t = mk(); c = Contract("REVERSIBLE"); h = t.prepare("a", "k", "n", c); t.commit(h); self.assertEqual(t.compensate(h), "NO_COMPENSATION")
    def test_ledger_tamper_detected(self):
        l = Ledger(); l.append({"op": "write", "key": "k", "value": 1}); l.append({"op": "write", "key": "k", "value": 2}); self.assertTrue(l.verify()); l.rows[0]["value"] = 9; self.assertFalse(l.verify())
    def test_results_ordering(self):
        d = json.load(open("results/v2/p17-transactions/result.json")); t, a, s = d["txn"], d["detect_alert"], d["stop_after_breach"]
        self.assertEqual((t["residual_damage"], t["irreversible_residual"]), (0, 0)); self.assertEqual(t["prevented_verified_absent"], t["prohibited_attempts"]); self.assertEqual(a["prevented_verified_absent"], 0); self.assertGreater(a["residual_damage"], s["residual_damage"] > 0 and 0)
        self.assertGreater(s["legit_skipped_by_halt"], 0); self.assertGreater(t["legit_final_state_correct"], s["legit_final_state_correct"]); self.assertTrue(all(v["ledger_chain_valid"] for v in d.values()))


if __name__ == "__main__": unittest.main()
