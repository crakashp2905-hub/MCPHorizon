import unittest
from research.commitproof import model as M


def replay(design, trace, n=3):
    """Re-execute a counterexample label-by-label on the model; returns the final state (raises if a step is not enabled)."""
    d = M.DESIGNS[design]; s = M.initial(n)
    for lab in trace:
        nxt = [t for l, t in M.successors(s, d) if l == lab]
        assert len(nxt) == 1, (lab, s)
        s = nxt[0]
    return s


EXPECT = {   # design -> exact set of violated invariants at n=3
    "proposed": set(), "proposed_timeout_recovery": set(), "no_fence_after_death": set(),
    "proposed_no_orphan_expiry": {"I5_unresolved_deadend"},
    "no_fence_timeout_recovery": {"I3b_blocked_means_no_sink_effect"},
    "retry_from_unknown": {"I1_at_most_one_sink_effect"},
    "retry_on_timeout": {"I1_at_most_one_sink_effect", "I3a_committed_requires_sink_evidence"},
    "per_worker_nonce": {"I1_at_most_one_sink_effect", "I3a_committed_requires_sink_evidence"},
}
STATES = {"proposed": 145, "proposed_no_orphan_expiry": 133, "proposed_timeout_recovery": 229, "no_fence_timeout_recovery": 229, "no_fence_after_death": 145,
          "retry_from_unknown": 334, "retry_on_timeout": 754, "per_worker_nonce": 571}


class Designs(unittest.TestCase):
    def test_exact_violation_sets(self):
        for name, exp in EXPECT.items(): self.assertEqual(set(M.explore(name)["violations"]), exp, name)

    def test_state_counts_pinned(self):
        for name, n in STATES.items(): self.assertEqual(M.explore(name)["states"], n, name)

    def test_proposed_safe_up_to_six_workers(self):
        want = {(4, "proposed"): 385, (4, "proposed_timeout_recovery"): 609, (6, "proposed"): 2305, (6, "proposed_timeout_recovery"): 3649}
        for (n, name), st in want.items():
            r = M.explore(name, n=n); self.assertTrue(r["safe"], (n, name)); self.assertEqual(r["states"], st, (n, name))

    def test_fence_is_needed_exactly_when_recovery_can_race_a_live_owner(self):
        self.assertTrue(M.explore("no_fence_after_death")["safe"]); self.assertFalse(M.explore("no_fence_timeout_recovery")["safe"])
        self.assertTrue(M.explore("proposed_timeout_recovery")["safe"])

    def test_every_counterexample_is_a_real_execution_ending_in_a_violation(self):
        for name in EXPECT:
            for inv, tr in M.explore(name)["violations"].items():
                s = replay(name, tr)
                if inv.startswith("I5"): self.assertEqual(M.successors(s, M.DESIGNS[name]), []); self.assertIn(s[0], (M.AUTH, M.LSTART, M.UNKNOWN))
                else: self.assertIn(inv, M.invariants(s), (name, inv))

    def test_counterexamples_are_shortest(self):
        self.assertEqual(len(M.explore("no_fence_timeout_recovery")["violations"]["I3b_blocked_means_no_sink_effect"]), 5)
        self.assertEqual(len(M.explore("per_worker_nonce")["violations"]["I1_at_most_one_sink_effect"]), 4)

    def test_zombie_counterexample_content(self):
        tr = M.explore("no_fence_timeout_recovery")["violations"]["I3b_blocked_means_no_sink_effect"]
        self.assertEqual(tr, ["w0.authorize", "w0.begin", "recover(STARTED->UNKNOWN)", "reconcile(observe)", "w0.sink_write"])

    def test_orphan_trace(self):
        self.assertEqual(M.explore("proposed_no_orphan_expiry")["violations"]["I5_unresolved_deadend"][:2], ["w0.authorize", "w0.CRASH"])

    def test_design_flags_documented_complete(self):
        keys = {"shared_ledger", "recover", "fenced", "retry_unknown", "retry_started", "expire_auth"}
        for name, d in M.DESIGNS.items(): self.assertEqual(set(d), keys, name)


class Invariants(unittest.TestCase):
    def st(self, L=M.NONE, used=False, c=0): return (L, used, -1, c, False, (M.IDLE,))
    def test_clean(self): self.assertEqual(M.invariants(self.st()), [])
    def test_double_effect(self): self.assertIn("I1_at_most_one_sink_effect", M.invariants(self.st(c=2, used=True)))
    def test_effect_without_permit(self): self.assertIn("I2_no_effect_without_consumed_permit", M.invariants(self.st(c=1)))
    def test_committed_without_evidence(self):
        self.assertIn("I3a_committed_requires_sink_evidence", M.invariants(self.st(L=M.COMMITTED, used=True))); self.assertIn("I3a_committed_requires_sink_evidence", M.invariants(self.st(L=M.REC_C, used=True)))
    def test_blocked_with_effect(self):
        self.assertIn("I3b_blocked_means_no_sink_effect", M.invariants(self.st(L=M.REC_B, used=True, c=1))); self.assertIn("I3b_blocked_means_no_sink_effect", M.invariants(self.st(L=M.BLOCKED, used=True, c=1)))
    def test_valid_committed(self): self.assertEqual(M.invariants(self.st(L=M.COMMITTED, used=True, c=1)), [])


class Transitions(unittest.TestCase):
    def labels(self, s, design="proposed"): return [l for l, _ in M.successors(s, M.DESIGNS[design])]
    def test_recovery_blocked_while_owner_alive_in_after_death(self):
        s = (M.LSTART, True, 0, 0, False, (M.STARTED, M.IDLE)); self.assertNotIn("recover(STARTED->UNKNOWN)", self.labels(s)); self.assertIn("recover(STARTED->UNKNOWN)", self.labels(s, "proposed_timeout_recovery"))
    def test_recovery_allowed_after_owner_death(self):
        s = (M.LSTART, True, 0, 0, False, (M.DEAD, M.IDLE)); self.assertIn("recover(STARTED->UNKNOWN)", self.labels(s))
    def test_reconcile_fences_and_reads(self):
        s = (M.UNKNOWN, True, 0, 1, False, (M.DEAD,)); (lab, t), = [x for x in M.successors(s, M.DESIGNS["proposed"]) if x[0].startswith("reconcile")]
        self.assertEqual((t[0], t[4]), (M.REC_C, True))
        s2 = (M.UNKNOWN, True, 0, 0, False, (M.DEAD,)); (lab, t), = [x for x in M.successors(s2, M.DESIGNS["proposed"]) if x[0].startswith("reconcile")]; self.assertEqual((t[0], t[4]), (M.REC_B, True))
    def test_fenced_sink_refuses_write(self):
        s = (M.REC_B, True, 0, 0, True, (M.STARTED,)); self.assertEqual(self.labels(s)[0], "w0.sink_write_refused(fenced)")
    def test_unfenced_sink_accepts_write(self):
        s = (M.REC_B, True, 0, 0, False, (M.STARTED,)); self.assertEqual(self.labels(s)[0], "w0.sink_write")
    def test_finish_refused_after_unknown(self):
        s = (M.UNKNOWN, True, 0, 1, False, (M.WROTE,)); self.assertTrue(any(l.startswith("w0.finish_refused") for l in self.labels(s)))
    def test_orphan_expiry_only_without_live_authorizer(self):
        self.assertNotIn("expire_orphan(AUTHORIZED->BLOCKED)", self.labels((M.AUTH, True, -1, 0, False, (M.AUTHED,))))
        self.assertIn("expire_orphan(AUTHORIZED->BLOCKED)", self.labels((M.AUTH, True, -1, 0, False, (M.DEAD,))))

if __name__ == "__main__": unittest.main()
