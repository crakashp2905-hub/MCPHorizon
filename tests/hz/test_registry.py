import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from horizon.assurance.registry import AssuranceClaim, Registry, ClaimError, outcome
class T(unittest.TestCase):
    def setUp(self):
        self.t = [100]; self.r = Registry(lambda: self.t[0]); self.r.set_node("adapter:fs", "d1"); self.r.set_node("witness:j", "w1")
        self.base = AssuranceClaim("c:base", ("fs",), 5, 200, ("adapter:fs",), (("adapter:fs", "d1"),)); self.r.add(self.base)
        self.top = AssuranceClaim("c:top", ("fs", "send"), 5, 200, ("c:base", "witness:j"), (("c:base", "x"), ("witness:j", "w1"))); self.r.add(self.top)
    def st(self, c="c:top", e=5): return self.r.status(c, e)[0]
    def test_valid(self): self.assertEqual((self.st(), self.r.may_issue_permit("c:top", 5)), ("VALID", True))
    def test_unknown_claim_fails_closed(self): self.assertFalse(self.r.may_issue_permit("nope", 5)); self.assertEqual(self.r.status("nope", 5)[1], "unknown_claim")
    def test_expiry(self): self.t[0] = 200; self.assertEqual(self.st(), "EXPIRED"); self.assertFalse(self.r.may_issue_permit("c:top", 5))
    def test_stale_epoch_suspends(self): self.assertEqual(self.st(e=6), "SUSPENDED")
    def test_adapter_digest_change_suspends_transitively(self): self.r.set_node("adapter:fs", "d2"); self.assertEqual(self.st("c:base"), "SUSPENDED"); self.assertEqual(self.st("c:top"), "SUSPENDED")
    def test_dependency_invalidation_propagates(self): self.r.invalidate("witness:j", "compromised"); self.assertEqual(self.st("c:top"), "SUSPENDED"); self.assertEqual(self.st("c:base"), "VALID")
    def test_base_invalidation_reaches_top(self): self.r.invalidate("adapter:fs", "coverage_lost"); self.assertIn("coverage_lost", self.r.status("c:top", 5)[1])
    def test_revoke_claim(self): self.r.revoke("c:base"); self.assertEqual((self.st("c:base"), self.st("c:top")), ("REVOKED", "SUSPENDED"))
    def test_revoke_unknown(self):
        with self.assertRaises(ClaimError): self.r.revoke("zzz")
    def test_missing_dependency_suspends(self):
        self.r.add(AssuranceClaim("c:m", ("x",), 5, 200, ("ghost",), (("ghost", "g"),))); self.assertEqual(self.st("c:m"), "SUSPENDED")
    def test_digests_must_cover_deps(self):
        with self.assertRaises(ClaimError): self.r.add(AssuranceClaim("c:b", ("x",), 5, 200, ("a", "b"), (("a", "1"),)))
    def test_empty_scope_rejected(self):
        with self.assertRaises(ClaimError): self.r.add(AssuranceClaim("c:e", (), 5, 200, ("a",), (("a", "1"),)))
    def test_duplicate_rejected(self):
        with self.assertRaises(ClaimError): self.r.add(self.base)
    def test_cycle_does_not_hang_and_suspends(self):
        self.r.add(AssuranceClaim("c:a", ("x",), 5, 200, ("c:b",), (("c:b", "1"),))); self.r.add(AssuranceClaim("c:b", ("x",), 5, 200, ("c:a",), (("c:a", "1"),))); self.assertEqual(self.st("c:a"), "SUSPENDED")
    def test_digest_binds_all_fields(self):
        a = self.base.digest(); import dataclasses as d
        for k, v in (("scope", ("fs", "x")), ("epoch", 6), ("expires_at", 201), ("depends_on", ("adapter:fs", "y")), ("digests", (("adapter:fs", "d9"),))): self.assertNotEqual(a, d.replace(self.base, **{k: v}).digest(), k)
    def test_outcome_prevention_vs_observation(self):
        self.assertEqual(outcome(True, True), "VERIFIED_COMMITTED"); self.assertEqual(outcome(True, False), "UNKNOWN"); self.assertEqual(outcome(None, True), "UNKNOWN")
        self.assertEqual(outcome(False, True), "NOT_OBSERVED"); self.assertEqual(outcome(False, False), "UNKNOWN")
if __name__ == "__main__": unittest.main()
