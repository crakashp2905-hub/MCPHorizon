import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from horizon.coverage import schema as S
Z = {"agentz": S.TrustZone("agentz", "agent"), "recv": S.TrustZone("recv", "receiver"), "ops": S.TrustZone("ops", "operator"), "tools": S.TrustZone("tools", "tool_server")}
class Schemas(unittest.TestCase):
    def test_roundtrip_and_digest_stable(self):
        for o in (S.TrustZone("a", "agent"), S.Witness("w", "recv", frozenset({"x", "y"})), S.EffectEdge("a", "b", "file_write", "instrumented"), S.Probe("p", True, 0), S.Observation("p", "b", "seen", "w"), S.HypothesisWorld("h", ("b",), True)):
            o2 = type(o).from_dict(o.to_dict()); self.assertEqual(o, o2); self.assertEqual(o.digest(), o2.digest())
    def test_digest_binds_content(self):
        self.assertNotEqual(S.EffectEdge("a", "b", "file_write", "instrumented").digest(), S.EffectEdge("a", "b", "file_write", "uninstrumented").digest())
    def test_closed_enums_fail_closed(self):
        for f in (lambda: S.TrustZone("a", "root"), lambda: S.EffectEdge("a", "b", "teleport", "instrumented"), lambda: S.EffectEdge("a", "b", "dns", "maybe"), lambda: S.Observation("p", "b", "clean", "w")):
            with self.assertRaises(S.SchemaError): f()
    def test_bad_ids_and_self_edge(self):
        for f in (lambda: S.TrustZone("A", "agent"), lambda: S.TrustZone("", "agent"), lambda: S.TrustZone(1, "agent"), lambda: S.EffectEdge("a", "a", "dns", "instrumented"), lambda: S.Witness("w", "recv", frozenset()), lambda: S.Witness("w", "recv", frozenset({"Bad"}))):
            with self.assertRaises(S.SchemaError): f()
    def test_probe_must_be_synthetic_and_zero_external_effects(self):
        for a in ((False, 0), (True, 1), (True, True), (1, 0), (True, -1)):
            with self.assertRaises(S.SchemaError): S.Probe("p", *a)
    def test_unknown_and_missing_fields_rejected(self):
        d = S.TrustZone("a", "agent").to_dict()
        with self.assertRaises(S.SchemaError): S.TrustZone.from_dict({**d, "extra": 1})
        with self.assertRaises(S.SchemaError): S.TrustZone.from_dict({"name": "a"})
        with self.assertRaises(S.SchemaError): S.TrustZone.from_dict([])
    def test_hypothesis_world_checks(self):
        with self.assertRaises(S.SchemaError): S.HypothesisWorld("h", ("B",), True)
        with self.assertRaises(S.SchemaError): S.HypothesisWorld("h", ("b",), "yes")
    def test_witness_independence_depends_on_zone_authority(self):
        self.assertTrue(S.Witness("w", "recv", frozenset({"x"})).independent_of(Z)); self.assertTrue(S.Witness("w", "ops", frozenset({"x"})).independent_of(Z))
        self.assertFalse(S.Witness("w", "agentz", frozenset({"x"})).independent_of(Z)); self.assertFalse(S.Witness("w", "tools", frozenset({"x"})).independent_of(Z)); self.assertFalse(S.Witness("w", "nozone", frozenset({"x"})).independent_of(Z))
    def test_grade_independent_vs_self_reported(self):
        e = S.EffectEdge("a", "b", "http_egress", "instrumented")
        self.assertEqual(S.validate_observation(S.Observation("p", "b", "seen", "w"), e, S.Witness("w", "recv", frozenset({"b"})), Z), "POSITIVE_INDEPENDENT")
        self.assertEqual(S.validate_observation(S.Observation("p", "b", "seen", "w"), e, S.Witness("w", "agentz", frozenset({"b"})), Z), "POSITIVE_SELF_REPORTED")
    def test_not_seen_is_never_absence_evidence(self):
        e = S.EffectEdge("a", "b", "http_egress", "instrumented"); w = S.Witness("w", "recv", frozenset({"b"}))
        for out in ("not_seen", "unobservable"): self.assertEqual(S.validate_observation(S.Observation("p", "b", out, "w"), e, w, Z), "UNKNOWN")
    def test_uninstrumented_edge_cannot_be_reported_seen(self):
        e = S.EffectEdge("a", "b", "remote_service", "uninstrumented"); w = S.Witness("w", "recv", frozenset({"b"}))
        with self.assertRaises(S.SchemaError): S.validate_observation(S.Observation("p", "b", "seen", "w"), e, w, Z)
        self.assertEqual(S.validate_observation(S.Observation("p", "b", "not_seen", "w"), e, w, Z), "UNKNOWN")
    def test_witness_that_cannot_see_edge_cannot_report_it(self):
        e = S.EffectEdge("a", "b", "dns", "instrumented"); w = S.Witness("w", "recv", frozenset({"other"}))
        with self.assertRaises(S.SchemaError): S.validate_observation(S.Observation("p", "b", "seen", "w"), e, w, Z)
    def test_mismatched_observation_rejected(self):
        e = S.EffectEdge("a", "b", "dns", "instrumented"); w = S.Witness("w", "recv", frozenset({"b"}))
        with self.assertRaises(S.SchemaError): S.validate_observation(S.Observation("p", "c", "seen", "w"), e, w, Z)
        with self.assertRaises(S.SchemaError): S.validate_observation(S.Observation("p", "b", "seen", "w2"), e, w, Z)
if __name__ == "__main__": unittest.main()
