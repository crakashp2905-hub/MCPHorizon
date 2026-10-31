import json, tempfile, unittest
from pathlib import Path
from horizon.equiv import effects as F, parity as P
from horizon.equiv.rig import Rig, ENDPOINTS
from bench.p14 import parity_gate as G

U = ENDPOINTS["notes"]


class T(unittest.TestCase):
    def test_equivalence_is_kernel(self):
        a = F.make("send", "url", U, principal="a", tenant="T", payload="x", protocol="mcp"); b = F.make("send", "url", "HTTPS://API.example.com:443/b/../v1/notes", principal="a", tenant="T", payload="x", protocol="utcp")
        self.assertTrue(F.equivalent(a, b) and F.equivalent(b, a) and F.equivalent(a, a))
        self.assertTrue(F.sequence_equivalent([a, b], [b, a])); self.assertFalse(F.sequence_equivalent([a], [a, b]))
    def test_causality_optional(self):
        a = F.make("read", "url", U, principal="a", tenant="T", parent="r1"); b = F.make("read", "url", U, principal="a", tenant="T", parent="r2")
        self.assertTrue(F.equivalent(a, b)); self.assertFalse(F.equivalent(a, b, causality=True))
    def test_non_equivalent_fixtures_all_flagged(self):
        fx = P.non_equivalent_fixtures(); self.assertEqual(len(fx), 7)
        for n, x, y in fx: self.assertFalse(F.equivalent(x, y), n)
    def test_unsupported_kind_and_method_not_silent(self):
        with self.assertRaises(F.Unsupported): F.make("admin", "url", U, principal="a", tenant="T")
        r = Rig(P.policy); r.observed.append({"via": "x", "method": "PATCH", "url": U, "body": b""})
        with self.assertRaises(F.Unsupported): r.effects("a", "T", "x", 0)
    def test_all_paths_reach_same_receiver(self):
        for path in P.PATHS:
            r = P.run_path({"id": "w", "principal": "agent-a", "steps": [{"op": "send", "ep": "notes", "text": "hi"}]}, path)
            self.assertEqual(r["verdicts"], ["ALLOW"]); self.assertEqual((r["effects"][0].kind, r["effects"][0].target), ("send", U))
    def test_policy_denial_blocks_effect_on_every_path(self):
        for path in P.PATHS:
            r = P.run_path({"id": "w", "principal": "agent-a", "steps": [{"op": "send", "ep": "other", "text": "hi"}, {"op": "delete", "ep": "notes", "text": ""}]}, path)
            self.assertEqual(r["verdicts"], ["REVIEW", "DENY"], path); self.assertEqual(r["effects"], [], path)
    def test_known_utcp_payload_discrepancy_is_detected(self):
        d = P.compare({"id": "w", "principal": "agent-a", "steps": [{"op": "send", "ep": "notes", "text": "hi"}]})
        self.assertEqual([(x["path"], x["cls"]) for x in d], [("utcp", "PAYLOAD_ENCODING")])
    def test_metamorphic_and_traps(self):
        self.assertEqual(P.metamorphic_mcp(3, 15), [])
        for r in P.trap_results(): self.assertFalse(r["allowed"], r); self.assertEqual(r["observed"], [])
    def test_generator_deterministic(self): self.assertEqual(P.generate(5, 10), P.generate(5, 10)); self.assertNotEqual(P.generate(5, 10), P.generate(6, 10))
    def test_gate_catches_new_stale_and_unexplained(self):
        d = Path(tempfile.mkdtemp()); f = d / "e.json"; ok = {"path": "utcp", "cls": "PAYLOAD_ENCODING", "owner": "o", "explanation": "e"}
        f.write_text(json.dumps({"expected": [ok]})); self.assertEqual(G.check(f), [])
        f.write_text(json.dumps({"expected": []})); self.assertTrue(any("NEW" in e for e in G.check(f)))
        f.write_text(json.dumps({"expected": [ok, dict(ok, path="code_mode", cls="VERDICT")]})); self.assertTrue(any("STALE" in e for e in G.check(f)))
        f.write_text(json.dumps({"expected": [dict(ok, explanation="")]})); self.assertTrue(any("unexplained" in e for e in G.check(f)))
    def test_committed_expected_file_passes(self): self.assertEqual(G.check(Path("results/v2/p14-parity/expected_discrepancies.json")), [])
    def test_verdict_injection_detected(self):
        # a gate that disagrees on verdict must be reported: simulate by a decider keyed on protocol
        def bad(body): return {"verdict": "DENY" if body["protocol"] == "code_mode" else "ALLOW"}
        import horizon.equiv.parity as PP; orig = PP.policy; PP.policy = bad
        try: d = PP.compare({"id": "w", "principal": "agent-a", "steps": [{"op": "read", "ep": "notes", "text": ""}]})
        finally: PP.policy = orig
        self.assertTrue(any(x["cls"] == "VERDICT" and x["path"] == "code_mode" for x in d))
    def test_missing_effect_reported_as_count_discrepancy(self):
        import horizon.equiv.parity as PP; orig = PP.policy
        PP.policy = lambda b: {"verdict": "DENY" if b["protocol"] == "code_mode" else "ALLOW"}
        try: d = PP.compare({"id": "w", "principal": "agent-a", "steps": [{"op": "read", "ep": "notes", "text": ""}]})
        finally: PP.policy = orig
        self.assertTrue(any(x["cls"] == "EFFECT_COUNT" and x["path"] == "code_mode" for x in d))


if __name__ == "__main__": unittest.main()
