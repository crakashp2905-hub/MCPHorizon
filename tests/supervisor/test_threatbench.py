"""SupervisorThreatBench self-test: clean run is clean AND disabling each defence makes the matching oracle fire (oracles are live)."""
import sys, unittest
from pathlib import Path
from unittest import mock
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from bench.supervisor_threatbench.run import run
from bench.supervisor_threatbench import scenarios as S
from orchestrator import packets, packet2, verifier2, deps


class Bench(unittest.TestCase):
    def test_clean_run_has_no_unauthorized_effect_no_false_block_no_error(self):
        r = run(); self.assertEqual(r["totals"]["errored"], 0, r); self.assertEqual(r["totals"]["attacks_with_unauthorized_effect"], 0, r)
        self.assertEqual(r["totals"]["false_blocks"], 0, r); self.assertEqual(r["totals"]["run"], 13)
        self.assertTrue({"S09", "S10", "P86-17"} <= set(r["not_run"])); self.assertTrue(r["open_findings"]); self.assertTrue(r["caveats"])

    def eff(self, sid): return S.SCENARIOS[sid][1]()[0]

    def test_mutation_signature_checks_off_fires_forgery_oracles(self):
        with mock.patch("orchestrator.ledger.hmac.compare_digest", lambda a, b: True):
            for sid in ("S03", "S04", "S13", "S15"): self.assertTrue(self.eff(sid), sid)

    def test_mutation_packet_signature_off_fires_scope_oracles(self):
        with mock.patch("orchestrator.packet2.hmac.compare_digest", lambda a, b: True):
            self.assertTrue(self.eff("S14"))

    def test_mutation_label_binding_off_fires_s02(self):
        with mock.patch.object(packet2, "item_digest", lambda i: packet2.sha(packet2.canon([i["sha256"]]))): self.assertTrue(self.eff("S02"))

    def test_mutation_trust_roots_unprotected_fires_s08(self):
        weak = tuple(p for p in packets.FORBIDDEN_PREFIXES if p not in packets.TRUST_ROOTS)
        with mock.patch.object(packets, "FORBIDDEN_PREFIXES", weak), mock.patch.object(packet2, "FORBIDDEN_PREFIXES", weak), mock.patch.object(S, "FORBIDDEN_PREFIXES", weak):
            self.assertTrue(self.eff("S08"))

    def test_mutation_tamper_detection_off_fires_s05(self):
        with mock.patch.object(verifier2, "oracle_tamper", lambda *a, **k: {"modified_protected": [], "shadowing_additions": []}):
            self.assertTrue(self.eff("S05"))

    def test_mutation_dependency_check_off_fires_s07(self):
        with mock.patch.object(deps, "check_artifact", lambda *a, **k: None): self.assertTrue(self.eff("S07"))

    def test_mutation_provider_filter_off_fires_s11(self):
        with mock.patch.object(packet2, "eligible_providers", lambda pk, provs: sorted(provs)): self.assertTrue(self.eff("S11"))

    def test_mutation_handoff_status_check_off_fires_s01_s06(self):
        orig = packet2.check_handoff
        with mock.patch.object(packet2, "check_handoff", lambda h, pk: [] if h["claimed_status"] == "VERIFIED" else orig(h, pk)):
            for sid in ("S01", "S06"): self.assertTrue(self.eff(sid), sid)

    def test_mutation_stale_epoch_and_expiry_off_fires_s12(self):
        orig = packet2.validate
        with mock.patch.object(packet2, "validate", lambda *a, **k: []): self.assertTrue(self.eff("S12"))


if __name__ == "__main__": unittest.main()
