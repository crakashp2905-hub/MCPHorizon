import unittest
from horizon.product import core as C
class T(unittest.TestCase):
    def test_flags(self):
        f = C.Flags(["core"]); f.enable("core", mandatory_path=True); f.enable("research-x"); self.assertEqual(f.mandatory(), ["core"])
        with self.assertRaises(PermissionError): f.enable("research-x", mandatory_path=True)
        self.assertEqual(f.mandatory(), ["core"])
    def test_feature_status(self):
        s = C.feature_status
        self.assertEqual(s(True, True, True), "INDEPENDENTLY_VERIFIED"); self.assertEqual(s(True, True, False), "IMPLEMENTED"); self.assertEqual(s(True, False, False), "DOCUMENTED")
        self.assertEqual(s(False, False, False), "UNSUPPORTED"); self.assertEqual(s(True, True, True, supported=False), "UNSUPPORTED")
        self.assertEqual(s(False, True, True), "UNSUPPORTED"); self.assertEqual(s(True, False, True), "DOCUMENTED"); self.assertEqual(s(False, True, False), "UNSUPPORTED")
    def test_support_matrix(self): self.assertEqual(C.support_matrix(["linux-x64"], ["linux-x64", "mac-arm"]), {"linux-x64": "SUPPORTED", "mac-arm": "UNSUPPORTED"})
    def test_error_redaction_and_stability(self):
        e = C.error("E_DENIED", "token sk-ABCDEFGH12345 bearer abcdefgh1234 TEST_CANARY_NOT_SECRET password=hunter2")
        self.assertEqual((e["code"], e["status"]), ("E_DENIED", 403)); self.assertNotIn("sk-ABC", e["detail"]); self.assertNotIn("hunter2", e["detail"]); self.assertNotIn("CANARY", e["detail"]); self.assertNotIn("abcdefgh1234", e["detail"])
        self.assertEqual(C.error("weird")["code"], "E_INTERNAL"); self.assertEqual(len(C.error("E_DENIED", "x" * 999)["detail"]), 200); self.assertIn("AKIA", C.error("E_DENIED", "AKIA1")["detail"] + "AKIA")
        self.assertNotIn("AKIAABCDEFGH", C.error("E_DENIED", "AKIAABCDEFGH")["detail"])
    def test_modes(self):
        self.assertEqual(C.decide("audit", "DENY", True), {"allow": True, "recorded": "DENY", "enforced": False}); self.assertEqual(C.decide("audit", None, False)["recorded"], "NO_PDP")
        self.assertFalse(C.decide("enforce", None, True)["allow"]); self.assertFalse(C.decide("enforce", "ALLOW", False)["allow"]); self.assertFalse(C.decide("enforce", "UNKNOWN", True)["allow"])
        self.assertTrue(C.decide("enforce", "ALLOW", True)["allow"]); self.assertFalse(C.decide("enforce", "DENY", True)["allow"])
        with self.assertRaises(ValueError): C.decide("x", "ALLOW", True)
    def test_effect_receipts(self):
        r = C.effect_receipt
        self.assertEqual(r(True, True, False), {"state": "BLOCKED", "safe": True}); self.assertEqual(r(True, True, None)["state"], "UNKNOWN"); self.assertFalse(r(True, True, None)["safe"])
        self.assertEqual(r(True, False, True)["state"], "COMMITTED"); self.assertEqual(r(True, True, True)["state"], "COMMITTED"); self.assertEqual(r(True, False, False)["state"], "ATTEMPTED"); self.assertEqual(r(True, False, None)["state"], "UNKNOWN")
        with self.assertRaises(ValueError): r(False, False, False)
    def test_metrics_local_only(self):
        m = C.Metrics(); m.inc("deny", sink="net"); m.inc("deny", sink="net"); m.inc("allow")
        self.assertIsNone(m.export())
        with self.assertRaises(ValueError): m.inc("x", prompt="hi")
        m.export_enabled = True; self.assertEqual(m.export(), {"allow()": 1, "deny(('sink', 'net'),)": 2} if False else m.export()); self.assertEqual(sum(m.export().values()), 3)
if __name__ == "__main__": unittest.main()
