"""P83-15 broken-manifest tests for scripts/compile_plan.py (stdlib unittest)."""
import json, shutil, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import compile_plan as cp  # noqa: E402

SPEC = ROOT / "docs" / "MCPHORIZON_2_0_MASTER_SPEC.md"


class PlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp())
        cp.compile_plan(SPEC, cls.base)

    def fresh(self):
        d = Path(tempfile.mkdtemp()); shutil.copytree(self.base, d, dirs_exist_ok=True); return d

    def rows(self, d):
        return [json.loads(l) for l in (d / "task_compiled.jsonl").read_text().splitlines()]

    def write(self, d, rows):
        (d / "task_compiled.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))

    def test_clean_plan_valid_and_complete(self):
        self.assertEqual(cp.validate(self.base, SPEC), [])
        self.assertEqual(len(self.rows(self.base)), 1686)

    def test_lock_unreviewed_and_scheduling_disabled(self):
        lock = json.loads((self.base / "plan.lock").read_text())
        self.assertFalse(lock["reviewed"]); self.assertFalse(lock["scheduling_enabled"])
        self.assertTrue(all(r["status"] == "PENDING" for r in self.rows(self.base)))

    def test_duplicate_id(self):
        d = self.fresh(); r = self.rows(d); r.append(dict(r[0])); self.write(d, r)
        self.assertTrue(any("duplicate" in e for e in cp.validate(d, SPEC)))

    def test_wrong_digest(self):
        d = self.fresh(); r = self.rows(d); r[5]["description_hash"] = "0" * 64; self.write(d, r)
        self.assertTrue(any("wrong description digest" in e for e in cp.validate(d, SPEC)))

    def test_missing_and_orphan_task(self):
        d = self.fresh(); r = self.rows(d); gone = r.pop(10)["task_id"]
        r.append({**r[0], "task_id": "P99-01"}); self.write(d, r)
        errs = cp.validate(d, SPEC)
        self.assertTrue(any(gone in e and "missing" in e for e in errs))
        self.assertTrue(any("P99-01" in e and "orphan" in e for e in errs))

    def test_cycle(self):
        d = self.fresh(); deps = json.loads((d / "dependencies.yaml").read_text())
        deps["edges"].append({"from": "GATE:P74", "to": "PHASE:P1", "citation": "x", "confidence": "low",
                              "review_status": "NEEDS_REVIEW", "signed_by": None})
        (d / "dependencies.yaml").write_text(json.dumps(deps))
        self.assertTrue(any("cycle" in e for e in cp.validate(d, SPEC)))

    def test_self_dependency(self):
        d = self.fresh(); r = self.rows(d); r[0]["depends_on"] = [r[0]["task_id"]]; self.write(d, r)
        self.assertTrue(any("self-dependency" in e for e in cp.validate(d, SPEC)))

    def test_missing_rcr_gate_for_product_task(self):
        d = self.fresh(); r = self.rows(d)
        for x in r:
            if x["phase"] == 55: x["depends_on"] = []
        self.write(d, r)
        self.assertTrue(any("RC-R" in e for e in cp.validate(d, SPEC)))

    def test_unknown_prerequisite(self):
        d = self.fresh(); r = self.rows(d); r[3]["depends_on"] = ["GATE:NOPE"]; self.write(d, r)
        self.assertTrue(any("unknown prerequisite" in e for e in cp.validate(d, SPEC)))

    def test_verified_without_revision_rejected(self):
        d = self.fresh(); r = self.rows(d); r[0]["status"] = "VERIFIED"; self.write(d, r)
        self.assertTrue(any("VERIFIED without" in e for e in cp.validate(d, SPEC)))

    def test_scheduling_without_signature_rejected(self):
        d = self.fresh(); lock = json.loads((d / "plan.lock").read_text()); lock["scheduling_enabled"] = True
        (d / "plan.lock").write_text(json.dumps(lock))
        self.assertTrue(any("scheduling enabled" in e for e in cp.validate(d, SPEC)))

    def test_fake_review_with_unsigned_edges_rejected(self):
        d = self.fresh(); lock = json.loads((d / "plan.lock").read_text())
        lock.update(reviewed=True, reviewer_signature="x"); (d / "plan.lock").write_text(json.dumps(lock))
        self.assertTrue(any("unsigned" in e for e in cp.validate(d, SPEC)))

    def test_spec_change_detected_and_renumber_refused(self):
        d = Path(tempfile.mkdtemp()); s = d / "spec.md"
        s.write_text(SPEC.read_text().replace("**P5-03**", "**P5-04**", 1))
        with self.assertRaises(ValueError): cp.parse_spec(s.read_text())
        s.write_text(SPEC.read_text() + "\nextra\n")
        self.assertTrue(any("spec digest differs" in e for e in cp.validate(self.base, s)))

    def test_truncated_task_definition_refused(self):
        with self.assertRaises(ValueError):
            cp.parse_spec(SPEC.read_text().replace("- [ ] **P7-01**", "- [ ] **P7-01**", 1) + "\n- [ ] **P7-99**\n")

    def test_silent_status_reset_detected(self):
        d = self.fresh(); old = self.base / "old.jsonl"; r = self.rows(d); r[0]["status"] = "VERIFIED"
        old.write_text("".join(json.dumps(x) + "\n" for x in r))
        out = cp.diff(old, d / "task_compiled.jsonl")
        self.assertTrue(any("SILENT-STATUS-RESET" in x for x in out))


if __name__ == "__main__":
    unittest.main()
