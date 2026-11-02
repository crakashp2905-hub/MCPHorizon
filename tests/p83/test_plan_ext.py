import copy, json, os, unittest
from horizon.plan import spans, migrate, profiles
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SPEC = open(os.path.join(ROOT, "docs/MCPHORIZON_2_0_MASTER_SPEC.md"), encoding="utf-8").read()
SMALL = "## Gate G1\n- [ ] **P1-01** a\n- [ ] **P1-02** b\n  more\n## Next\n- [ ] **P2-01** c\n"
def rows():
    return [{"task_id": "P1-01", "phase": 1, "status": "VERIFIED", "description_hash": "a", "depends_on": [], "risk_tier": "high"},
            {"task_id": "P1-02", "phase": 1, "status": "PENDING", "description_hash": "b", "depends_on": ["P1-01"], "risk_tier": "medium"},
            {"task_id": "P2-01", "phase": 2, "status": "VERIFIED", "description_hash": "c", "depends_on": ["P1-02"], "risk_tier": "medium"}]

class Spans(unittest.TestCase):
    def test_small_spans(self):
        m = spans.span_map(SMALL)
        self.assertEqual((m["tasks"]["P1-01"]["start"], m["tasks"]["P1-01"]["end"]), (2, 2))
        self.assertEqual((m["tasks"]["P1-02"]["start"], m["tasks"]["P1-02"]["end"]), (3, 4))
        self.assertEqual(len(m["gates"]), 1)
    def test_duplicate_refused(self):
        with self.assertRaises(ValueError): spans.span_map(SMALL + "- [ ] **P1-01** dup\n")
    def test_full_spec_inventory(self):
        m = spans.span_map(SPEC); self.assertEqual(len(m["tasks"]), 1686)
        ph = {int(t[1:].split("-")[0]) for t in m["tasks"]}; self.assertEqual(ph, set(range(95)))
    def test_check_detects_edit(self):
        m = spans.span_map(SMALL); self.assertEqual(spans.check_span_map(m, SMALL), [])
        self.assertTrue(spans.check_span_map(m, SMALL.replace("b\n", "B\n")))
    def test_task_edit_without_any_gate_heading_detected(self):
        T = "- [ ] **P1-01** a\n- [ ] **P1-02** b\n"; m = spans.span_map(T); self.assertEqual(m["gates"], [])
        self.assertEqual(spans.check_span_map(m, T.replace("b", "c")), ["spec digest differs", "P1-02: span or digest changed"])
    def test_gate_edit_detected_on_its_own(self):
        T = "## Gate G1\nprose\n"; m = spans.span_map(T); self.assertEqual(m["tasks"], {})
        self.assertEqual(spans.check_span_map(m, T.replace("prose", "other")), ["spec digest differs", "gate spans differ"])
    def test_check_detects_missing_and_added(self):
        m = spans.span_map(SMALL)
        self.assertTrue(any("missing" in e for e in spans.check_span_map(m, SMALL.replace("- [ ] **P2-01** c\n", ""))))
        self.assertTrue(any("not in pinned" in e for e in spans.check_span_map(m, SMALL + "- [ ] **P2-02** d\n")))
    def test_pinned_map_matches_repo_spec(self):
        pinned = json.load(open(os.path.join(ROOT, "spec/source_spans.json"))); self.assertEqual(spans.check_span_map(pinned, SPEC), [])
    def test_history_refs_flag_missing(self):
        t = "- [ ] **P1-01** see `results/nonexistent_zz/x.json` and `docs/MCPHORIZON_2_0_MASTER_SPEC.md`\n"
        r = spans.history_refs(t, ROOT)["P1-01"]
        self.assertEqual(r["results/nonexistent_zz/x.json"], "MISSING"); self.assertEqual(r["docs/MCPHORIZON_2_0_MASTER_SPEC.md"], "present")

class Migrate(unittest.TestCase):
    def test_identity(self):
        out, man = migrate.migrate(rows(), rows(), revision="r1"); self.assertEqual(out, rows()); self.assertEqual(man["removed"], [])
        self.assertEqual(man["before_digest"], man["after_digest"])
    def test_silent_deletion_refused(self):
        with self.assertRaises(migrate.MigrationError): migrate.migrate(rows(), rows()[:2], revision="r")
    def test_tombstoned_deletion_allowed_and_listed(self):
        _, man = migrate.migrate(rows(), rows()[:2], tombstones=["P2-01"], revision="r"); self.assertEqual(man["removed"], ["P2-01"])
    def test_renumber_refused(self):
        n = rows(); n[0]["phase"] = 9
        with self.assertRaises(migrate.MigrationError): migrate.migrate(rows(), n, revision="r")
    def test_silent_status_reset_refused(self):
        n = rows(); n[0]["status"] = "PENDING"
        with self.assertRaises(migrate.MigrationError): migrate.migrate(rows(), n, revision="r")
    def test_changed_verified_becomes_revalidation(self):
        n = rows(); n[0]["description_hash"] = "z"
        out, man = migrate.migrate(rows(), n, revision="r"); self.assertEqual(out[0]["status"], "NEEDS_REVALIDATION"); self.assertEqual(man["needs_revalidation"], ["P1-01"])
    def test_changed_pending_stays_pending(self):
        n = rows(); n[1]["description_hash"] = "z"
        out, man = migrate.migrate(rows(), n, revision="r"); self.assertEqual(out[1]["status"], "PENDING"); self.assertEqual(man["needs_revalidation"], [])
    def test_added_listed(self):
        n = rows() + [dict(rows()[0], task_id="P2-02", phase=2, status="PENDING")]
        _, man = migrate.migrate(rows(), n, revision="r"); self.assertEqual(man["added"], ["P2-02"])
    def test_duplicate_new_refused(self):
        with self.assertRaises(migrate.MigrationError): migrate.migrate(rows(), rows() + rows()[:1], revision="r")

class Invalidate(unittest.TestCase):
    R = {"P1-01": {"evidence": {"code": "d1"}}, "P2-01": {"evidence": {"code": "d1"}}}
    def test_changed_code_invalidates_direct_and_downstream(self):
        out, rep = migrate.invalidate(rows(), {"P1-01": {"evidence": {"code": "d1"}}}, {"code": "d2"})
        self.assertEqual(rep["direct"], ["P1-01"]); self.assertEqual(rep["invalidated"], ["P1-01", "P2-01"])
        self.assertEqual({r["task_id"]: r["status"] for r in out}["P1-02"], "PENDING")
    def test_unchanged_evidence_invalidates_nothing(self):
        _, rep = migrate.invalidate(rows(), self.R, {"code": "d1"}); self.assertEqual(rep["invalidated"], [])
    def test_unrelated_evidence_key_ignored(self):
        _, rep = migrate.invalidate(rows(), self.R, {"other": "x"}); self.assertEqual(rep["invalidated"], [])
    def test_no_rows_deleted_and_pending_not_promoted(self):
        out, _ = migrate.invalidate(rows(), self.R, {"code": "d2"}); self.assertEqual(len(out), 3); self.assertEqual(out[1]["status"], "PENDING")
    def test_explicit_edges_followed(self):
        r = rows(); r[2]["depends_on"] = []
        _, rep = migrate.invalidate(r, {"P1-01": {"evidence": {"c": "1"}}}, {"c": "2"}, edges=[("P1-01", "P2-01")]); self.assertIn("P2-01", rep["invalidated"])
    def test_cycle_terminates(self):
        r = rows(); r[0]["depends_on"] = ["P2-01"]
        _, rep = migrate.invalidate(r, {"P1-01": {"evidence": {"c": "1"}}}, {"c": "2"}); self.assertIn("P1-01", rep["invalidated"])

class Profiles(unittest.TestCase):
    def test_all_classes_present(self): self.assertEqual(set(profiles.PROFILES), {"CODE", "EXPERIMENT", "EXTERNAL", "DECISION", "LIVE_EFFECT"})
    def test_code_denies_network_secrets_live(self):
        for q in ({"network": "any"}, {"secrets": "x"}, {"live_effect": True}): self.assertFalse(profiles.authorize("CODE", q)[0])
        self.assertTrue(profiles.authorize("CODE", {})[0])
    def test_live_effect_needs_signature(self):
        self.assertFalse(profiles.authorize("LIVE_EFFECT", {"live_effect": True})[0])
        self.assertFalse(profiles.authorize("LIVE_EFFECT", {"live_effect": True, "approval": "chat"})[0])
        self.assertTrue(profiles.authorize("LIVE_EFFECT", {"live_effect": True, "network": "allowlist", "approval": "human_signature_per_effect"})[0])
    def test_external_and_decision_need_approval(self):
        self.assertFalse(profiles.authorize("EXTERNAL", {})[0]); self.assertFalse(profiles.authorize("DECISION", {})[0])
        self.assertTrue(profiles.authorize("DECISION", {"approval": "human_signature"})[0])
    def test_unknown_class_denied(self): self.assertFalse(profiles.authorize("NOPE", {})[0])
    def test_coverage_reports_gaps(self):
        rep = profiles.high_risk_coverage(rows(), {"P1-01": {"cmds": [["x"]]}}); self.assertEqual(rep["gaps"], ["P1-01"]); self.assertEqual(rep["with_commands"], 1)
        rep = profiles.high_risk_coverage(rows(), {"P1-01": {"cmds": [["x"]], "oracle": "o"}}); self.assertEqual(rep["gaps"], []); self.assertEqual(rep["with_named_oracle"], 1)
        rep = profiles.high_risk_coverage(rows(), {"P1-01": {"oracle": "o"}}); self.assertEqual(rep["gaps"], ["P1-01"])
    def test_compiled_plan_classes_all_have_profiles(self):
        rs = [json.loads(l) for l in open(os.path.join(ROOT, "spec/task_compiled.jsonl"))]
        self.assertTrue({r["work_class"] for r in rs} <= set(profiles.PROFILES))
    def test_rcr_is_machine_node(self):
        d = json.load(open(os.path.join(ROOT, "spec/dependencies.yaml"))); self.assertTrue(d["gates"]["RC-R"]["requires_external_signature"])
        rs = [json.loads(l) for l in open(os.path.join(ROOT, "spec/task_compiled.jsonl"))]
        self.assertTrue(all("GATE:RC-R" in r["depends_on"] for r in rs if 55 <= r["phase"] <= 74))
if __name__ == "__main__": unittest.main()
