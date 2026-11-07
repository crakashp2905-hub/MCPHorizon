import copy, json, os, sys, tempfile, unittest
R = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, R)
from security_hardening import roadmap as rm
DOC = "# x\n- [ ] S0-01 first thing\n- [ ] S0-GATE gate thing\n- [ ] S1-01 third | pipe\nprose\n"
class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.f = os.path.join(self.d, "ev.txt"); open(self.f, "w").write("evidence")
        self.doc = rm.parse_doc(DOC)
        self.st = {"doc_sha256": "a" * 64, "tasks": {"S0-01": {"status": "CANDIDATE", "evidence": {"ev.txt": rm.sha(self.f)}, "note": "limits"}, "S0-GATE": {"status": "BLOCKED", "blocked_by": "reviewer"}, "S1-01": {"status": "OPEN"}}}
    def P(self, st=None): return rm.problems(self.doc, st or self.st, self.d, "a" * 64)
class Parse(Base):
    def test_parse(self): self.assertEqual(list(self.doc), ["S0-01", "S0-GATE", "S1-01"])
    def test_duplicate_rejected(self):
        with self.assertRaises(ValueError): rm.parse_doc("- [ ] S0-01 a\n- [x] S0-01 b\n")
    def test_empty_rejected(self):
        with self.assertRaises(ValueError): rm.parse_doc("nothing")
    def test_real_doc_has_74_tasks(self):
        d = rm.parse_doc(open(os.path.join(R, "docs/roadmap/BOUNDARY_SYNTHESIS_BLUEPRINT_2026-11-07.md")).read()); self.assertEqual(len(d), 74); self.assertEqual(sum(k.endswith("-GATE") for k in d), 7)
class Rules(Base):
    def test_clean(self): self.assertEqual(self.P(), [])
    def test_doc_digest(self): self.assertIn("DOC_DIGEST_MISMATCH", rm.problems(self.doc, self.st, self.d, "b" * 64))
    def test_untracked_and_extra(self):
        s = copy.deepcopy(self.st); del s["tasks"]["S1-01"]; s["tasks"]["S9-01"] = {"status": "OPEN"}
        self.assertEqual(sorted(self.P(s)), ["NOT_IN_DOC:S9-01", "UNTRACKED:S1-01"])
    def test_no_tasks(self): self.assertEqual(self.P({"doc_sha256": "a" * 64}), ["NO_TASKS"])
    def test_status_vocabulary_closed(self):
        for bad in ("DONE", "INDEPENDENTLY_VERIFIED", "HARDENED_FOR_SCOPE", "candidate", None):
            s = copy.deepcopy(self.st); s["tasks"]["S1-01"]["status"] = bad; self.assertEqual(self.P(s), ["BAD_STATUS:S1-01"])
    def test_gate_cannot_be_candidate(self):
        s = copy.deepcopy(self.st); s["tasks"]["S0-GATE"] = copy.deepcopy(s["tasks"]["S0-01"]); self.assertEqual(self.P(s), ["GATE_CANNOT_BE_CANDIDATE:S0-GATE"])
    def test_candidate_needs_evidence_and_note(self):
        s = copy.deepcopy(self.st); s["tasks"]["S0-01"]["evidence"] = {}; self.assertEqual(self.P(s), ["NO_EVIDENCE:S0-01"])
        s = copy.deepcopy(self.st); del s["tasks"]["S0-01"]["evidence"]; self.assertEqual(self.P(s), ["NO_EVIDENCE:S0-01"])
        s = copy.deepcopy(self.st); s["tasks"]["S0-01"]["note"] = "  "; self.assertEqual(self.P(s), ["NO_LIMITS_NOTE:S0-01"])
    def test_stale_or_bad_digest(self):
        s = copy.deepcopy(self.st); s["tasks"]["S0-01"]["evidence"]["ev.txt"] = "0" * 64; self.assertEqual(self.P(s), ["EVIDENCE_STALE:S0-01:ev.txt"])
        s["tasks"]["S0-01"]["evidence"]["ev.txt"] = "zz"; self.assertEqual(self.P(s), ["EVIDENCE_STALE:S0-01:ev.txt"])
        open(self.f, "w").write("changed"); s2 = copy.deepcopy(self.st); self.assertEqual(self.P(s2), ["EVIDENCE_STALE:S0-01:ev.txt"])
    def test_missing_or_escaping_evidence(self):
        s = copy.deepcopy(self.st); s["tasks"]["S0-01"]["evidence"] = {"nope.txt": "0" * 64}; self.assertEqual(self.P(s), ["EVIDENCE_MISSING:S0-01:nope.txt"])
        outside = os.path.join(os.path.dirname(self.d), "outside_%d.txt" % os.getpid()); open(outside, "w").write("x")
        try:
            s["tasks"]["S0-01"]["evidence"] = {"../" + os.path.basename(outside): rm.sha(outside)}; self.assertEqual(len(self.P(s)), 1); self.assertTrue(self.P(s)[0].startswith("EVIDENCE_MISSING"))
        finally: os.remove(outside)
    def test_blocked_needs_blocker(self):
        for b in (None, "", "  ", 5):
            s = copy.deepcopy(self.st); s["tasks"]["S0-GATE"] = {"status": "BLOCKED", "blocked_by": b}; self.assertEqual(self.P(s), ["NO_BLOCKER:S0-GATE"])
    def test_open_cannot_carry_claims(self):
        s = copy.deepcopy(self.st); s["tasks"]["S1-01"] = {"status": "OPEN", "evidence": {"ev.txt": rm.sha(self.f)}}; self.assertEqual(self.P(s), ["OPEN_WITH_CLAIMS:S1-01"])
        s["tasks"]["S1-01"] = {"status": "OPEN", "blocked_by": "x"}; self.assertEqual(self.P(s), ["OPEN_WITH_CLAIMS:S1-01"])
    def test_unknown_keys_rejected(self):
        s = copy.deepcopy(self.st); s["tasks"]["S1-01"] = {"status": "OPEN", "verified_by": "me"}; self.assertEqual(self.P(s), ["BAD_RECORD:S1-01"])
        s["tasks"]["S1-01"] = "OPEN"; self.assertEqual(self.P(s), ["BAD_RECORD:S1-01"])
class Report(Base):
    def test_counts_and_no_verified_claim(self):
        r = rm.report(self.doc, self.st); self.assertIn("Tasks: 3 | OPEN 1 | CANDIDATE 1 | BLOCKED 1 | INDEPENDENTLY_VERIFIED 0", r); self.assertIn("NOT integrated", r)
class Repo(unittest.TestCase):
    def test_committed_status_file_is_consistent(self):
        import subprocess
        r = subprocess.run([sys.executable, "-B", os.path.join(R, "scripts/blueprint_roadmap.py"), "--check"], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stdout)
    def test_no_gate_is_candidate_and_none_above_candidate(self):
        s = json.load(open(os.path.join(R, "docs/roadmap/blueprint_status.json")))["tasks"]
        self.assertTrue(all(v["status"] in rm.STATUSES for v in s.values())); self.assertTrue(all(v["status"] != "CANDIDATE" for k, v in s.items() if k.endswith("-GATE")))
    def test_owner_signoff_not_touched_by_tracker(self):
        s = json.load(open(os.path.join(R, "docs/roadmap/blueprint_status.json")))["tasks"]; self.assertEqual(s["S0-03"]["status"], "BLOCKED")
if __name__ == "__main__": unittest.main()
