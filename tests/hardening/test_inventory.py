import copy, importlib.util, json, os, re, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
spec = importlib.util.spec_from_file_location("hinv", os.path.join(ROOT, "scripts/hardening_inventory.py")); H = importlib.util.module_from_spec(spec); spec.loader.exec_module(H)
DOC = open(H.DOC, encoding="utf-8").read()


class Parse(unittest.TestCase):
    def test_every_doc_task_id_present_exactly_once(self):
        ids = re.findall(r"^- \[[ x]\] \*\*([A-G]\d{2}-(?:\d{2}|GATE))\*\*", DOC, re.M)
        inv = H.render(); got = [t["id"] for m in inv["modules"] for t in m["tasks"]]
        self.assertEqual(sorted(ids), sorted(got)); self.assertEqual(len(set(got)), len(got)); self.assertGreater(len(got), 200)

    def test_every_module_has_gate_task_and_paths(self):
        for m in H.render()["modules"]:
            self.assertTrue(any(t["id"] == m["id"] + "-GATE" for t in m["tasks"]), m["id"])
            self.assertTrue(m["code_paths"], m["id"])

    def test_all_declared_code_paths_exist(self):
        for m in H.render()["modules"]:
            for p in m["code_paths"]: self.assertTrue(p["exists"], (m["id"], p["path"]))

    def test_six_gates_parsed_all_open(self):
        inv = H.render(); self.assertEqual([g["id"] for g in inv["gates"]], ["G0", "G1", "G2", "G3", "G4", "G5"])
        self.assertTrue(all(g["status"] == "OPEN" and not any(i["done"] for i in g["items"]) for g in inv["gates"]))

    def test_all_gate_tasks_classified_external(self):
        for m in H.render()["modules"]:
            self.assertEqual([t["class_heuristic"] for t in m["tasks"] if t["id"].endswith("GATE")], ["EXTERNAL"])

    def test_committed_inventory_is_current_and_clean(self):
        inv = H.render(); self.assertEqual(open(H.OUT).read(), json.dumps(inv, indent=1, sort_keys=True) + "\n"); self.assertEqual(H.problems(inv), [])


class Helpers(unittest.TestCase):
    def test_gate_classified_external_regardless_of_text(self): self.assertEqual(H.classify({"id": "A01-GATE", "text": "foo"}), "EXTERNAL")
    def test_plain_task_is_doable_here(self): self.assertEqual(H.classify({"id": "A01-01", "text": "Write a table"}), "DOABLE_HERE")
    def test_reviewer_task_is_external(self): self.assertEqual(H.classify({"id": "A01-05", "text": "Commission independent review"}), "EXTERNAL")
    def test_missing_path_flagged(self):
        r = H.code_paths("`nope/x.py; horizon/schemas.py`"); self.assertEqual([x["exists"] for x in r], [False, True])


class Blocked(unittest.TestCase):
    def test_blocked_md_current_and_lists_every_gate_task(self):
        inv = H.render(); md = H.render_blocked(inv); self.assertEqual(open(H.BLK).read(), md)
        for m in inv["modules"]: self.assertIn(f"`{m['id']}-GATE`", md)
    def test_done_task_excluded_from_blocked(self):
        import copy; i = copy.deepcopy(H.render()); t = [x for x in i["modules"][0]["tasks"] if x["class_heuristic"] == "EXTERNAL" and not x["id"].endswith("GATE")]
        if t: t[0]["done"] = True; self.assertNotIn(f"`{t[0]['id']}`", H.render_blocked(i))


class Integrity(unittest.TestCase):
    def setUp(self): self.inv = H.render()

    def test_no_module_above_candidate(self):
        self.assertTrue(all(m["status"] in ("CANDIDATE", "BLOCKED") for m in self.inv["modules"]))
        self.assertTrue(all(m["independent_attestation"] is None for m in self.inv["modules"]))

    def test_verified_without_attestation_rejected(self):
        i = copy.deepcopy(self.inv); i["modules"][0]["status"] = "INDEPENDENTLY_VERIFIED"
        self.assertTrue(any("without independent_attestation" in p for p in H.problems(i)))

    def test_hardened_without_attestation_rejected(self):
        i = copy.deepcopy(self.inv); i["modules"][3]["status"] = "HARDENED_FOR_SCOPE"
        self.assertTrue(H.problems(i))

    def test_attestation_requires_reviewer_identity(self):
        i = copy.deepcopy(self.inv); i["modules"][0]["independent_attestation"] = "sig"
        self.assertTrue(any("reviewer_identity" in p for p in H.problems(i)))

    def test_done_without_evidence_rejected(self):
        i = copy.deepcopy(self.inv); i["modules"][0]["tasks"][0]["done"] = True
        self.assertTrue(any("without evidence" in p for p in H.problems(i)))

    def test_done_with_missing_evidence_file_rejected(self):
        i = copy.deepcopy(self.inv); t = i["modules"][0]["tasks"][0]; t.update(done=True, evidence=["nope.txt"])
        self.assertTrue(any("evidence missing" in p for p in H.problems(i)))

    def test_done_with_wrong_digest_rejected(self):
        i = copy.deepcopy(self.inv); t = i["modules"][0]["tasks"][0]; t.update(done=True, evidence=["LICENSE"], evidence_digests={"LICENSE": "0" * 64})
        self.assertTrue(any("digest mismatch" in p for p in H.problems(i)))

    def test_done_with_correct_digest_accepted(self):
        i = copy.deepcopy(self.inv); t = i["modules"][0]["tasks"][0]; t.update(done=True, evidence=["LICENSE"], evidence_digests={"LICENSE": H.digest("LICENSE")})
        self.assertEqual(H.problems(i), [])

    def test_gate_task_done_needs_attestation_even_with_evidence(self):
        i = copy.deepcopy(self.inv); m = i["modules"][0]; t = [x for x in m["tasks"] if x["id"].endswith("GATE")][0]
        t.update(done=True, evidence=["LICENSE"], evidence_digests={"LICENSE": H.digest("LICENSE")})
        self.assertTrue(any("GATE done without attestation" in p for p in H.problems(i)))

    def test_duplicate_task_rejected(self):
        i = copy.deepcopy(self.inv); i["modules"][0]["tasks"].append(copy.deepcopy(i["modules"][0]["tasks"][0]))
        self.assertTrue(any("duplicate" in p for p in H.problems(i)))

    def test_bad_status_rejected(self):
        i = copy.deepcopy(self.inv); i["modules"][0]["status"] = "VERIFIED"
        self.assertTrue(any("bad status" in p for p in H.problems(i)))

    def test_doc_checkbox_does_not_set_done(self):
        # a [x] in the prose document must never count as completion evidence
        mods, _ = H.parse(DOC.replace("- [ ] **A01-01**", "- [x] **A01-01**", 1)); self.assertTrue(mods[0]["tasks"][0]["doc_checked"])
        orig = H.parse; H.parse = lambda t: orig(DOC.replace("- [ ] **A01-01**", "- [x] **A01-01**", 1))
        try: self.assertFalse(H.render()["modules"][0]["tasks"][0]["done"])
        finally: H.parse = orig

if __name__ == "__main__": unittest.main()
