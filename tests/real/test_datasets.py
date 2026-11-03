"""Tests on HAND-WRITTEN FIXTURE repos (tiny, synthetic). Real validation output: bench/real/results/dataset_validation.json."""
import json, os, subprocess, sys, tempfile, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, ROOT)
from bench.real import datasets as D
MIT = "Permission is hereby granted, free of charge, to any person obtaining a copy"

def repo(files, url="https://example.invalid/o/r"):
    t = tempfile.TemporaryDirectory(); d = t.name
    for rel, txt in files.items():
        p = os.path.join(d, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f: f.write(txt)
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
    for a in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "x"], ["remote", "add", "origin", url]):
        subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, env=env)
    return t

class T(unittest.TestCase):
    def test_good_repo_passes(self):
        t = repo({"LICENSE": MIT, "d/a.jsonl": '{"q":"one"}\n{"q":"two"}\n', "d/b.csv": "x,y\n1,2\n3,4\n", "d/c.json": '[{"k":1},{"k":2},{"k":3}]'})
        r = D.validate(t.name, "https://example.invalid/o/r")
        self.assertEqual((r["status"], r["license"], r["records"], r["data_files_parsed"], r["parse_failures"]), ("PASS", "MIT", 7, 3, 0)); self.assertEqual(len(r["commit"]), 40); self.assertEqual(len(r["tree_sha256"]), 64)
    def test_parse_failure_is_reported(self):
        t = repo({"LICENSE": MIT, "a.json": "{not json", "b.json": "[1]"}); r = D.validate(t.name)
        self.assertEqual((r["parse_failures"], r["data_files_parsed"], r["status"]), (1, 1, "WARN")); self.assertIn("a.json", r["parse_failure_examples"][0])
    def test_jsonl_bad_line_is_failure(self):
        t = repo({"LICENSE": MIT, "a.jsonl": '{"a":1}\nBROKEN\n'}); self.assertEqual(D.validate(t.name)["parse_failures"], 1)
    def test_license_detection(self):
        for txt, want in ((MIT, "MIT"), ("Apache License, Version 2.0", "Apache-2.0"), ("hello", "UNRECOGNISED")):
            t = repo({"LICENSE": txt, "a.json": "[1]"}); self.assertEqual(D.detect_license(t.name), want)
        t = repo({"a.json": "[1]"}); self.assertEqual(D.detect_license(t.name), "NONE"); self.assertIn("license NONE", D.validate(t.name)["reasons"])
    def test_origin_mismatch_warns(self):
        t = repo({"LICENSE": MIT, "a.json": "[1]"}); r = D.validate(t.name, "https://example.invalid/other/repo")
        self.assertFalse(r["origin_matches"]); self.assertEqual(r["status"], "WARN")
    def test_origin_match_ignores_case_and_dot_git(self):
        t = repo({"LICENSE": MIT, "a.json": "[1]"}, url="https://Example.invalid/O/R.git"); self.assertTrue(D.validate(t.name, "https://example.invalid/o/r")["origin_matches"])
    def test_duplicates_counted(self):
        t = repo({"LICENSE": MIT, "a.jsonl": '{"q":"same"}\n{"q":"same"}\n{"q":"other"}\n'}); self.assertEqual(D.validate(t.name)["exact_duplicate_records"], 1)
    def test_lfs_stub_flagged_and_not_parsed(self):
        t = repo({"LICENSE": MIT, "big.json": "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 9\n", "ok.json": "[1]"}); r = D.validate(t.name)
        self.assertEqual((r["lfs_stub_files"], r["parse_failures"], r["data_files_parsed"], r["status"]), (1, 0, 1, "WARN"))
    def test_credential_like_strings_counted(self):
        t = repo({"LICENSE": MIT, "a.jsonl": json.dumps({"q": "key AKIA" + "A" * 16 + " here"}) + "\n"}); self.assertEqual(D.validate(t.name)["credential_like_strings"], 1)
    def test_tree_digest_changes_with_content_and_is_stable(self):
        a = repo({"LICENSE": MIT, "a.json": "[1]"}); b = repo({"LICENSE": MIT, "a.json": "[2]"}); c = repo({"LICENSE": MIT, "a.json": "[1]"})
        self.assertEqual(D.validate(a.name)["tree_sha256"], D.validate(c.name)["tree_sha256"]); self.assertNotEqual(D.validate(a.name)["tree_sha256"], D.validate(b.name)["tree_sha256"])
    def test_no_data_files_warns(self):
        t = repo({"LICENSE": MIT, "README.md": "x"}); r = D.validate(t.name); self.assertEqual(r["status"], "WARN"); self.assertIn("no parsable data files", r["reasons"])
    def test_skip_dirs_and_git_dir_ignored(self):
        t = repo({"LICENSE": MIT, "runs/x.json": "{bad", "a.json": "[1]"}); r = D.validate(t.name, skip_dirs=("runs/",)); self.assertEqual((r["parse_failures"], r["data_files_parsed"]), (0, 1))
    def test_csv_and_tsv_rows(self):
        t = repo({"LICENSE": MIT, "a.tsv": "x\ty\n1\t2\n", "b.csv": "p\n1\n2\n"}); self.assertEqual(D.validate(t.name)["records"], 3)
    def test_tsv_uses_tab_delimiter(self):
        t = repo({"a.tsv": "x\ty\n1\t2\n"}); recs, kind = D._records(os.path.join(t.name, "a.tsv")); self.assertEqual(list(recs[0]), ["x", "y"])
    def test_dot_git_directory_is_never_scanned(self):
        t = repo({"LICENSE": MIT, "a.json": "[1]"}); os.makedirs(os.path.join(t.name, ".git", "zz")); open(os.path.join(t.name, ".git", "zz", "bad.json"), "w").write("{bad")
        self.assertEqual(D.validate(t.name)["parse_failures"], 0)
    def test_llama_license_and_restrictions(self):
        t = repo({"LICENSE": "LLAMA 3.2 COMMUNITY LICENSE AGREEMENT", "a.json": "[1]"}); r = D.validate(t.name)
        self.assertIn("Llama", r["license"]); self.assertEqual(r["license_restrictions"], "custom/restricted")
        t = repo({"LICENSE": "Attribution-NonCommercial 4.0", "a.json": "[1]"}); self.assertEqual(D.validate(t.name)["license_restrictions"], "non-commercial")
        t = repo({"LICENSE": MIT, "a.json": "[1]"}); self.assertEqual(D.validate(t.name)["license_restrictions"], "none-known")
        t = repo({"a.json": "[1]"}); self.assertTrue(D.validate(t.name)["license_restrictions"].startswith("unknown"))
    def test_tooling_json_is_not_data(self):
        t = repo({"LICENSE": MIT, "tsconfig.app.json": "{ /* comment */ }", "package.json": "{bad", "node_modules/x/y.json": "{bad", "d.json": "[1]"}); r = D.validate(t.name)
        self.assertEqual((r["parse_failures"], r["data_files_parsed"]), (0, 1))
    def test_registry_is_wellformed(self):
        with open(os.path.join(ROOT, "bench/real/REGISTRY.json")) as f: reg = json.load(f)
        ids = [e["id"] for e in reg]; self.assertEqual(len(ids), len(set(ids))); self.assertGreaterEqual(len(reg), 20)
        for e in reg:
            self.assertEqual(set(e), {"id", "dir", "url", "category", "role"}, e["id"]); self.assertTrue(e["url"].startswith("https://github.com/"))
            self.assertIn(e["category"], {"agent_injection_trajectories", "agent_injection_cases", "mcp_security", "agent_safety_cases", "jailbreak_text", "benign_agent_tasks", "redteam_tooling"})
if __name__ == "__main__": unittest.main()
