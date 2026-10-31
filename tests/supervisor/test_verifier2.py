"""P85 verifier tests against REAL git repos (synthetic content). Covers worker tampering, fabricated claims, UNKNOWN coverage, key handling."""
import os, subprocess, sys, tempfile, unittest
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from orchestrator.ledger import Ledger, LedgerError
from orchestrator import verifier2 as V
from tests.supervisor.test_supervisor import rows, lock

VKEY = b"verifier-key-1"
PR = {"sup": ("supervisor", b"s"), "w1": ("worker", b"w1"), "ver": ("verifier", VKEY)}
ENVIRON = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
ACC = [["python3", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"]]
PROT = ["tests/*", "grader/*"]


def g(cwd, *a):
    p = subprocess.run(["git", *a], cwd=cwd, capture_output=True, text=True, env={**os.environ, **ENVIRON}); assert p.returncode == 0, p.stderr; return p.stdout.strip()


def write(root, rel, text):
    f = Path(root) / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(text)


class Base(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp(); g(self.repo, "init", "-q", "-b", "main")
        write(self.repo, "src/calc.py", "def add(a, b):\n    return a + b\n")
        write(self.repo, "tests/test_calc.py", "import sys, unittest\nsys.path.insert(0, 'src')\nfrom calc import add\nclass T(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(2, 2), 4)\nunittest.main() if __name__ == '__main__' else None\n")
        g(self.repo, "add", "-A"); g(self.repo, "commit", "-qm", "base"); self.base = g(self.repo, "rev-parse", "HEAD")
        self.ks = V.KeyStore(); self.ks.add("k1", VKEY, 0, 10_000)
        self.led = Ledger(Path(tempfile.mkdtemp()) / "l.db", PR); self.led.load_plan(rows(), lock()); self.led.refresh_ready("sup")
        self.ep = self.led.lease("P0-01", "sup", "w1")

    def worker_commit(self, files: dict, delete=()):
        self.n = getattr(self, "n", 0) + 1; g(self.repo, "checkout", "-q", "-b", f"w{self.n}", self.base)
        for k, v in files.items(): write(self.repo, k, v)
        for d in delete: os.remove(Path(self.repo) / d)
        g(self.repo, "add", "-A"); g(self.repo, "commit", "-q", "--allow-empty", "-m", "work"); sha = g(self.repo, "rev-parse", "HEAD"); g(self.repo, "checkout", "-q", "main"); return sha

    def run_v(self, commit, **kw):
        a = dict(repo=self.repo, base=self.base, commit=commit, task="P0-01", attempt=1, epoch=self.ep, plan_digest=self.led.plan_digest(), acceptance=ACC,
                 protected_globs=PROT, required_sinks=[], independent_observed=[], env_digest="env1", verifier_id="ver", keystore=self.ks, key_id="k1", now=100.0)
        a.update(kw); return V.verify_task(**a)

    def submit(self, commit): self.led.submit("P0-01", "w1", self.ep, commit)


class Outcomes(Base):
    def test_honest_work_passes_and_ledger_verifies(self):
        c = self.worker_commit({"src/mul.py": "def mul(a, b):\n    return a * b\n", "tests/test_mul.py": "import sys, unittest\nsys.path.insert(0, 'src')\nfrom mul import mul\nclass M(unittest.TestCase):\n    def test(self):\n        self.assertEqual(mul(3, 3), 9)\n"})
        self.submit(c); r, env, sig, _ = self.run_v(c); self.assertEqual((env["verdict"], r["exit_code"]), ("PASS", 0))
        self.assertEqual(self.led.accept_receipt("P0-01", r, sig), "VERIFIED")

    def test_broken_code_fails_and_retry_wait(self):
        c = self.worker_commit({"src/calc.py": "def add(a, b):\n    return a - b\n"}); self.submit(c)
        r, env, sig, d = self.run_v(c); self.assertEqual(env["verdict"], "FAIL"); self.assertNotEqual(r["exit_code"], 0)
        self.assertEqual(self.led.accept_receipt("P0-01", r, sig), "RETRY_WAIT")
        rep = V.failure_report(env, d); self.assertEqual(rep["failed_command"], ACC[0]); self.assertIn(c, rep["repro"][0])

    def test_uncommitted_working_tree_changes_are_ignored(self):
        c = self.worker_commit({}); write(self.repo, "src/calc.py", "def add(a, b):\n    return 0\n")           # dirty, uncommitted
        self.assertEqual(self.run_v(c)[1]["verdict"], "PASS")


class Tampering(Base):
    def test_weakened_existing_test_is_flagged_and_not_run(self):
        c = self.worker_commit({"src/calc.py": "def add(a, b):\n    return 5\n", "tests/test_calc.py": "import unittest\nclass T(unittest.TestCase):\n    def test_add(self):\n        self.assertTrue(True)\n"})
        r, env, sig, d = self.run_v(c); self.assertEqual(env["verdict"], "FAIL"); self.assertEqual(d["results"], [])
        self.assertEqual(env["tamper"]["modified_protected"], ["M tests/test_calc.py"])

    def test_deleted_test_and_modified_grader(self):
        c = self.worker_commit({}, delete=["tests/test_calc.py"]); self.assertEqual(self.run_v(c)[1]["tamper"]["modified_protected"], ["D tests/test_calc.py"])

    def test_shadowing_files_flagged(self):
        for name in ("tests/conftest.py", "sitecustomize.py", "pytest.ini", "evil.pth"):
            c = self.worker_commit({name: "x"}); env = self.run_v(c)[1]
            self.assertEqual((env["verdict"], env["tamper"]["shadowing_additions"]), ("FAIL", [name]), name)


class Fabrication(Base):
    def test_verdict_comes_only_from_own_replay_worker_claims_are_not_inputs(self):
        c = self.worker_commit({"src/calc.py": "def add(a, b):\n    return 1\n"}); self.submit(c)
        with self.assertRaises(TypeError): self.run_v(c, worker_exit_code=0)                       # no parameter accepts worker claims
        r, env, sig, _ = self.run_v(c, observations=[{"source": "worker_reported", "sink": "net", "ok": True}])
        self.assertEqual(env["verdict"], "FAIL")

    def test_worker_cannot_forge_receipt_with_worker_key_or_guess(self):
        c = self.worker_commit({}); self.submit(c); r, env, sig, _ = self.run_v(c)
        from orchestrator.ledger import sign
        for bad in (sign(b"w1", r), sign(b"guess", r), "", sig[:-1] + ("0" if sig[-1] != "0" else "1")):
            with self.assertRaises(LedgerError): self.led.accept_receipt("P0-01", r, bad)
        self.assertEqual(self.led.status("P0-01"), "VERIFYING")

    def test_receipt_for_unrelated_commit_or_swapped_fields_rejected(self):
        a = self.worker_commit({"a.txt": "1"}); b = self.worker_commit({"b.txt": "2"}); self.submit(a)
        r, env, sig, _ = self.run_v(b)                                                           # valid receipt, but for another commit
        with self.assertRaises(LedgerError): self.led.accept_receipt("P0-01", r, sig)
        r2, _, sig2, _ = self.run_v(a); r3 = {**r2, "key_id": "k2"}
        with self.assertRaises(LedgerError): self.led.accept_receipt("P0-01", r3, sig2)         # signature substitution across key ids
        r4 = {**r2, "verdict": "UNKNOWN"}
        with self.assertRaises(LedgerError): self.led.accept_receipt("P0-01", r4, sig2)          # edited verdict breaks the signature

    def test_replayed_receipt_cannot_verify_a_later_attempt(self):
        c = self.worker_commit({}); self.submit(c); r, _, sig, _ = self.run_v(c); self.assertEqual(self.led.accept_receipt("P0-01", r, sig), "VERIFIED")
        with self.assertRaises(LedgerError): self.led.accept_receipt("P0-01", r, sig)
        self.led.invalidate("P0-01", "sup", "changed"); self.led.mark("P0-01", "READY", "sup", "again"); ep2 = self.led.lease("P0-01", "sup", "w1")
        self.led.submit("P0-01", "w1", ep2, c)
        with self.assertRaises(LedgerError): self.led.accept_receipt("P0-01", r, sig)            # old receipt carries the old epoch

    def test_contradictory_verdicts_rejected_by_ledger(self):
        c = self.worker_commit({}); self.submit(c); r, _, _, _ = self.run_v(c)
        from orchestrator.ledger import sign
        for bad in ({**r, "verdict": "FAIL"}, {**r, "verdict": "UNKNOWN"}, {**r, "verdict": "WAT"}, {**r, "exit_code": 1, "verdict": "PASS"}):
            with self.assertRaises(LedgerError): self.led.accept_receipt("P0-01", bad, sign(VKEY, bad))


class Coverage(Base):
    def test_missing_telemetry_is_unknown_never_pass(self):
        c = self.worker_commit({}); self.submit(c)
        r, env, sig, _ = self.run_v(c, required_sinks=["net.egress", "fs.write"], independent_observed=["fs.write"],
                                    observations=[{"source": "worker_reported", "sink": "net.egress"}])
        self.assertEqual((env["verdict"], env["coverage"]["unobserved"]), ("UNKNOWN", ["net.egress"]))
        self.assertTrue(all(not o["counts_toward_coverage"] for o in env["observations"]))
        self.assertEqual(self.led.accept_receipt("P0-01", r, sig), "NEEDS_RECONCILIATION")
        full = self.run_v(c, required_sinks=["net.egress"], independent_observed=["net.egress"])[1]; self.assertEqual(full["verdict"], "PASS")


class Environment(Base):
    def test_credentials_in_parent_env_do_not_reach_commands(self):
        os.environ["LEAK_TOKEN"] = "sekrit"; self.addCleanup(os.environ.pop, "LEAK_TOKEN", None)
        probe = [["python3", "-c", "import os,sys; sys.exit(1 if any(k in os.environ for k in ('LEAK_TOKEN','GITHUB_TOKEN','AWS_SECRET_ACCESS_KEY')) else 0)"]]
        self.assertEqual(self.run_v(self.worker_commit({}), acceptance=probe)[1]["verdict"], "PASS")

    def test_program_allowlist_and_short_sha(self):
        c = self.worker_commit({})
        with self.assertRaises(V.VerifierError): self.run_v(c, acceptance=[["sh", "-c", "true"]])
        with self.assertRaises(V.VerifierError): self.run_v(c[:12])
        with self.assertRaises(V.VerifierError): self.run_v("g" * 40)

    def test_timeout_is_a_failure(self):
        r, env, _, _ = self.run_v(self.worker_commit({}), acceptance=[["python3", "-c", "import time; time.sleep(5)"]], timeout=1)
        self.assertEqual((env["verdict"], r["exit_code"]), ("FAIL", 124))


class Keys(Base):
    def test_revocation_expiry_and_ledger_revocation(self):
        c = self.worker_commit({}); self.submit(c)
        with self.assertRaises(V.VerifierError): self.run_v(c, now=20_000.0)                      # outside validity window
        self.ks.revoke("k1", "compromised")
        with self.assertRaises(V.VerifierError): self.run_v(c)
        self.assertFalse(self.ks.verify("k1", {"a": 1}, "00", 100.0))
        self.ks.revoked.clear(); r, _, sig, _ = self.run_v(c)
        self.led.revoke_principal("ver", "sup", "key compromised")
        with self.assertRaises(LedgerError): self.led.accept_receipt("P0-01", r, sig)             # revoked principal's receipt refused
        with self.assertRaises(LedgerError): self.led.revoke_principal("ver", "w1", "x")

    def test_verifier_crash_never_promotes_in_flight_candidate(self):
        c = self.worker_commit({}); self.submit(c)
        with self.assertRaises(V.VerifierError): self.run_v(c, repo="/nonexistent/repo")          # verifier lost mid-flight
        self.assertEqual(self.led.status("P0-01"), "VERIFYING")
        r, _, sig, _ = self.run_v(c); self.assertEqual(self.led.accept_receipt("P0-01", r, sig), "VERIFIED")   # recovers and completes


class Reports(Base):
    def test_failure_report_scrubs_and_audit_export_has_no_output(self):
        write(self.repo, "tests/test_calc.py", open(Path(self.repo) / "tests/test_calc.py").read())
        c = self.worker_commit({"tests/test_new.py": "import unittest\nclass T(unittest.TestCase):\n    def test(self):\n        print('token=abc123secret')\n        self.fail('boom')\n"})
        r, env, sig, d = self.run_v(c); rep = V.failure_report(env, d)
        self.assertNotIn("abc123secret", str(rep)); self.assertIn("boom", rep["output_tail"])
        ex = V.audit_export(env); self.assertNotIn("output_tail", str(ex)); self.assertNotIn("boom", str(ex)); self.assertNotIn("abc123", str(ex))
        self.assertIn("stdout_sha256", ex["commands"][0])


if __name__ == "__main__": unittest.main()
