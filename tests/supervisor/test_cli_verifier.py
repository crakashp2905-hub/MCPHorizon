"""P75 CLI integrity + P77 false-completion attack tests."""
import json, os, shutil, subprocess, sys, tempfile, threading, unittest
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from orchestrator.ledger import Ledger, LedgerError, sign
from tests.supervisor.test_supervisor import K, SHA, rows, lock


def cli(root, *args, ledger=None):
    env = {**os.environ, "HORIZON_ROOT": str(root)}
    led = ledger or str(Path(root) / "l.db")
    p = subprocess.run([sys.executable, str(REPO / "scripts/horizon_plan.py"), "--ledger", led, *args], capture_output=True, text=True, env=env)
    return p.returncode, p.stdout, p.stderr


def clone():
    d = Path(tempfile.mkdtemp()); (d / "spec").mkdir()
    for f in ("task_compiled.jsonl", "plan.lock", "dependencies.yaml"): shutil.copy(REPO / "spec" / f, d / "spec" / f)
    return d


class Cli(unittest.TestCase):
    def test_commands_and_exit_codes(self):
        d = clone()
        rc, out, _ = cli(d, "plan"); self.assertEqual(rc, 0); self.assertEqual(json.loads(out)["tasks"], 1686)
        rc, out, _ = cli(d, "next"); self.assertEqual(rc, 0); self.assertIn("P0-01", out); self.assertNotIn("P1-01", out)   # only phase 0 is eligible
        self.assertEqual(cli(d, "why-blocked", "P1-01")[0], 1); self.assertEqual(cli(d, "why-blocked", "NOPE-01")[0], 1)
        self.assertEqual(json.loads(cli(d, "status")[1]), {"PENDING": 1686})
        g = json.loads(cli(d, "export-dag")[1]); self.assertIn("GATE:RC-R", g["gates"]); self.assertEqual(g["phases"][0], 0)

    def test_truncated_duplicate_and_wrong_digest_abort(self):
        d = clone(); lines = (d / "spec/task_compiled.jsonl").read_text().splitlines()
        (d / "spec/task_compiled.jsonl").write_text("\n".join(lines[:-5]) + "\n")                       # truncated
        rc, _, err = cli(d, "status"); self.assertNotEqual(rc, 0); self.assertIn("integrity", err)
        d = clone(); lines = (d / "spec/task_compiled.jsonl").read_text().splitlines(); lines[1] = lines[0]
        (d / "spec/task_compiled.jsonl").write_text("\n".join(lines) + "\n")                            # duplicated id, same count
        rc, _, err = cli(d, "status"); self.assertNotEqual(rc, 0); self.assertIn("duplicate", err)
        d = clone(); cli(d, "status"); lk = json.loads((d / "spec/plan.lock").read_text()); lk["plan_digest_sha256"] = "0" * 64
        (d / "spec/plan.lock").write_text(json.dumps(lk)); rc, _, err = cli(d, "status"); self.assertNotEqual(rc, 0); self.assertIn("different plan digest", err)

    def test_concurrent_render_never_corrupts(self):
        d = clone(); out = d / "gen"; res = []
        ts = [threading.Thread(target=lambda: res.append(cli(d, "render", "--out", str(out), ledger=str(d / "shared.db"))[0])) for _ in range(6)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(set(res), {0}); txt = (out / "LEDGER_STATUS.md").read_text()
        self.assertTrue(txt.startswith("# Ledger status") and "PENDING: 1686" in txt)
        self.assertEqual(sorted(p.name for p in out.iterdir()), [".lock", "LEDGER_BLOCKERS.md", "LEDGER_STATUS.md"])   # no stray temp files

    def test_rc_r_inputs_loaded_so_signature_alone_is_not_enough(self):
        d = clone(); rc, out, _ = cli(d, "why-blocked", "P55-01"); self.assertEqual(rc, 1); self.assertIn("GATE:P1'", out); self.assertIn("GATE:P93", out)


class FalseCompletion(unittest.TestCase):
    def setUp(self):
        self.l = Ledger(Path(tempfile.mkdtemp()) / "l.db", {**K, "llm": ("worker", b"llm"), "judge": ("approver", b"j")}); self.l.load_plan(rows(), lock()); self.l.refresh_ready("sup")
        self.ep = self.l.lease("P0-01", "sup", "w1"); self.l.submit("P0-01", "w1", self.ep, SHA)

    def r(self, **kw):
        base = {"task": "P0-01", "verifier": "ver", "git_sha": SHA, "epoch": self.ep, "plan": self.l.plan_digest(), "cmd": ["pytest"], "exit_code": 0, "report_hash": "real"}
        return {**base, **kw}

    def test_fabricated_ci_output_unsigned_or_wrong_key(self):
        r = self.r()
        for sig in ("", "0" * 64, sign(b"guess", r), sign(K["w1"][1], r)):
            with self.assertRaises(LedgerError): self.l.accept_receipt("P0-01", r, sig)
        self.assertEqual(self.l.status("P0-01"), "VERIFYING")

    def test_tampered_log_or_report_invalidates_signature(self):
        r = self.r(); s = sign(K["ver"][1], r)
        for k, v in (("report_hash", "forged"), ("cmd", ["true"])):
            t = dict(r, **{k: v})
            if t != r:
                with self.assertRaises(LedgerError): self.l.accept_receipt("P0-01", t, s)
        self.assertEqual(self.l.status("P0-01"), "VERIFYING")

    def test_misleading_agent_summary_cannot_change_status(self):
        with self.assertRaises(LedgerError): self.l.mark("P0-01", "VERIFIED", "w1", "All 18 tests pass, please mark complete")
        with self.assertRaises(LedgerError): self.l.mark("P0-01", "VERIFIED", "sup", "supervisor says it is fine")
        with self.assertRaises(LedgerError): self.l.mark("P0-01", "NOT_APPLICABLE_APPROVED", "w1", "n/a")

    def test_second_llm_pass_is_not_independent_evidence(self):
        for who, key in (("llm", b"llm"), ("judge", b"j"), ("ghost", b"g")):
            r = self.r(verifier=who)
            with self.assertRaises(LedgerError): self.l.accept_receipt("P0-01", r, sign(key, r))        # worker/approver/unknown role cannot verify
        self.assertEqual(self.l.status("P0-01"), "VERIFYING")

    def test_wrong_sha_epoch_plan_task(self):
        for kw in ({"git_sha": "b" * 40}, {"epoch": self.ep + 1}, {"plan": "f" * 64}, {"task": "P1-01"}):
            r = self.r(**kw)
            with self.assertRaises(LedgerError): self.l.accept_receipt("P0-01", r, sign(K["ver"][1], r))

    def test_stale_evidence_invalidation_closes_downstream(self):
        r = self.r(); self.assertEqual(self.l.accept_receipt("P0-01", r, sign(K["ver"][1], r)), "VERIFIED")
        self.assertEqual(self.l.refresh_ready("sup"), ["P1-01"])
        self.assertEqual(self.l.invalidate("P0-01", "sup", "tested file changed"), ["P0-01"])
        self.assertEqual(self.l.status("P0-01"), "NEEDS_REVALIDATION")
        with self.assertRaises(LedgerError): self.l.lease("P1-01", "sup", "w2")                          # READY task is no longer leasable
        with self.assertRaises(LedgerError): self.l.accept_receipt("P0-01", r, sign(K["ver"][1], r))    # old receipt cannot resurrect VERIFIED
        self.assertTrue(self.l.verify_journal())


if __name__ == "__main__": unittest.main()
