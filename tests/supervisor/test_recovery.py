"""P76/P77 crash-recovery, concurrency and restore tests. Synthetic plan only."""
import json, os, signal, sqlite3, sys, tempfile, threading, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from orchestrator.ledger import Ledger, LedgerError, sign
from orchestrator import recovery as R
from tests.supervisor.test_supervisor import K, SHA, rows, lock


class Clk:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t


class Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp()); self.clk = Clk()
        self.l = Ledger(self.d / "l.db", K, clock=self.clk); self.l.load_plan(rows(), lock()); self.l.refresh_ready("sup")

    def receipt(self, l, tid, ep, sha=SHA, code=0):
        r = {"task": tid, "verifier": "ver", "git_sha": sha, "epoch": ep, "plan": l.plan_digest(), "cmd": ["true"], "exit_code": code, "report_hash": "r"}
        return r, sign(K["ver"][1], r)

    def verify(self, tid="P0-01"):
        ep = self.l.lease(tid, "sup", "w1"); self.l.start(tid, "w1", ep); self.l.submit(tid, "w1", ep, SHA)
        r, s = self.receipt(self.l, tid, ep); return self.l.accept_receipt(tid, r, s)


class Leases(Base):
    def test_expired_lease_reclaimed_and_old_worker_fenced(self):
        ep = self.l.lease("P0-01", "sup", "w1", ttl=60); self.l.start("P0-01", "w1", ep)
        self.clk.t += 61
        self.assertEqual(self.l.reclaim_expired("sup"), {"P0-01": "RETRY_WAIT"})
        with self.assertRaises(LedgerError): self.l.submit("P0-01", "w1", ep, SHA)           # zombie worker cannot commit
        self.l.mark("P0-01", "READY", "sup", "retry"); ep2 = self.l.lease("P0-01", "sup", "w2", ttl=60)
        self.assertGreater(ep2, ep)
        with self.assertRaises(LedgerError): self.l.submit("P0-01", "w1", ep, SHA)           # old epoch still rejected after re-lease
        self.l.submit("P0-01", "w2", ep2, SHA); self.assertEqual(self.l.status("P0-01"), "VERIFYING")

    def test_live_lease_not_reclaimed(self):
        self.l.lease("P0-01", "sup", "w1", ttl=60); self.clk.t += 30
        self.assertEqual(self.l.reclaim_expired("sup"), {})

    def test_uncertain_external_effect_blocks_retry_until_reconciled(self):
        ep = self.l.lease("P0-01", "sup", "w1", ttl=60); self.l.start("P0-01", "w1", ep)
        self.l.declare_effect("P0-01", "w1", ep, "publish:pkg-1.0"); self.clk.t += 61
        self.assertEqual(self.l.reclaim_expired("sup"), {"P0-01": "NEEDS_RECONCILIATION"})
        with self.assertRaises(LedgerError): self.l.mark("P0-01", "RETRY_WAIT", "sup", "just retry")     # no automatic retry path
        with self.assertRaises(LedgerError): self.l.reconcile("P0-01", "sup", "performed", "")            # evidence required
        with self.assertRaises(LedgerError): self.l.reconcile("P0-01", "w1", "performed", "ev")           # supervisor only
        self.l.reconcile("P0-01", "sup", "performed", "registry shows pkg-1.0 published")
        self.assertEqual(self.l.status("P0-01"), "READY")

    def test_unconfirmed_effect_blocks_submit(self):
        ep = self.l.lease("P0-01", "sup", "w1"); self.l.declare_effect("P0-01", "w1", ep, "k")
        with self.assertRaises(LedgerError): self.l.submit("P0-01", "w1", ep, SHA)
        self.l.confirm_effect("P0-01", "w1", ep); self.l.submit("P0-01", "w1", ep, SHA)

    def test_only_supervisor_reclaims(self):
        with self.assertRaises(LedgerError): self.l.reclaim_expired("w1")

    def test_clock_skew_backwards_never_verifies_anything(self):
        ep = self.l.lease("P0-01", "sup", "w1", ttl=60); self.clk.t -= 10_000          # clock jumps back: lease looks valid for longer
        self.assertEqual(self.l.reclaim_expired("sup"), {})
        self.l.submit("P0-01", "w1", ep, SHA)
        self.assertNotEqual(self.l.status("P0-01"), "VERIFIED")                          # submission is still only a candidate

    def test_duplicate_events_and_stale_epoch(self):
        ep = self.l.lease("P0-01", "sup", "w1"); self.l.submit("P0-01", "w1", ep, SHA)
        with self.assertRaises(LedgerError): self.l.submit("P0-01", "w1", ep, SHA)       # duplicate submit
        r, s = self.receipt(self.l, "P0-01", ep); self.assertEqual(self.l.accept_receipt("P0-01", r, s), "VERIFIED")
        with self.assertRaises(LedgerError): self.l.accept_receipt("P0-01", r, s)        # replayed receipt
        with self.assertRaises(LedgerError): self.l.lease("P0-01", "sup", "w2")          # cannot re-lease a VERIFIED task

    def test_bad_sha_format_rejected(self):
        ep = self.l.lease("P0-01", "sup", "w1")
        for bad in ("A" * 40, "g" * 40, "a" * 39, "a" * 41): 
            with self.assertRaises(LedgerError): self.l.submit("P0-01", "w1", ep, bad)


class Concurrency(Base):
    def test_one_active_writer_across_connections(self):
        wins, errs = [], []
        def go(w):
            try:
                led = Ledger(self.d / "l.db", K, clock=self.clk); wins.append((w, led.lease("P0-01", "sup", w)))
            except LedgerError as e: errs.append(str(e))
        ts = [threading.Thread(target=go, args=(w,)) for w in ("w1", "w2") * 4]; [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(len(wins), 1, (wins, errs))                                      # exactly one lease granted
        self.assertTrue(self.l.verify_journal())


class Interruption(Base):
    def test_exception_between_steps_rolls_back(self):
        ep = self.l.lease("P0-01", "sup", "w1"); self.l.submit("P0-01", "w1", ep, SHA)
        r, s = self.receipt(self.l, "P0-01", ep)
        orig = self.l._set
        def boom(*a, **k): orig(*a, **k); raise RuntimeError("crash after write, before commit")
        self.l._set = boom
        with self.assertRaises(RuntimeError): self.l.accept_receipt("P0-01", r, s)
        self.l._set = orig
        self.assertEqual(self.l.status("P0-01"), "VERIFYING"); self.assertTrue(self.l.verify_journal())   # no half-applied VERIFIED
        self.assertEqual(self.l.db.execute("SELECT COUNT(*) FROM journal WHERE to_='VERIFIED'").fetchone()[0], 0)

    def test_reopen_after_kill_preserves_state(self):
        ep = self.l.lease("P0-01", "sup", "w1"); self.l.db.close()                         # abrupt close without any shutdown hook
        l2 = Ledger(self.d / "l.db", K, clock=self.clk)
        self.assertEqual((l2.status("P0-01"), l2.db.execute("SELECT epoch FROM tasks WHERE id='P0-01'").fetchone()[0]), ("LEASED", ep))


class DiskAndCorruption(Base):
    def test_disk_full_is_recoverable_and_atomic(self):
        self.verify()
        pages = self.l.db.execute("PRAGMA page_count").fetchone()[0]
        self.l.db.execute(f"PRAGMA max_page_count={pages}")                                # simulate no more space
        before = self.l.db.execute("SELECT COUNT(*) FROM journal").fetchone()[0]; failed = False
        for _ in range(500):
            try: self.l.refresh_ready("sup"); self.l.mark("P1-01", "RETRY_WAIT", "sup", "x"*2000) if self.l.status("P1-01") == "READY" else None
            except (sqlite3.OperationalError, LedgerError): failed = True; break
        self.l.db.execute("PRAGMA max_page_count=1073741823")
        self.assertTrue(self.l.verify_journal())                                           # chain intact whether or not we hit the limit
        self.assertEqual(R.audit_verified(self.l), [])

    def test_corrupt_file_refuses_to_open(self):
        p = self.d / "bad.db"; p.write_bytes(b"not a database" * 100)
        with self.assertRaises(LedgerError): Ledger(p, K)

    def test_newer_schema_refused_and_old_db_migrated(self):
        self.l.db.execute("PRAGMA user_version=99"); self.l.db.close()
        with self.assertRaises(LedgerError): Ledger(self.d / "l.db", K)
        old = self.d / "old.db"; c = sqlite3.connect(old)
        c.executescript("""CREATE TABLE plan(k TEXT PRIMARY KEY, v TEXT NOT NULL);
        CREATE TABLE tasks(id TEXT PRIMARY KEY, phase INTEGER NOT NULL, status TEXT NOT NULL, depends TEXT NOT NULL, epoch INTEGER NOT NULL DEFAULT 0,
          worker TEXT, lease_until REAL, attempts INTEGER NOT NULL DEFAULT 0, sub_sha TEXT, sub_epoch INTEGER, verified_sha TEXT);
        CREATE TABLE journal(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, task TEXT, frm TEXT, to_ TEXT, actor TEXT, detail TEXT, prev TEXT, hash TEXT);
        CREATE TABLE signatures(gate TEXT, signer TEXT, sig TEXT, PRIMARY KEY(gate, signer));""")
        c.commit(); c.close(); led = Ledger(old, K)
        self.assertEqual(led.db.execute("PRAGMA user_version").fetchone()[0], Ledger.SCHEMA_VERSION)


class BackupRestore(Base):
    def test_backup_restore_roundtrip_proves_no_false_verified(self):
        self.verify(); b = self.d / "b.db"; h = R.backup(self.l, b)
        led = R.restore(b, self.d / "r.db", K, expect_sha256=h)
        self.assertEqual(led.status("P0-01"), "VERIFIED"); self.assertEqual(R.audit_verified(led), [])

    def test_restore_rejects_forged_verified_in_backup(self):
        b = self.d / "b.db"; R.backup(self.l, b)
        c = sqlite3.connect(b); c.execute("UPDATE tasks SET status='VERIFIED', verified_sha=? WHERE id='P0-01'", (SHA,)); c.commit(); c.close()
        with self.assertRaises(LedgerError) as e: R.restore(b, self.d / "r.db", K)
        self.assertIn("no journaled transition", str(e.exception)); self.assertFalse((self.d / "r.db").exists())

    def test_restore_rejects_tampered_journal_and_wrong_hash_and_overwrite(self):
        self.verify(); b = self.d / "b.db"; h = R.backup(self.l, b)
        with self.assertRaises(LedgerError): R.restore(b, self.d / "r1.db", K, expect_sha256="0" * 64)
        c = sqlite3.connect(b); c.execute("UPDATE journal SET actor='w1' WHERE to_='VERIFIED'"); c.commit(); c.close()
        with self.assertRaises(LedgerError): R.restore(b, self.d / "r2.db", K)
        (self.d / "exists.db").write_bytes(b"x")
        with self.assertRaises(LedgerError): R.restore(b, self.d / "exists.db", K)

    def test_backup_refuses_broken_chain(self):
        self.l.db.execute("UPDATE journal SET actor='zzz' WHERE seq=1")
        with self.assertRaises(LedgerError): R.backup(self.l, self.d / "b.db")

    def test_verified_bound_to_plan_digest(self):
        self.verify(); self.l.db.execute("UPDATE plan SET v=? WHERE k='digest'", ("e" * 64,))
        self.assertTrue(R.audit_verified(self.l))                                          # digest swap is detected


class Checkpoints(unittest.TestCase):
    def test_scrub_and_isolation(self):
        d = Path(tempfile.mkdtemp())
        p = R.checkpoint(d, "P76-08", 3, {"a.txt": "token=abc123 and AKIAABCDEFGHIJKLMNOP and sk-abcdefghijklmnopqrstuv ok", "sub/b": "fine"})
        t = (p / "a.txt").read_text(); self.assertNotIn("abc123", t); self.assertNotIn("AKIA", t); self.assertIn("ok", t)
        self.assertEqual(oct(p.stat().st_mode & 0o777), "0o700")
        for bad in ("../x", "/etc/x"):
            with self.assertRaises(LedgerError): R.checkpoint(d, "P76-08", 3, {bad: "x"})
        with self.assertRaises(LedgerError): R.checkpoint(d, "../evil", 1, {})

    def test_manifest_and_symlink_escape(self):
        d = Path(tempfile.mkdtemp()); (d / "a").write_text("1"); (d / "b").write_text("2")
        m = R.manifest(d, ["b", "a"], "rev1"); m2 = R.manifest(d, ["a", "b"], "rev1"); self.assertEqual(m, m2)
        (d / "b").write_text("changed"); self.assertNotEqual(m["manifest_sha256"], R.manifest(d, ["a", "b"], "rev1")["manifest_sha256"])
        out = Path(tempfile.mkdtemp()); (out / "s").write_text("secret"); os.symlink(out / "s", d / "link")
        with self.assertRaises(LedgerError): R.manifest(d, ["link"], "r")
        with self.assertRaises(LedgerError): R.manifest(d, ["../x"], "r")

    def test_atomic_write_and_log_rotation_and_shutdown(self):
        d = Path(tempfile.mkdtemp()); R.write_atomic(d / "STATUS.md", "v1"); R.write_atomic(d / "STATUS.md", "v2")
        self.assertEqual((d / "STATUS.md").read_text(), "v2"); self.assertEqual([p.name for p in d.iterdir()], ["STATUS.md"])
        lg = d / "sup.log"
        for i in range(6): lg.write_text("x" * 100); R.rotate_log(lg, 50, 3)
        self.assertLessEqual(len([p for p in d.iterdir() if p.name.startswith("sup.log")]), 3)
        sd = R.Shutdown().install(); os.kill(os.getpid(), signal.SIGTERM); self.assertTrue(sd.requested)
        signal.signal(signal.SIGTERM, signal.SIG_DFL); signal.signal(signal.SIGINT, signal.default_int_handler)


if __name__ == "__main__": unittest.main()
