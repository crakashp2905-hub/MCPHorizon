import dataclasses, hashlib, os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from horizon import normalize as N
from horizon.authz import effect as E
from horizon.authz.keys import Signer, TrustStore
from horizon.authz.gateway import Verifier, NonceStore
from horizon.effects.canonical import CanonicalEffect
from horizon.effects.ledger import EffectLedger
from horizon.effects.filesink import FileSink, ProtectedFileWriter
NOW = 1_800_000_000
class T(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp()); self.root = os.path.join(self.d, "sink"); self.out = os.path.join(self.d, "outside"); os.makedirs(self.out)
        self.sink = FileSink(self.root, os.path.join(self.d, "journal.jsonl")); self.s = Signer.generate("k1", "iss"); ts = TrustStore(clock=lambda: NOW); ts.add("k1", "iss", self.s.public_raw(), not_before=0, not_after=NOW * 2)
        self.v = Verifier(ts, NonceStore(clock=lambda: NOW), issuer="iss", audience="gw", contract_version="c1", policy_version=lambda: "p1", clock=lambda: NOW)
        self.L = EffectLedger(os.path.join(self.d, "l.db")); self.w = ProtectedFileWriter(self.v, self.L, self.sink); self.data = b"TEST_CANARY_NOT_SECRET hello"
        self.ce = CanonicalEffect("t1", "srv1", "sess1", "agent-a", "write", "file", os.path.join(self.root, "a.txt"), {"sha256": hashlib.sha256(self.data).hexdigest()})
    def tearDown(self): self.L.close()
    def tok(self, ce=None, **o):
        ce = ce or self.ce; e = dict(v=1, iss="iss", sub=ce.principal, tenant=ce.tenant, effect=ce.effect, target=N.canonical_target(ce.target_kind, ce.target_raw), args_digest=ce.bound_args_digest(), contract_version="c1",
                                  policy_version="p1", aud="gw", iat=NOW - 1, exp=NOW + 30, nonce=os.urandom(8).hex(), decision_id="d"); e.update(o); return E.sign(self.s._p, "k1", e)
    def test_allow_commits_and_sink_receipt_matches(self):
        r = self.w.write(self.tok(), self.ce, self.data, "e1"); self.assertEqual(r["status"], "ALLOW_COMMITTED"); self.assertEqual(open(self.ce.target_raw, "rb").read(), self.data)
        self.assertEqual(self.sink.observed("e1")["sha256"], hashlib.sha256(self.data).hexdigest()); self.assertEqual(self.L.state("e1"), "COMMITTED")
    def test_blocked_without_permit_writes_nothing(self):
        r = self.w.write("garbage", self.ce, self.data, "e1"); self.assertEqual(r["status"], "BLOCKED"); self.assertFalse(os.path.exists(self.ce.target_raw)); self.assertIsNone(self.sink.observed("e1")); self.assertEqual(self.L.state("e1"), "BLOCKED")
    def test_tampered_target_blocked(self):
        t = self.tok(); bad = dataclasses.replace(self.ce, target_raw=os.path.join(self.root, "b.txt")); r = self.w.write(t, bad, self.data, "e1"); self.assertEqual((r["status"], r["code"]), ("BLOCKED", "TARGET_MISMATCH")); self.assertFalse(os.path.exists(bad.target_raw))
    def test_data_not_matching_permit_args_blocked(self):
        r = self.w.write(self.tok(), self.ce, b"different bytes", "e1"); self.assertEqual(r["code"], "DATA_NOT_BOUND_TO_PERMIT"); self.assertFalse(os.path.exists(self.ce.target_raw))
    def test_replay_of_permit_blocked(self):
        t = self.tok(); self.assertEqual(self.w.write(t, self.ce, self.data, "e1")["status"], "ALLOW_COMMITTED"); r = self.w.write(t, self.ce, self.data, "e2"); self.assertEqual((r["status"], r["code"]), ("BLOCKED", "REPLAY")); self.assertIsNone(self.sink.observed("e2"))
    def test_same_effect_id_twice_does_not_double_write(self):
        self.w.write(self.tok(), self.ce, self.data, "e1"); n = sum(1 for _ in open(self.sink.journal)); r = self.w.write(self.tok(), self.ce, self.data, "e1"); self.assertEqual(r["status"], "DUPLICATE"); self.assertEqual(sum(1 for _ in open(self.sink.journal)), n)
    def test_traversal_outside_root_blocked_by_sink(self):
        ce = dataclasses.replace(self.ce, target_raw=os.path.join(self.root, "..", "outside", "x.txt")); r = self.w.write(self.tok(ce), ce, self.data, "e1")
        self.assertEqual(r["status"], "BLOCKED"); self.assertFalse(os.path.exists(os.path.join(self.out, "x.txt")))
    def test_symlink_escape_blocked_by_sink(self):
        os.symlink(self.out, os.path.join(self.root, "lnk")); ce = dataclasses.replace(self.ce, target_raw=os.path.join(self.root, "lnk", "y.txt")); r = self.w.write(self.tok(ce), ce, self.data, "e1")
        self.assertEqual((r["status"], r["code"]), ("BLOCKED", "OUTSIDE_ROOT")); self.assertFalse(os.path.exists(os.path.join(self.out, "y.txt")))
    def test_unsupported_effect_type_blocked(self):
        ce = dataclasses.replace(self.ce, effect="delete"); self.assertEqual(self.w.write(self.tok(ce), ce, self.data, "e1")["code"], "UNSUPPORTED_EFFECT")
    def test_failure_after_start_is_unknown_not_failed(self):
        def boom(): raise OSError("disk")
        r = self.w.write(self.tok(), self.ce, self.data, "e1", fault=boom); self.assertEqual((r["status"], self.L.state("e1")), ("UNKNOWN", "UNKNOWN"))
    def test_unknown_reconciles_to_blocked_when_sink_never_wrote(self):
        def boom(): raise OSError("disk")
        self.w.write(self.tok(), self.ce, self.data, "e1", fault=boom); self.assertEqual(self.w.reconcile("e1"), "RECONCILED_BLOCKED")
    def test_unknown_reconciles_to_committed_when_sink_journal_says_so(self):
        self.w.write(self.tok(), self.ce, self.data, "e1"); self.L.db.execute("update effects set state='UNKNOWN' where effect_id='e1'"); self.assertEqual(self.w.reconcile("e1"), "RECONCILED_COMMITTED")
    def test_reconcile_is_blocked_if_file_changed_after_journal(self):
        self.w.write(self.tok(), self.ce, self.data, "e1"); open(self.ce.target_raw, "wb").write(b"tampered"); self.L.db.execute("update effects set state='UNKNOWN' where effect_id='e1'")
        self.assertEqual(self.w.reconcile("e1"), "RECONCILED_BLOCKED")
    def test_directory_target_blocked(self):
        ce = dataclasses.replace(self.ce, target_raw=self.root); self.assertEqual(self.w.write(self.tok(ce), ce, self.data, "e1")["status"], "BLOCKED")
    def test_no_tmp_files_left_after_commit(self):
        self.w.write(self.tok(), self.ce, self.data, "e1"); self.assertEqual(os.listdir(self.root), ["a.txt"])

class Races(T):
    def test_zombie_write_after_fenced_reconcile_is_blocked_not_an_exception(self):
        # model: no_fence_timeout_recovery counterexample, on the real code: recovery + reconcile run while the worker is between begin() and the sink write
        r = self.w.write(self.tok(), self.ce, self.data, "e1", fault=lambda: (self.L.recover(), self.w.reconcile("e1")))
        self.assertEqual((r["status"], r["code"]), ("BLOCKED", "FENCED")); self.assertEqual(self.L.state("e1"), "RECONCILED_BLOCKED")
        self.assertFalse(os.path.exists(self.ce.target_raw)); self.assertIsNone(self.sink.observed("e1"))

    def test_ledger_moved_on_after_sink_write_reports_unknown_and_reconciles_committed(self):
        L = self.L
        class S(FileSink):
            def write(s, *a, **k): rec = super().write(*a, **k); L.recover(); return rec     # timeout recovery fires after the write landed, before finish()
        w = ProtectedFileWriter(self.v, self.L, S(self.root, os.path.join(self.d, "j2.jsonl")))
        r = w.write(self.tok(), self.ce, self.data, "e1"); self.assertEqual((r["status"], r["code"]), ("UNKNOWN", "LEDGER_MOVED_ON")); self.assertEqual(self.L.state("e1"), "UNKNOWN")
        self.assertEqual(w.reconcile("e1"), "RECONCILED_COMMITTED")

    def test_sink_lock_serialises_writers(self):
        import fcntl, threading, time
        done = threading.Event(); res = {}
        def writer():
            try: res["r"] = self.sink.write(self.ce.target_raw, self.data, "e9")
            finally: done.set()
        with open(self.sink.journal + ".lock", "a") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX); t = threading.Thread(target=writer); t.start(); time.sleep(0.4)
            self.assertFalse(done.is_set()); self.assertFalse(os.path.exists(self.ce.target_raw))          # blocked while someone holds the sink lock
            fcntl.flock(lk, fcntl.LOCK_UN)
        t.join(5); self.assertTrue(done.is_set()); self.assertEqual(res["r"]["effect_id"], "e9")


if __name__ == "__main__": unittest.main()
