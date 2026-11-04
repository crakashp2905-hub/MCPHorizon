"""B02-02 / B02-04 / B02-05 (CANDIDATE evidence): multi-PROCESS atomic nonce consumption and crash injection against the file-backed EffectLedger.
Single host, single SQLite file.  This does NOT show cross-host or failover safety (needs an external backend; BLOCKED_EXTERNAL).
The 'sink' is a test-owned append-only journal file; the ledger is never trusted to say what the sink did."""
import os, signal, subprocess, sys, tempfile, time, unittest
from horizon.effects.ledger import EffectLedger

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHILD = r'''
import os, sys, time
from horizon.effects.ledger import EffectLedger
db, journal, eid, nonce, mode, go = sys.argv[1:7]
L = EffectLedger(db)
while not os.path.exists(go): time.sleep(0.001)          # start barrier: all children race at once
if mode == "authorize":
    print("AUTH", L.authorize(eid, nonce)); sys.exit(0)
if mode == "begin":
    ok = L.begin(eid)
    if ok:
        with open(journal, "a") as f: f.write(eid + "\n"); f.flush(); os.fsync(f.fileno())
        L.finish(eid, "COMMITTED")
    print("BEGIN", ok); sys.exit(0)
# crash-injection modes: kill -9 self at a chosen point of the dispatch
ok = L.begin(eid)
if not ok: print("BEGIN False"); sys.exit(0)
if mode == "crash_after_begin": os.kill(os.getpid(), 9)
with open(journal, "a") as f: f.write(eid + "\n"); f.flush(); os.fsync(f.fileno())
if mode == "crash_after_sink": os.kill(os.getpid(), 9)
L.finish(eid, "COMMITTED")
if mode == "crash_after_finish": os.kill(os.getpid(), 9)
print("DONE")
'''


def run_children(db, journal, specs, go_delay=0.3):
    go = os.path.join(os.path.dirname(db), "go"); 
    if os.path.exists(go): os.remove(go)
    ps = [subprocess.Popen([sys.executable, "-B", "-c", CHILD, db, journal, eid, nonce, mode, go], cwd=ROOT, env=dict(os.environ, PYTHONPATH=ROOT), stdout=subprocess.PIPE, text=True) for eid, nonce, mode in specs]
    time.sleep(go_delay); open(go, "w").close()
    return [(p.communicate(timeout=60)[0].strip(), p.returncode) for p in ps]


class Multiproc(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.db = os.path.join(self.d, "l.db"); self.j = os.path.join(self.d, "sink.journal"); open(self.j, "w").close()
        self.L = EffectLedger(self.db)

    def lines(self): return open(self.j).read().split()

    def test_one_nonce_across_many_processes_wins_once(self):
        for i in range(8): self.L.request(f"e{i}")
        res = run_children(self.db, self.j, [(f"e{i}", "SAME_NONCE", "authorize") for i in range(8)])
        self.assertEqual(sorted(r[0] for r in res).count("AUTH True"), 1); self.assertEqual(sorted(r[0] for r in res).count("AUTH False"), 7)
        self.assertEqual(sum(1 for i in range(8) if self.L.state(f"e{i}") == "AUTHORIZED"), 1)

    def test_begin_race_dispatches_exactly_once(self):
        self.L.request("e1"); self.L.authorize("e1", "n1")
        res = run_children(self.db, self.j, [("e1", "n1", "begin")] * 8)
        self.assertEqual([r[0] for r in res].count("BEGIN True"), 1); self.assertEqual(self.lines(), ["e1"]); self.assertEqual(self.L.state("e1"), "COMMITTED")

    def test_crash_after_begin_leaves_started_then_unknown_and_is_never_redispatched(self):
        self.L.request("e1"); self.L.authorize("e1", "n1")
        res = run_children(self.db, self.j, [("e1", "n1", "crash_after_begin")]); self.assertEqual(res[0][1], -signal.SIGKILL)
        self.assertEqual(self.L.state("e1"), "STARTED"); self.assertEqual(self.lines(), [])
        self.assertEqual(self.L.recover(), ["e1"]); self.assertEqual(self.L.state("e1"), "UNKNOWN")
        run_children(self.db, self.j, [("e1", "n1", "begin")]); self.assertEqual(self.lines(), [])           # retry cannot dispatch

    def test_crash_after_sink_commit_is_unknown_not_committed_until_reconciled_from_sink(self):
        self.L.request("e1"); self.L.authorize("e1", "n1")
        res = run_children(self.db, self.j, [("e1", "n1", "crash_after_sink")]); self.assertEqual(res[0][1], -signal.SIGKILL)
        self.assertEqual(self.lines(), ["e1"])                                    # the effect DID happen at the sink
        self.assertEqual(self.L.state("e1"), "STARTED"); self.L.recover(); self.assertEqual(self.L.state("e1"), "UNKNOWN")   # ledger must not claim COMMITTED
        self.L.reconcile("e1", "e1" in self.lines()); self.assertEqual(self.L.state("e1"), "RECONCILED_COMMITTED")
        run_children(self.db, self.j, [("e1", "n1", "begin")]); self.assertEqual(self.lines(), ["e1"])        # never dispatched twice

    def test_crash_before_sink_reconciles_to_blocked_from_empty_sink(self):
        self.L.request("e1"); self.L.authorize("e1", "n1"); run_children(self.db, self.j, [("e1", "n1", "crash_after_begin")])
        self.L.recover(); self.L.reconcile("e1", "e1" in self.lines()); self.assertEqual(self.L.state("e1"), "RECONCILED_BLOCKED")

    def test_crash_after_finish_is_committed_and_recover_is_noop(self):
        self.L.request("e1"); self.L.authorize("e1", "n1"); run_children(self.db, self.j, [("e1", "n1", "crash_after_finish")])
        self.assertEqual(self.L.state("e1"), "COMMITTED"); self.assertEqual(self.L.recover(), []); self.assertEqual(self.lines(), ["e1"])

    def test_many_effects_concurrent_crashes_never_exceed_one_sink_line_each(self):
        modes = ["crash_after_begin", "crash_after_sink", "crash_after_finish", "begin"]
        for i in range(12): self.L.request(f"e{i}"); self.L.authorize(f"e{i}", f"n{i}")
        run_children(self.db, self.j, [(f"e{i}", f"n{i}", modes[i % 4]) for i in range(12)] + [(f"e{i}", f"n{i}", "begin") for i in range(12)])
        self.L.recover(); ls = self.lines()
        for i in range(12): self.assertLessEqual(ls.count(f"e{i}"), 1, f"e{i} dispatched {ls.count(f'e{i}')}x")
        for i in range(12):
            if f"e{i}" in ls: self.assertIn(self.L.state(f"e{i}"), ("COMMITTED", "UNKNOWN"))     # sink effect never recorded as BLOCKED
            else: self.assertIn(self.L.state(f"e{i}"), ("UNKNOWN", "AUTHORIZED", "COMMITTED"))

    def test_reopen_after_crash_preserves_nonce_reservation(self):
        self.L.request("e1"); self.L.authorize("e1", "n1"); self.L.close(); L2 = EffectLedger(self.db)
        L2.request("e2"); self.assertFalse(L2.authorize("e2", "n1")); self.assertEqual(L2.state("e2"), "REQUESTED")

if __name__ == "__main__": unittest.main()
