import os, sys, tempfile, threading, unittest, itertools
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from horizon.effects.ledger import EffectLedger, LedgerError, NEXT
class T(unittest.TestCase):
    def setUp(self): self.d = tempfile.mkdtemp(); self.p = os.path.join(self.d, "l.db"); self.L = EffectLedger(self.p)
    def tearDown(self): self.L.close()
    def go(self, i="e1", n="n1"): self.L.request(i); self.assertTrue(self.L.authorize(i, n))
    def test_happy_path_and_history(self):
        self.go(); self.assertTrue(self.L.begin("e1")); self.L.finish("e1", "COMMITTED"); self.assertEqual(self.L.state("e1"), "COMMITTED")
        self.assertEqual(self.L.history("e1"), [(None, "REQUESTED"), ("REQUESTED", "AUTHORIZED"), ("AUTHORIZED", "STARTED"), ("STARTED", "COMMITTED")])
    def test_request_idempotent(self): self.assertTrue(self.L.request("e1")); self.assertFalse(self.L.request("e1")); self.assertEqual(len(self.L.history("e1")), 1)
    def test_all_illegal_transitions_rejected(self):
        EXPECT = {"REQUESTED": {"AUTHORIZED", "BLOCKED"}, "AUTHORIZED": {"STARTED", "BLOCKED"}, "STARTED": {"COMMITTED", "BLOCKED", "UNKNOWN"}, "UNKNOWN": {"RECONCILED_COMMITTED", "RECONCILED_BLOCKED"}, "COMMITTED": set(), "BLOCKED": set(), "RECONCILED_COMMITTED": set(), "RECONCILED_BLOCKED": set()}
        self.assertEqual(NEXT, EXPECT); states = list(EXPECT)
        for a, b in itertools.product(states, states):
            if b in EXPECT[a] or b == "REQUESTED": continue
            self.L.db.execute("delete from effects where effect_id='x'"); self.L.db.execute("insert into effects values('x',?,'{}',0)", (a,))
            with self.assertRaises(LedgerError, msg=f"{a}->{b}") as c: self.L._tx(lambda: self.L._move("x", b))
            self.assertEqual(c.exception.code, "ILLEGAL_TRANSITION"); self.assertEqual(self.L.state("x"), a)
    def test_unknown_effect(self):
        with self.assertRaises(LedgerError): self.L.finish("nope", "COMMITTED")
    def test_bad_outcome(self):
        self.go(); self.L.begin("e1")
        with self.assertRaises(LedgerError) as c: self.L.finish("e1", "RECONCILED_COMMITTED")
        self.assertEqual(c.exception.code, "BAD_OUTCOME")
    def test_begin_requires_authorized(self): self.L.request("e1"); self.assertFalse(self.L.begin("e1")); self.assertEqual(self.L.state("e1"), "REQUESTED")
    def test_second_begin_refused(self): self.go(); self.assertTrue(self.L.begin("e1")); self.assertFalse(self.L.begin("e1"))
    def test_nonce_belongs_to_one_effect(self): self.go(); self.L.request("e2"); self.assertFalse(self.L.authorize("e2", "n1")); self.assertEqual(self.L.state("e2"), "REQUESTED")
    def test_concurrent_100_way_begin_executes_once(self):
        self.go(); wins = []; b = threading.Barrier(100)
        def w():
            b.wait(); wins.append(self.L.begin("e1"))
        ts = [threading.Thread(target=w) for _ in range(100)]; [t.start() for t in ts]; [t.join() for t in ts]; self.assertEqual(sum(wins), 1)
    def test_concurrent_100_way_nonce_reuse_single_winner(self):
        for i in range(100): self.L.request(f"c{i}")
        wins = []; b = threading.Barrier(100)
        def w(i):
            b.wait(); wins.append(self.L.authorize(f"c{i}", "shared"))
        ts = [threading.Thread(target=w, args=(i,)) for i in range(100)]; [t.start() for t in ts]; [t.join() for t in ts]; self.assertEqual(sum(wins), 1)
    def test_crash_after_started_becomes_unknown_never_retried(self):
        self.go(); self.L.begin("e1"); self.L.close(); L2 = EffectLedger(self.p); self.assertEqual(L2.state("e1"), "STARTED")
        self.assertEqual(L2.recover(), ["e1"]); self.assertEqual(L2.state("e1"), "UNKNOWN"); self.assertFalse(L2.begin("e1"))
        L2.reconcile("e1", True); self.assertEqual(L2.state("e1"), "RECONCILED_COMMITTED"); self.L = L2
    def test_state_and_nonce_survive_restart(self):
        self.go(); self.L.close(); L2 = EffectLedger(self.p); self.assertEqual(L2.state("e1"), "AUTHORIZED"); L2.request("e2"); self.assertFalse(L2.authorize("e2", "n1")); self.L = L2
    def test_recover_leaves_other_states_alone(self):
        self.go(); self.go("e2", "n2"); self.L.begin("e2"); self.L.finish("e2", "COMMITTED"); self.assertEqual(self.L.recover(), []); self.assertEqual(self.L.state("e1"), "AUTHORIZED")
    def test_unknown_not_resolved_by_finish(self):
        self.go(); self.L.begin("e1"); self.L.finish("e1", "UNKNOWN")
        with self.assertRaises(LedgerError): self.L.finish("e1", "COMMITTED")
    def test_block_from_authorized_prevents_begin(self): self.go(); self.L.block("e1"); self.assertFalse(self.L.begin("e1"))
    def test_failed_transition_leaves_no_history(self):
        self.go(); n = len(self.L.history("e1"))
        with self.assertRaises(LedgerError): self.L.reconcile("e1", True)
        self.assertEqual(len(self.L.history("e1")), n)
    def test_reconcile_not_committed(self):
        self.go(); self.L.begin("e1"); self.L.finish("e1", "UNKNOWN"); self.L.reconcile("e1", False); self.assertEqual(self.L.state("e1"), "RECONCILED_BLOCKED")
if __name__ == "__main__": unittest.main()
