"""Trace-based conformance: EVERY reachable state of the model (design `proposed_expiry_any_time`, 3 workers) is reached by replaying its shortest trace on the REAL
EffectLedger + FileSink + ProtectedFileWriter.reconcile, and EVERY enabled model transition from it (including refusals) is executed on the real objects; the real outcome
(ledger state, permit consumed, sink effect count, fence, per-worker pc, owner) must equal the model's successor.  Outcomes come from the real calls, never from the model.
Limits: single process; request+authorize are one abstract step (two real transactions); one effect; `recover` is the real unguarded recover(), so the design under test is the
timeout-recovery one; post-write file tampering is out of scope."""
import json, os, shutil, tempfile, unittest
from research.commitproof import model as M
from horizon.effects.ledger import EffectLedger, LedgerError
from horizon.effects.filesink import FileSink, SinkError, ProtectedFileWriter

E, NONCE = "eff-1", "nonce-1"
LEDGER_TO_MODEL = {None: M.NONE, "REQUESTED": "REQUESTED", "AUTHORIZED": M.AUTH, "STARTED": M.LSTART, "COMMITTED": M.COMMITTED, "UNKNOWN": M.UNKNOWN,
                   "RECONCILED_COMMITTED": M.REC_C, "RECONCILED_BLOCKED": M.REC_B, "BLOCKED": M.BLOCKED}


class Real:
    def __init__(self, base, n):
        self.root = os.path.join(base, "root"); self.jr = os.path.join(base, "journal.jsonl")
        self.L = EffectLedger(":memory:", clock=lambda: 100.0); self.sink = FileSink(self.root, self.jr); self.w = ProtectedFileWriter(None, self.L, self.sink)
        self.pc = [M.IDLE] * n; self.owner = -1

    def apply(self, label):
        i = int(label.split(".")[0][1:]) if label.startswith("w") else None; op = label.split(".", 1)[1] if i is not None else label
        if op.startswith("authorize"):
            ok = self.L.request(E) and self.L.authorize(E, NONCE); self.pc[i] = M.AUTHED if ok else M.DONE
        elif op.startswith("begin"):
            ok = self.L.begin(E)
            if ok: self.owner = i
            self.pc[i] = M.STARTED if ok else M.DONE
        elif op.startswith("sink_write"):
            try: self.sink.write(os.path.join(self.root, "f.txt"), b"x", E); self.pc[i] = M.WROTE
            except SinkError: self.pc[i] = M.DONE
        elif op.startswith("finish"):
            try: self.L.finish(E, "COMMITTED")
            except LedgerError: pass
            self.pc[i] = M.DONE
        elif op == "CRASH": self.pc[i] = M.DEAD
        elif label.startswith("recover"): self.L.recover()
        elif label.startswith("expire_orphan"): self.L.expire_authorized(0)
        elif label.startswith("reconcile"): self.w.reconcile(E)
        else: raise AssertionError("unmapped label " + label)

    def project(self):
        st = LEDGER_TO_MODEL[self.L.state(E)]; used = bool(self.L.db.execute("select 1 from nonces where nonce=?", (NONCE,)).fetchone())
        recs = self.sink._records(); c = sum(1 for r in recs if r.get("effect_id") == E and "fence" not in r); fenced = any(r.get("fence") == E for r in recs)
        return (st, used, self.owner, c, fenced, tuple(self.pc))


def paths(design, n):
    d = M.DESIGNS[design]; s0 = M.initial(n); parent = {s0: None}; order = [s0]
    for s in order:
        if M.invariants(s): continue
        for lab, t in M.successors(s, d):
            if t not in parent: parent[t] = (s, lab); order.append(t)
    def path(s):
        out = []
        while parent[s] is not None: s, lab = parent[s]; out.append(lab)
        return list(reversed(out))
    return order, path


class Conformance(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.mkdtemp()
    def tearDown(self): shutil.rmtree(self.tmp, ignore_errors=True)

    def run_real(self, labels, n):
        base = tempfile.mkdtemp(dir=self.tmp); r = Real(base, n)
        for lab in labels: r.apply(lab)
        return r

    def test_every_transition_of_every_reachable_state_matches_the_real_implementation(self):
        n = 3; design = "proposed_expiry_any_time"; d = M.DESIGNS[design]; states, path = paths(design, n); checked = 0; refusals = 0
        for s in states:
            p = path(s); r = self.run_real(p, n); self.assertEqual(r.project(), s, ("state", p))
            for lab, t in M.successors(s, d):
                rr = self.run_real(p, n); rr.apply(lab); self.assertEqual(rr.project(), t, ("transition", p, lab)); checked += 1; refusals += ("refused" in lab)
        self.assertEqual((len(states), checked), (248, 576)); self.assertGreater(refusals, 50)

    def test_zombie_scenario_on_real_objects(self):
        # the model's counterexample against the UNFENCED design, replayed on the real FIXED code: the late write is refused and the ledger stays truthful
        r = self.run_real(["w0.authorize", "w0.begin", "recover(STARTED->UNKNOWN)", "reconcile(fence_and_observe)"], 2)
        self.assertEqual(r.L.state(E), "RECONCILED_BLOCKED"); r.apply("w0.sink_write_refused(fenced)")
        self.assertEqual(r.project()[3], 0); self.assertEqual(r.pc[0], M.DONE)

    def test_unfenced_read_would_have_been_unsafe_on_real_objects(self):
        r = self.run_real(["w0.authorize", "w0.begin", "recover(STARTED->UNKNOWN)"], 2)
        self.assertIsNone(r.sink.observed(E))                                    # plain read says "nothing there" ...
        r.L.reconcile(E, False); r.sink.write(os.path.join(r.root, "f.txt"), b"x", E)    # ... and without a fence the zombie then writes: ledger BLOCKED, effect happened
        self.assertEqual((r.L.state(E), r.project()[3]), ("RECONCILED_BLOCKED", 1))

    def test_orphan_expiry(self):
        r = self.run_real(["w0.authorize", "w0.CRASH"], 2); self.assertEqual(r.L.state(E), "AUTHORIZED")
        self.assertEqual(r.L.expire_authorized(0), [E]); self.assertEqual(r.L.state(E), "BLOCKED"); self.assertFalse(r.L.begin(E))
    def test_expiry_respects_age(self):
        r = self.run_real(["w0.authorize"], 1); self.assertEqual(r.L.expire_authorized(10), [])
    def test_expiry_leaves_started_alone(self):
        r = self.run_real(["w0.authorize", "w0.begin"], 1); self.assertEqual(r.L.expire_authorized(0), []); self.assertEqual(r.L.state(E), "STARTED")

    def test_fence_blocks_later_write_but_not_earlier_record(self):
        r = self.run_real(["w0.authorize", "w0.begin", "w0.sink_write"], 1); obs = r.sink.fence_and_observe(E); self.assertTrue(obs["present_now"])
        with self.assertRaises(SinkError) as c: r.sink.write(os.path.join(r.root, "f.txt"), b"y", E)
        self.assertEqual(c.exception.code, "FENCED")
    def test_fence_is_idempotent(self):
        r = self.run_real([], 1); r.sink.fence_and_observe(E); r.sink.fence_and_observe(E); self.assertEqual(sum(1 for x in r.sink._records() if x.get("fence") == E), 1)
    def test_sink_refuses_duplicate_effect_id(self):
        r = self.run_real([], 1); r.sink.write(os.path.join(r.root, "f.txt"), b"x", E)
        with self.assertRaises(SinkError) as c: r.sink.write(os.path.join(r.root, "f.txt"), b"x", E)
        self.assertEqual(c.exception.code, "ALREADY_WRITTEN")
    def test_fence_for_other_effect_does_not_block(self):
        r = self.run_real([], 1); r.sink.fence_and_observe("other"); r.sink.write(os.path.join(r.root, "f.txt"), b"x", E)

if __name__ == "__main__": unittest.main()
