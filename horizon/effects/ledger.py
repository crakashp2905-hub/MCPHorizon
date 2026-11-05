"""ENG-PR04 (E04, HARD-B04..B08 subset): minimal durable EffectLedger on SQLite (WAL, one transaction per transition).
States: REQUESTED -> AUTHORIZED -> STARTED -> COMMITTED | BLOCKED | UNKNOWN -> RECONCILED_(COMMITTED|BLOCKED). Illegal transitions are rejected.
At-most-once dispatch: begin() atomically moves AUTHORIZED->STARTED for exactly one caller per effect_id; a crash after STARTED leaves it STARTED, and recover() marks it UNKNOWN (never retried, never assumed failed).
Single-node SQLite only: NOT a multi-instance / leader-fenced store (needs an external durable backend; BLOCKED_EXTERNAL). CANDIDATE."""
from __future__ import annotations
import json, sqlite3, threading, time

NEXT = {"REQUESTED": {"AUTHORIZED", "BLOCKED"}, "AUTHORIZED": {"STARTED", "BLOCKED"}, "STARTED": {"COMMITTED", "BLOCKED", "UNKNOWN"},
        "UNKNOWN": {"RECONCILED_COMMITTED", "RECONCILED_BLOCKED"}, "COMMITTED": set(), "BLOCKED": set(), "RECONCILED_COMMITTED": set(), "RECONCILED_BLOCKED": set()}


class LedgerError(Exception):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


class EffectLedger:
    def __init__(self, path=":memory:", clock=time.time):
        self.path, self.clock, self.l = path, clock, threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        if path != ":memory:": self.db.execute("pragma journal_mode=wal"); self.db.execute("pragma synchronous=full")
        self.db.execute("create table if not exists effects(effect_id text primary key, state text not null, detail text not null, ts real not null)")
        self.db.execute("create table if not exists history(seq integer primary key autoincrement, effect_id text not null, frm text, to_state text not null, detail text, ts real not null)")
        self.db.execute("create table if not exists nonces(nonce text primary key, effect_id text not null)")

    def _tx(self, fn):
        with self.l:
            self.db.execute("begin immediate")
            try: r = fn(); self.db.execute("commit"); return r
            except BaseException: self.db.execute("rollback"); raise

    def _move(self, effect_id, to, detail=None):
        row = self.db.execute("select state from effects where effect_id=?", (effect_id,)).fetchone()
        if row is None: raise LedgerError("UNKNOWN_EFFECT", effect_id)
        if to not in NEXT[row[0]]: raise LedgerError("ILLEGAL_TRANSITION", f"{row[0]} -> {to}")
        d = json.dumps(detail or {}, sort_keys=True)
        self.db.execute("update effects set state=?, detail=?, ts=? where effect_id=?", (to, d, self.clock(), effect_id))
        self.db.execute("insert into history(effect_id,frm,to_state,detail,ts) values(?,?,?,?,?)", (effect_id, row[0], to, d, self.clock()))

    def request(self, effect_id: str, detail=None) -> bool:
        """Idempotent on effect_id: returns False (and changes nothing) if it already exists."""
        def f():
            if self.db.execute("select 1 from effects where effect_id=?", (effect_id,)).fetchone(): return False
            self.db.execute("insert into effects values(?,?,?,?)", (effect_id, "REQUESTED", json.dumps(detail or {}, sort_keys=True), self.clock()))
            self.db.execute("insert into history(effect_id,frm,to_state,detail,ts) values(?,NULL,'REQUESTED',?,?)", (effect_id, "{}", self.clock())); return True
        return self._tx(f)

    def authorize(self, effect_id: str, nonce: str) -> bool:
        """REQUESTED->AUTHORIZED and atomically reserve the nonce; a nonce can belong to exactly one effect."""
        def f():
            if self.db.execute("select 1 from nonces where nonce=?", (nonce,)).fetchone(): return False
            self._move(effect_id, "AUTHORIZED", {"nonce": nonce}); self.db.execute("insert into nonces values(?,?)", (nonce, effect_id)); return True
        return self._tx(f)

    def begin(self, effect_id: str) -> bool:
        """At-most-once dispatch gate: True for exactly one caller; later/concurrent callers get False and must not execute."""
        def f():
            row = self.db.execute("select state from effects where effect_id=?", (effect_id,)).fetchone()
            if row is None: raise LedgerError("UNKNOWN_EFFECT", effect_id)
            if row[0] != "AUTHORIZED": return False
            self._move(effect_id, "STARTED"); return True
        return self._tx(f)

    def finish(self, effect_id: str, outcome: str, detail=None):
        if outcome not in ("COMMITTED", "BLOCKED", "UNKNOWN"): raise LedgerError("BAD_OUTCOME", outcome)
        self._tx(lambda: self._move(effect_id, outcome, detail))

    def block(self, effect_id: str, detail=None): self._tx(lambda: self._move(effect_id, "BLOCKED", detail))

    def reconcile(self, effect_id: str, sink_says_committed: bool, detail=None):
        """Resolve an UNKNOWN effect from an INDEPENDENT sink observation; never from a timeout."""
        self._tx(lambda: self._move(effect_id, "RECONCILED_COMMITTED" if sink_says_committed else "RECONCILED_BLOCKED", detail))

    def recover(self) -> list:
        """After a crash/restart: anything left STARTED may have run -> UNKNOWN (not retried, not assumed failed)."""
        def f():
            ids = [r[0] for r in self.db.execute("select effect_id from effects where state='STARTED' order by effect_id")]
            for i in ids: self._move(i, "UNKNOWN", {"reason": "crash_recovery"})
            return ids
        return self._tx(f)

    def expire_authorized(self, older_than: float) -> list:
        """Liveness: an effect whose permit was consumed (AUTHORIZED) but never began would sit forever. Move those older than `older_than` seconds to BLOCKED.
        Safe even if the authorizer is alive: begin() is an atomic AUTHORIZED->STARTED compare-and-set, so a late begin() returns False and nothing is dispatched
        (model: research/commitproof, design `proposed_expiry_any_time`). The consumed nonce stays consumed (the permit is burned)."""
        def f():
            cut = self.clock() - older_than
            ids = [r[0] for r in self.db.execute("select effect_id from effects where state='AUTHORIZED' and ts<=? order by effect_id", (cut,))]
            for i in ids: self._move(i, "BLOCKED", {"reason": "authorized_orphan_expired"})
            return ids
        return self._tx(f)

    def state(self, effect_id): r = self.db.execute("select state from effects where effect_id=?", (effect_id,)).fetchone(); return r[0] if r else None
    def history(self, effect_id): return [(r[0], r[1]) for r in self.db.execute("select frm,to_state from history where effect_id=? order by seq", (effect_id,))]
    def close(self): self.db.close()
