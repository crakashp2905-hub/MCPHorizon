"""Versioned, transaction-safe privacy ledger (P45-02, 05, 06, 13).

* The policy owner is an EVIDENCE service: budgets and allocations are ATTESTATION tokens (claim.type = privacy-budget / privacy-alloc) issued by the owner role through the shared HorizonPolicy authority. This module holds only a Verifier. The stored token is re-verified and compared with the budget columns on every reservation, so editing the database row (or replaying an older, looser token) is detected.
* Every state change is one SQLite `BEGIN IMMEDIATE` transaction, so concurrent threads and processes serialize on check-and-reserve. Entries are appended to a hash chain (`verify_chain`, `audit`).
* Request lifecycle: RESERVED -> STARTED (the mechanism began) -> COMMITTED.  Charged states: RESERVED, STARTED, COMMITTED, ABANDONED.
  - cancel before STARTED refunds; cancel/timeout after STARTED does NOT (the noisy value may exist): the entry becomes ABANDONED and stays charged.
  - an unstarted RESERVED entry past its ttl is refunded (EXPIRED).  A STARTED entry may be committed later (noise is a deterministic function of the request id, so releasing it again adds no information).
  - the same request id with the same query digest is idempotent (never charged twice, returns the stored answer); the same id with a different digest is refused.
"""
import hashlib, json, sqlite3, threading, time
from ..authz.effect import canonical
from ..hpolicy.authority import EvidenceError
from . import accountant as AC

CHARGED = ("RESERVED", "STARTED", "COMMITTED", "ABANDONED")


def digest(o) -> str: return "sha256:" + hashlib.sha256(canonical(o)).hexdigest()


class Ledger:
    def __init__(self, path, verifier, clock=time.time, *, atomic=True, refund_after_start=False, gap=0.0):
        self.path, self.v, self.clock, self.atomic, self.refund_after_start, self.gap = path, verifier, clock, atomic, refund_after_start, gap; self._tl, self._mem_lock = threading.local(), threading.RLock(); self._mem = None
        if path == ":memory:": self._mem = sqlite3.connect(path, timeout=60, isolation_level=None, check_same_thread=False)
        self.db.executescript("""CREATE TABLE IF NOT EXISTS budgets(ledger_id TEXT PRIMARY KEY, dataset TEXT, token TEXT, eps TEXT, delta TEXT, accountant TEXT, version INTEGER);
          CREATE TABLE IF NOT EXISTS alloc(ledger_id TEXT, kind TEXT, scope TEXT, token TEXT, eps TEXT, delta TEXT, PRIMARY KEY(ledger_id, kind, scope));
          CREATE TABLE IF NOT EXISTS res(ledger_id TEXT, request_id TEXT, qdigest TEXT, principal TEXT, task TEXT, tenant TEXT, charge TEXT, state TEXT, t_reserved REAL, ttl REAL, answer TEXT, receipt TEXT, PRIMARY KEY(ledger_id, request_id));
          CREATE TABLE IF NOT EXISTS entries(seq INTEGER PRIMARY KEY AUTOINCREMENT, prev TEXT, hash TEXT, body TEXT);""")
    @property
    def db(self):
        """One connection per thread for file ledgers (SQLite transactions are per connection); a single connection guarded by a lock for :memory:."""
        if self._mem is not None: return self._mem
        c = getattr(self._tl, "c", None)
        if c is None:
            c = self._tl.c = sqlite3.connect(self.path, timeout=60, isolation_level=None)
            c.execute("PRAGMA journal_mode=WAL")
        return c
    def close(self):
        try: self.db.close()
        except Exception: pass

    # ---- helpers ------------------------------------------------------------------------------------------------------------------------------------------------------
    def _tx(self, fn):
        if not self.atomic: return fn()           # ABLATION ONLY: every statement auto-commits, so check-then-reserve is not atomic
        if self._mem is not None:
            with self._mem_lock:
                self.db.execute("BEGIN IMMEDIATE")
                try: r = fn(); self.db.execute("COMMIT"); return r
                except BaseException: self.db.execute("ROLLBACK"); raise
        self.db.execute("BEGIN IMMEDIATE")
        try: r = fn(); self.db.execute("COMMIT"); return r
        except BaseException: self.db.execute("ROLLBACK"); raise
    def _log(self, body: dict):
        prev = (self.db.execute("SELECT hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone() or ("genesis",))[0]
        b = json.dumps(body, sort_keys=True); h = hashlib.sha256((prev + b).encode()).hexdigest(); self.db.execute("INSERT INTO entries(prev,hash,body) VALUES(?,?,?)", (prev, h, b)); return h

    # ---- policy owner ------------------------------------------------------------------------------------------------------------------------------------------
    def open_budget(self, token: str) -> str:
        p = self.v.verify(token, now=self.clock()); c = p["claim"]
        if p["kind"] != "ATTESTATION" or c.get("type") != "privacy-budget": raise EvidenceError("MALFORMED", "not a privacy budget")
        if p["args_digest"] != digest(c) or c.get("accountant") not in AC.ACCOUNTANTS: raise EvidenceError("MALFORMED", "budget digest or accountant")
        lid = p["artifact"]
        def f():
            old = self.db.execute("SELECT version,eps,delta,accountant FROM budgets WHERE ledger_id=?", (lid,)).fetchone()
            if old and p["object_version"] <= old[0]: raise EvidenceError("STALE_VERSION", "budget version must increase (no rollback to a looser or equal token)")
            self.db.execute("INSERT OR REPLACE INTO budgets VALUES(?,?,?,?,?,?,?)", (lid, c["dataset"], token, str(c["eps"]), str(c["delta"]), c["accountant"], p["object_version"])); self._log({"op": "budget", "ledger": lid, "eps": c["eps"], "delta": c["delta"], "acc": c["accountant"], "ver": p["object_version"]}); return lid
        return self._tx(f)
    def allocate(self, token: str) -> None:
        p = self.v.verify(token, now=self.clock()); c = p["claim"]
        if p["kind"] != "ATTESTATION" or c.get("type") != "privacy-alloc" or c.get("kind") not in ("task", "tenant") or p["args_digest"] != digest(c): raise EvidenceError("MALFORMED", "not a privacy allocation")
        def f(): self.db.execute("INSERT OR REPLACE INTO alloc VALUES(?,?,?,?,?,?)", (p["artifact"], c["kind"], c["scope"], token, str(c["eps"]), str(c["delta"]))); self._log({"op": "alloc", "ledger": p["artifact"], "kind": c["kind"], "scope": c["scope"], "eps": c["eps"], "delta": c["delta"]})
        self._tx(f)
    def _budget(self, lid):
        r = self.db.execute("SELECT dataset,token,eps,delta,accountant FROM budgets WHERE ledger_id=?", (lid,)).fetchone()
        if not r: return None, "NO_BUDGET"
        try: p = self.v.verify(r[1], now=self.clock())
        except EvidenceError as e: return None, "BUDGET_TOKEN_" + e.code
        c = p["claim"]
        if p["artifact"] != lid or str(c["eps"]) != r[2] or str(c["delta"]) != r[3] or c["accountant"] != r[4]: return None, "BUDGET_ROW_TAMPERED"
        return {"eps": r[2], "delta": r[3], "accountant": r[4]}, None

    # ---- lifecycle ------------------------------------------------------------------------------------------------------------------------------------------------
    def _sweep(self, lid):
        now = self.clock()
        for (rid,) in self.db.execute("SELECT request_id FROM res WHERE ledger_id=? AND state='RESERVED' AND t_reserved+ttl<?", (lid, now)).fetchall():
            self.db.execute("UPDATE res SET state='EXPIRED' WHERE ledger_id=? AND request_id=?", (lid, rid)); self._log({"op": "expire", "ledger": lid, "req": rid})
    def _charges(self, lid, where="", args=()):
        return [json.loads(r[0]) for r in self.db.execute("SELECT charge FROM res WHERE ledger_id=? AND state IN ('RESERVED','STARTED','COMMITTED','ABANDONED') " + where, (lid,) + args).fetchall()]
    def reserve(self, lid, request_id, qdigest, charge, principal="", task="", tenant="", ttl=30.0) -> dict:
        def f():
            self._sweep(lid); b, why = self._budget(lid)
            if b is None: self._log({"op": "deny", "ledger": lid, "req": request_id, "why": why}); return {"ok": False, "reason": why}
            row = self.db.execute("SELECT qdigest,state,answer,receipt FROM res WHERE ledger_id=? AND request_id=?", (lid, request_id)).fetchone()
            if row:
                if row[0] != qdigest: return {"ok": False, "reason": "REQUEST_ID_REUSE"}
                if row[1] == "EXPIRED": return {"ok": False, "reason": "RESERVATION_EXPIRED", "state": "EXPIRED"}
                if row[1] == "CANCELLED": return {"ok": False, "reason": "CANCELLED", "state": "CANCELLED"}
                return {"ok": True, "replayed": True, "state": row[1], "answer": json.loads(row[2]) if row[2] else None, "receipt": row[3]}
            allc = self._charges(lid) + [charge]
            if self.gap: time.sleep(self.gap)
            try: ok, spent = AC.fits(b["accountant"], b, allc)
            except AC.Unsupported as e: return {"ok": False, "reason": "UNSUPPORTED: " + str(e)}
            if not ok: self._log({"op": "deny", "ledger": lid, "req": request_id, "why": "BUDGET_EXCEEDED"}); return {"ok": False, "reason": "BUDGET_EXCEEDED", "spent": spent}
            for kind, scope in (("task", task), ("tenant", tenant)):
                a = self.db.execute("SELECT eps,delta,token FROM alloc WHERE ledger_id=? AND kind=? AND scope=?", (lid, kind, scope)).fetchone() if scope else None
                if a:
                    own = [json.loads(r[0]) for r in self.db.execute("SELECT charge FROM res WHERE ledger_id=? AND %s=? AND state IN ('RESERVED','STARTED','COMMITTED','ABANDONED')" % kind, (lid, scope)).fetchall()] + [charge]
                    try: self.v.verify(a[2], now=self.clock())
                    except EvidenceError as e: return {"ok": False, "reason": "ALLOCATION_TOKEN_" + e.code}
                    if not AC.fits(b["accountant"], {"eps": a[0], "delta": a[1]}, own)[0]: self._log({"op": "deny", "ledger": lid, "req": request_id, "why": "%s_ALLOCATION_EXCEEDED" % kind.upper()}); return {"ok": False, "reason": "%s_ALLOCATION_EXCEEDED" % kind.upper()}
            self.db.execute("INSERT INTO res VALUES(?,?,?,?,?,?,?,?,?,?,NULL,NULL)", (lid, request_id, qdigest, principal, task, tenant, json.dumps(charge, sort_keys=True), "RESERVED", self.clock(), ttl))
            h = self._log({"op": "reserve", "ledger": lid, "req": request_id, "q": qdigest, "charge": charge}); return {"ok": True, "replayed": False, "state": "RESERVED", "entry": h, "spent": spent}
        return self._tx(f)
    def _state(self, lid, rid):
        r = self.db.execute("SELECT state FROM res WHERE ledger_id=? AND request_id=?", (lid, rid)).fetchone(); return r[0] if r else None
    def begin(self, lid, rid) -> dict:
        def f():
            self._sweep(lid); s = self._state(lid, rid)
            if s in ("STARTED", "COMMITTED", "ABANDONED"): return {"ok": True, "state": s}
            if s != "RESERVED": return {"ok": False, "reason": "NOT_RESERVED:" + str(s)}
            self.db.execute("UPDATE res SET state='STARTED' WHERE ledger_id=? AND request_id=?", (lid, rid)); self._log({"op": "begin", "ledger": lid, "req": rid}); return {"ok": True, "state": "STARTED"}
        return self._tx(f)
    def commit(self, lid, rid, answer, receipt) -> dict:
        def f():
            s = self._state(lid, rid)
            if s == "COMMITTED": r = self.db.execute("SELECT answer,receipt FROM res WHERE ledger_id=? AND request_id=?", (lid, rid)).fetchone(); return {"ok": True, "state": s, "answer": json.loads(r[0]), "receipt": r[1], "replayed": True}
            if s not in ("STARTED", "ABANDONED"): return {"ok": False, "reason": "NOT_STARTED:" + str(s)}
            self.db.execute("UPDATE res SET state='COMMITTED', answer=?, receipt=? WHERE ledger_id=? AND request_id=?", (json.dumps(answer), receipt, lid, rid)); self._log({"op": "commit", "ledger": lid, "req": rid, "a": digest(answer)}); return {"ok": True, "state": "COMMITTED", "answer": answer, "receipt": receipt}
        return self._tx(f)
    def cancel(self, lid, rid) -> dict:
        def f():
            self._sweep(lid); s = self._state(lid, rid)
            if s == "RESERVED": self.db.execute("UPDATE res SET state='CANCELLED' WHERE ledger_id=? AND request_id=?", (lid, rid)); self._log({"op": "cancel", "ledger": lid, "req": rid, "refund": True}); return {"ok": True, "refunded": True}
            if s == "STARTED" and self.refund_after_start: self.db.execute("UPDATE res SET state='CANCELLED' WHERE ledger_id=? AND request_id=?", (lid, rid)); self._log({"op": "cancel", "ledger": lid, "req": rid, "refund": True}); return {"ok": True, "refunded": True}          # ABLATION ONLY
            if s == "STARTED": self.db.execute("UPDATE res SET state='ABANDONED' WHERE ledger_id=? AND request_id=?", (lid, rid)); self._log({"op": "cancel", "ledger": lid, "req": rid, "refund": False}); return {"ok": True, "refunded": False}
            return {"ok": s in ("CANCELLED", "EXPIRED", "ABANDONED"), "refunded": s in ("CANCELLED", "EXPIRED"), "state": s}
        return self._tx(f)

    # ---- inspection --------------------------------------------------------------------------------------------------------------------------------------------------
    def spent(self, lid) -> dict:
        b, why = self._budget(lid)
        if b is None: return {"error": why}
        ok, sp = AC.fits(b["accountant"], b, self._charges(lid)); return {"within": ok, **sp, "n_charged": len(self._charges(lid))}
    def states(self, lid) -> dict:
        return {r[0]: r[1] for r in self.db.execute("SELECT request_id,state FROM res WHERE ledger_id=?", (lid,)).fetchall()}
    def charged_events(self, lid) -> list:
        """charge/refund event log for the independent accountant, reconstructed from the hash-chained entries (not from the res table)."""
        ev = []
        for (b,) in self.db.execute("SELECT body FROM entries ORDER BY seq").fetchall():
            e = json.loads(b)
            if e.get("ledger") != lid: continue
            if e["op"] == "reserve": ev.append({"op": "charge", "id": e["req"], **e["charge"]})
            elif (e["op"] == "cancel" and e.get("refund")) or e["op"] == "expire": ev.append({"op": "refund", "id": e["req"]})
        return ev
    def verify_chain(self) -> bool:
        prev = "genesis"
        for seq, p, h, b in self.db.execute("SELECT seq,prev,hash,body FROM entries ORDER BY seq").fetchall():
            if p != prev or hashlib.sha256((p + b).encode()).hexdigest() != h: return False
            prev = h
        return True
    def audit(self, lid) -> list:
        """Differences between the res table and the state implied by the entries; empty = consistent."""
        implied = {}
        for (b,) in self.db.execute("SELECT body FROM entries ORDER BY seq").fetchall():
            e = json.loads(b)
            if e.get("ledger") != lid: continue
            r = e.get("req")
            if e["op"] == "reserve": implied[r] = "RESERVED"
            elif e["op"] == "begin": implied[r] = "STARTED"
            elif e["op"] == "commit": implied[r] = "COMMITTED"
            elif e["op"] == "cancel": implied[r] = "CANCELLED" if e.get("refund") else "ABANDONED"
            elif e["op"] == "expire": implied[r] = "EXPIRED"
        cur = self.states(lid); return sorted(k for k in set(implied) | set(cur) if implied.get(k) != cur.get(k))
