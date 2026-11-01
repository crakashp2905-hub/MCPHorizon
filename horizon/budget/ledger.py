"""Strongly consistent budget ledger (P50-02..07, 14).
* The policy owner is an EVIDENCE service: a task budget is an ATTESTATION token {type: budget, task, limits, rev, ver} issued by the owner role through the shared HorizonPolicy authority and bound to the task principal and the policy revision. This module holds only a Verifier.
* Every state change is one SQLite BEGIN IMMEDIATE transaction; reservations are checked against the node and every ancestor scope (delegation never resets quota). Entries are hash-chained.
* Reservation lifecycle:  RESERVED -start-> STARTED -commit(observed)-> COMMITTED
    RESERVED --release/expire--> RELEASED / EXPIRED (refunded)      STARTED --timeout/crash--> UNKNOWN (still charged, conservative)
    STARTED|UNKNOWN --reconcile(observed)--> COMMITTED (charge = what the independent receiver observed; an observed overrun is recorded) or RELEASED (receiver observed nothing)
  Charged states: RESERVED, STARTED, COMMITTED, UNKNOWN, HELD.  Only an unstarted reservation, or a receiver-observed shortfall, is ever refunded."""
import hashlib, json, sqlite3, threading, time
from ..hpolicy.authority import EvidenceError
from . import units as U

CHARGED = ("RESERVED", "STARTED", "COMMITTED", "UNKNOWN", "HELD")


class Ledger:
    def __init__(self, path, verifier, clock=time.time, policy=U.POLICY, *, atomic=True, gap=0.0, attenuate=True, idempotent=True, conservative=True, ancestors=True, signed=True, bind_principal=True, owner_role="owner"):
        self.path, self.v, self.clock, self.policy = path, verifier, clock, policy; self.atomic, self.gap, self.attenuate, self.idempotent, self.conservative, self.ancestors, self.signed, self.bind_principal, self.owner_role = atomic, gap, attenuate, idempotent, conservative, ancestors, signed, bind_principal, owner_role
        self._tl, self._lk = threading.local(), threading.RLock(); self._mem = None
        if path == ":memory:": self._mem = sqlite3.connect(path, timeout=60, isolation_level=None, check_same_thread=False)
        self.db.executescript("""CREATE TABLE IF NOT EXISTS scopes(scope TEXT PRIMARY KEY, parent TEXT, path TEXT, task TEXT, principal TEXT, cap TEXT, mode TEXT, token TEXT, ver INTEGER);
          CREATE TABLE IF NOT EXISTS res(rid TEXT PRIMARY KEY, scope TEXT, principal TEXT, qdigest TEXT, charge TEXT, state TEXT, t0 REAL, ttl REAL, observed TEXT, overrun TEXT);
          CREATE TABLE IF NOT EXISTS entries(seq INTEGER PRIMARY KEY AUTOINCREMENT, prev TEXT, hash TEXT, body TEXT);""")
    @property
    def db(self):
        if self._mem is not None: return self._mem
        c = getattr(self._tl, "c", None)
        if c is None: c = self._tl.c = sqlite3.connect(self.path, timeout=60, isolation_level=None); c.execute("PRAGMA journal_mode=WAL")
        return c
    def close(self):
        try: self.db.close()
        except Exception: pass
    def _tx(self, fn):
        if not self.atomic: return fn()                 # ABLATION ONLY: statements auto-commit, check-then-reserve is not atomic
        lk = self._lk if self._mem is not None else threading.Lock()
        with (lk if self._mem is not None else _Null()):
            self.db.execute("BEGIN IMMEDIATE")
            try: r = fn(); self.db.execute("COMMIT"); return r
            except BaseException: self.db.execute("ROLLBACK"); raise
    def _log(self, body):
        prev = (self.db.execute("SELECT hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone() or ("genesis",))[0]; b = json.dumps(body, sort_keys=True)
        self.db.execute("INSERT INTO entries(prev,hash,body) VALUES(?,?,?)", (prev, hashlib.sha256((prev + b).encode()).hexdigest(), b))
    def verify_chain(self):
        prev = "genesis"
        for seq, p, h, b in self.db.execute("SELECT seq,prev,hash,body FROM entries ORDER BY seq").fetchall():
            if p != prev or h != hashlib.sha256((prev + b).encode()).hexdigest(): return False
            prev = h
        return True
    # ---- scopes ----------------------------------------------------------------------------------------------------------------------------------------------------
    def open_task(self, token):
        """Signed budget assignment (P50-02). Accepts only a token for the current policy revision; the version must increase (no rollback to a looser or equal budget)."""
        p = self.v.verify(token, now=self.clock()) if self.signed else _unsigned(token); c = p["claim"]
        if p["kind"] != "ATTESTATION" or c.get("type") != "budget" or p["args_digest"] != U.digest(c): raise EvidenceError("MALFORMED", "not a budget assignment")
        if self.signed and p["role"] != self.owner_role: raise EvidenceError("ROLE_NOT_OWNER", "budgets are assigned by the policy owner role only")
        if c.get("rev") != self.policy["rev"]: raise EvidenceError("POLICY_REVISION", "budget issued for another policy revision")
        task = p["artifact"]; limits = U.clean_limits(c["limits"])
        def f():
            old = self.db.execute("SELECT ver FROM scopes WHERE scope=?", (task,)).fetchone()
            if old and p["object_version"] <= old[0]: raise EvidenceError("STALE_VERSION", "budget version must increase")
            self.db.execute("INSERT OR REPLACE INTO scopes VALUES(?,?,?,?,?,?,?,?,?)", (task, None, task, task, p["principal"], json.dumps(limits), "root", token, p["object_version"])); self._log({"op": "open", "task": task, "limits": limits, "ver": p["object_version"]})
        self._tx(f)
    def _scope(self, s):
        r = self.db.execute("SELECT scope,parent,path,task,principal,cap,mode FROM scopes WHERE scope=?", (s,)).fetchone()
        return None if r is None else {"scope": r[0], "parent": r[1], "path": r[2], "task": r[3], "principal": r[4], "cap": json.loads(r[5]), "mode": r[6]}
    def delegate(self, parent, child, principal, caps, mode="attenuate"):
        """Child scope for a sub-agent. attenuate: caps clamped to the parent's caps and charges still count against every ancestor. transfer: the amounts are held (charged) at the parent and the child spends only its own pool."""
        caps = U.clean_limits(caps)
        def f():
            p = self._scope(parent)
            if p is None: return {"ok": False, "reason": "NO_PARENT"}
            if self._scope(child) is not None: return {"ok": False, "reason": "SCOPE_EXISTS"}
            if mode == "attenuate":
                cap = {k: min(v, p["cap"].get(k, 0)) for k, v in caps.items()} if self.attenuate else dict(caps)
                self.db.execute("INSERT INTO scopes VALUES(?,?,?,?,?,?,?,?,?)", (child, parent, p["path"] + "/" + child, p["task"], principal, json.dumps(cap), "attenuate", "", 0))
            else:
                bad = self._over(p, caps, exclude_hold=None)
                if bad: return {"ok": False, "reason": "PARENT_INSUFFICIENT", "classes": bad}
                self.db.execute("INSERT INTO res VALUES(?,?,?,?,?,?,?,?,?,?)", ("hold:" + child, parent, p["principal"], "", json.dumps(caps), "HELD", self.clock(), 0, None, None))
                self.db.execute("INSERT INTO scopes VALUES(?,?,?,?,?,?,?,?,?)", (child, parent, p["path"] + "/" + child, p["task"], principal, json.dumps(caps), "transfer", "", 0)); cap = caps
            self._log({"op": "delegate", "parent": parent, "child": child, "mode": mode, "cap": cap}); return {"ok": True, "cap": cap}
        return self._tx(f)
    def close_scope(self, child):
        """Return the unused part of a transferred pool to the parent."""
        def f():
            s = self._scope(child)
            if s is None or s["mode"] != "transfer": return {"ok": False, "reason": "NOT_TRANSFER"}
            used = self._used(s); self.db.execute("UPDATE res SET charge=? WHERE rid=?", (json.dumps({k: used.get(k, 0) for k in s["cap"]}), "hold:" + child)); self._log({"op": "close", "child": child, "kept": used}); return {"ok": True, "kept": used}
        return self._tx(f)
    # ---- accounting ------------------------------------------------------------------------------------------------------------------------------------------------
    def _sweep(self):
        now = self.clock()
        for rid, st in self.db.execute("SELECT rid,state FROM res WHERE state IN ('RESERVED','STARTED') AND t0+ttl<?", (now,)).fetchall():
            new = "EXPIRED" if st == "RESERVED" else ("UNKNOWN" if self.conservative else "RELEASED"); self.db.execute("UPDATE res SET state=? WHERE rid=?", (new, rid)); self._log({"op": "sweep", "rid": rid, "state": new})
    def _used(self, s):
        """Charged units in the subtree of `s`. A transferred child pool is represented by the HELD charge at its parent, so its own reservations are not counted again above it."""
        out = {}; modes = {p: m for p, m in self.db.execute("SELECT path,mode FROM scopes").fetchall()}
        for ch, st, path in self.db.execute("SELECT r.charge,r.state,s.path FROM res r JOIN scopes s ON s.scope=r.scope WHERE (s.path=? OR s.path LIKE ?) AND r.state IN (%s)" % ",".join("'%s'" % x for x in CHARGED), (s["path"], s["path"] + "/%")).fetchall():
            segs = path.split("/"); k0 = len(s["path"].split("/"))
            if any(modes.get("/".join(segs[:i])) == "transfer" for i in range(k0 + 1, len(segs) + 1)): continue
            for k, v in json.loads(ch).items(): out[k] = out.get(k, 0) + v
        return out
    def _over(self, s, cost, exclude_hold=None):
        used = self._used(s); return [k for k, v in cost.items() if v > 0 and used.get(k, 0) + v > s["cap"].get(k, 0)]
    def _chain(self, s):
        out = [s]
        while self.ancestors and s["mode"] == "attenuate" and s["parent"]: s = self._scope(s["parent"]); out.append(s)
        return out
    def reserve(self, scope, principal, rid, qdigest, cost, ttl=30.0):
        def f():
            self._sweep(); s = self._scope(scope)
            if s is None: return {"ok": False, "reason": "NO_BUDGET"}
            if self.bind_principal and principal != s["principal"]: self._log({"op": "deny", "rid": rid, "why": "NOT_SCOPE_PRINCIPAL"}); return {"ok": False, "reason": "NOT_SCOPE_PRINCIPAL"}
            row = self.db.execute("SELECT qdigest,state,scope FROM res WHERE rid=?", (rid,)).fetchone()
            if row and self.idempotent:
                if row[0] != qdigest or row[2] != scope: return {"ok": False, "reason": "REQUEST_ID_REUSE"}
                if row[1] in ("EXPIRED", "RELEASED"): return {"ok": False, "reason": "RESERVATION_" + row[1], "state": row[1]}
                return {"ok": True, "replayed": True, "state": row[1]}
            try: cst = U.clean_limits(cost)
            except U.CostError: return {"ok": False, "reason": "BAD_COST"}
            over = []
            for n in self._chain(s):
                snap = self._used(n)
                if self.gap: time.sleep(self.gap)
                over += [k for k, v in cst.items() if v > 0 and snap.get(k, 0) + v > n["cap"].get(k, 0)]
            if over: self._log({"op": "deny", "rid": rid, "why": "BUDGET_EXCEEDED", "classes": sorted(set(over))}); return {"ok": False, "reason": "BUDGET_EXCEEDED", "classes": sorted(set(over))}
            self.db.execute("INSERT OR REPLACE INTO res VALUES(?,?,?,?,?,?,?,?,?,?)", (rid, scope, principal, qdigest, json.dumps(cst), "RESERVED", self.clock(), ttl, None, None)); self._log({"op": "reserve", "rid": rid, "scope": scope, "cost": cst}); return {"ok": True, "state": "RESERVED"}
        return self._tx(f)
    def _state(self, rid): r = self.db.execute("SELECT state,charge,scope FROM res WHERE rid=?", (rid,)).fetchone(); return r
    def start(self, rid):
        def f():
            self._sweep(); r = self._state(rid)
            if r is None or r[0] != "RESERVED": return {"ok": False, "reason": "NOT_RESERVED", "state": r[0] if r else None}
            self.db.execute("UPDATE res SET state='STARTED' WHERE rid=?", (rid,)); self._log({"op": "start", "rid": rid}); return {"ok": True}
        return self._tx(f)
    def release(self, rid):
        def f():
            self._sweep(); r = self._state(rid)
            if r is None or r[0] != "RESERVED": return {"ok": False, "reason": "NOT_REFUNDABLE", "state": r[0] if r else None}
            self.db.execute("UPDATE res SET state='RELEASED' WHERE rid=?", (rid,)); self._log({"op": "release", "rid": rid}); return {"ok": True}
        return self._tx(f)
    def commit(self, rid, observed):
        """Record what the independent receiver observed. Charge = observed (a shortfall is refunded; an overrun is charged in full and recorded)."""
        def f():
            self._sweep(); r = self._state(rid)
            if r is None or r[0] not in ("STARTED", "UNKNOWN"): return {"ok": False, "reason": "NOT_STARTED", "state": r[0] if r else None}
            reserved = json.loads(r[1]); obs = U.clean_limits(observed); over = {k: v - reserved.get(k, 0) for k, v in obs.items() if v > reserved.get(k, 0)}
            self.db.execute("UPDATE res SET state='COMMITTED', charge=?, observed=?, overrun=? WHERE rid=?", (json.dumps(obs), json.dumps(obs), json.dumps(over), rid)); self._log({"op": "commit", "rid": rid, "observed": obs, "overrun": over}); return {"ok": True, "overrun": over}
        return self._tx(f)
    def reconcile(self, rid, observed):
        """observed=None: receiver unreachable (telemetry missing) -> stays charged. observed={} (all zero): receiver confirms no effect -> refund."""
        if observed is None: return {"ok": True, "state": (self._state(rid) or (None,))[0], "unknown": True}
        if all(v == 0 for v in observed.values()):
            def f():
                r = self._state(rid)
                if r is None or r[0] not in ("STARTED", "UNKNOWN"): return {"ok": False, "reason": "NOT_STARTED"}
                self.db.execute("UPDATE res SET state='RELEASED', observed=? WHERE rid=?", (json.dumps(observed), rid)); self._log({"op": "reconcile_release", "rid": rid}); return {"ok": True, "state": "RELEASED"}
            return self._tx(f)
        return self.commit(rid, observed)
    # ---- inspection ------------------------------------------------------------------------------------------------------------------------------------------------
    def used(self, scope): return self._used(self._scope(scope))
    def remaining(self, scope): s = self._scope(scope); u = self._used(s); return {k: v - u.get(k, 0) for k, v in s["cap"].items()}
    def state(self, rid): r = self._state(rid); return r[0] if r else None
    def info(self, rid):
        r = self.db.execute("SELECT state,charge,observed FROM res WHERE rid=?", (rid,)).fetchone()
        return None if r is None else {"state": r[0], "charge": json.loads(r[1]), "observed": json.loads(r[2]) if r[2] else None}
    def entries(self): return [json.loads(b) for (b,) in self.db.execute("SELECT body FROM entries ORDER BY seq")]
    def invariants(self):
        """Every scope: charged <= cap for each class. Returns violations (empty = hold)."""
        bad = []
        for (sc,) in self.db.execute("SELECT scope FROM scopes").fetchall():
            s = self._scope(sc); u = self._used(s)
            bad += [(sc, k, u[k], s["cap"].get(k, 0)) for k in u if u[k] > s["cap"].get(k, 0)]
        return bad


class _Null:
    def __enter__(self): return self
    def __exit__(self, *a): return False
def _unsigned(token):
    """ABLATION ONLY: parse a token without checking its signature (models a ledger that trusts whoever supplies the budget)."""
    from ..authz.effect import b64d
    return json.loads(b64d(token.split(".")[1]))
