"""The synthetic object / grant / policy / effect service (P52-05, 09). One SQLite database; every method is ONE transaction, so a conditional write (compare-and-swap) and an effect applied inside the same transaction are atomic
with respect to every other mutation. The effect table is written by the service itself with a snapshot of the live state at the moment of the effect: it is the receiver sink record the oracle reads."""
import json, sqlite3, threading
from . import core as C

class Store:
    def __init__(self, clock, path=":memory:"):
        self.clock, self._lk = clock, threading.RLock(); self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=30); self.depth = 0
        self.db.executescript("""CREATE TABLE IF NOT EXISTS objects(id TEXT PRIMARY KEY, version INTEGER, cls TEXT, content TEXT);
          CREATE TABLE IF NOT EXISTS grants(principal TEXT, scope TEXT, version INTEGER, active INTEGER, PRIMARY KEY(principal, scope));
          CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY, version INTEGER, body TEXT);
          CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, subject TEXT, at REAL);
          CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY, actor TEXT, claim TEXT, issued_seq INTEGER, iat REAL, exp REAL, used INTEGER DEFAULT 0, revoked INTEGER DEFAULT 0);
          CREATE TABLE IF NOT EXISTS effects(seq INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, obj TEXT, obj_version INTEGER, obj_cls TEXT, content_d TEXT, canary INTEGER, host TEXT, ip TEXT, final_host TEXT, scopes TEXT, grant_version INTEGER, slice TEXT, slice_rules TEXT, approval TEXT, at REAL, rev_seq INTEGER);""")
    def tx(self):
        s = self
        class T:
            def __enter__(self_):
                s._lk.acquire()
                if s.depth == 0: s.db.execute("BEGIN IMMEDIATE")
                s.depth += 1; return s
            def __exit__(self_, et, ev, tb):
                s.depth -= 1
                try:
                    if s.depth == 0: s.db.execute("ROLLBACK" if et else "COMMIT")
                finally: s._lk.release()
                return False
        return T()
    # ---- setup / mutations (each one security-relevant change bumps a version and appends to the event log) -------------------------------------------------------------
    def event(self, kind, subject): self.db.execute("INSERT INTO events(kind,subject,at) VALUES(?,?,?)", (kind, subject, self.clock())); return self.db.execute("SELECT MAX(seq) FROM events").fetchone()[0]
    def put_object(self, id, cls, content):
        with self.tx(): self.db.execute("INSERT OR REPLACE INTO objects VALUES(?,?,?,?)", (id, 1, cls, content))
    def set_class(self, id, cls):
        with self.tx(): self.db.execute("UPDATE objects SET cls=?, version=version+1 WHERE id=?", (cls, id)); self.event("class", id)
    def replace_content(self, id, content):
        with self.tx(): self.db.execute("UPDATE objects SET content=?, version=version+1 WHERE id=?", (content, id)); self.event("content", id)
    def cas_update(self, id, expected_version, content=None, cls=None):
        """Conditional write: applies only if the object is still at `expected_version`."""
        with self.tx():
            r = self.db.execute("SELECT version,cls,content FROM objects WHERE id=?", (id,)).fetchone()
            if r is None or r[0] != expected_version: self.event("cas_reject", "%s|%s|%s" % (id, expected_version, r[0] if r else None)); return False
            self.db.execute("UPDATE objects SET content=?, cls=?, version=version+1 WHERE id=?", (content if content is not None else r[2], cls or r[1], id)); self.event("cas", "%s|%s|%s" % (id, expected_version, r[0])); return True
    def lww_update(self, id, base_version, content=None, cls=None):
        """Unconditional write: the last writer wins whatever changed since `base_version` (recorded, so a lost update is visible to the oracle)."""
        with self.tx():
            r = self.db.execute("SELECT version,cls,content FROM objects WHERE id=?", (id,)).fetchone()
            self.db.execute("UPDATE objects SET content=?, cls=?, version=version+1 WHERE id=?", (content if content is not None else r[2], cls or r[1], id)); self.event("lww", "%s|%s|%s" % (id, base_version, r[0]))
    def grant(self, principal, scope):
        with self.tx():
            r = self.db.execute("SELECT version FROM grants WHERE principal=? AND scope=?", (principal, scope)).fetchone()
            self.db.execute("INSERT OR REPLACE INTO grants VALUES(?,?,?,1)", (principal, scope, (r[0] if r else 0) + 1)); self.event("grant", principal + ":" + scope)
    def revoke_grant(self, principal, scope):
        with self.tx(): self.db.execute("UPDATE grants SET active=0, version=version+1 WHERE principal=? AND scope=?", (principal, scope)); self.event("revoke_grant", principal + ":" + scope)
    def set_rule(self, id, body):
        with self.tx():
            r = self.db.execute("SELECT version FROM rules WHERE id=?", (id,)).fetchone(); self.db.execute("INSERT OR REPLACE INTO rules VALUES(?,?,?)", (id, (r[0] if r else 0) + 1, json.dumps(body, sort_keys=True))); self.event("rule", id)
    def revoke_approval(self, aid):
        with self.tx(): self.db.execute("UPDATE approvals SET revoked=1 WHERE id=?", (aid,)); self.event("revoke_approval", aid)
    # ---- reads -----------------------------------------------------------------------------------------------------------------------------------------------------------
    def obj(self, id): r = self.db.execute("SELECT id,version,cls,content FROM objects WHERE id=?", (id,)).fetchone(); return None if r is None else {"id": r[0], "version": r[1], "cls": r[2], "content": r[3]}
    def scopes(self, principal): return sorted(s for (s,) in self.db.execute("SELECT scope FROM grants WHERE principal=? AND active=1", (principal,)).fetchall())
    def grant_version(self, principal): return sum(v for (v,) in self.db.execute("SELECT version FROM grants WHERE principal=?", (principal,)).fetchall())
    def rules(self): return {i: json.loads(b) for i, b in self.db.execute("SELECT id,body FROM rules").fetchall()}, {i: v for i, v in self.db.execute("SELECT id,version FROM rules").fetchall()}
    def rev_seq(self): return self.db.execute("SELECT COALESCE(MAX(seq),0) FROM events").fetchone()[0]
    def revoked_since(self, aid, seq): return self.db.execute("SELECT COUNT(*) FROM events WHERE kind='revoke_approval' AND subject=? AND seq>?", (aid, seq)).fetchone()[0] > 0
    def approval(self, aid):
        r = self.db.execute("SELECT id,actor,claim,issued_seq,iat,exp,used,revoked FROM approvals WHERE id=?", (aid,)).fetchone()
        return None if r is None else {"id": r[0], "actor": r[1], "claim": json.loads(r[2]), "issued_seq": r[3], "iat": r[4], "exp": r[5], "used": r[6], "revoked": r[7]}
    def mark_used(self, aid): self.db.execute("UPDATE approvals SET used=1 WHERE id=?", (aid,))
    def view(self, principal, obj_id, host, ips):
        """Current security-relevant state for an export, read in the caller's transaction."""
        o = self.obj(obj_id); rules, vers = self.rules(); sc = self.scopes(principal)
        return {"obj": o, "scopes": sc, "rules": rules, "vec": C.vector((o["id"], o["version"], o["cls"]), (principal, self.grant_version(principal), sc), C.slice_digest(rules, vers, o["cls"], host), host, ips, self.rev_seq(), C.short(o["content"]))}
    def apply_export(self, actor, obj_id, host, ip, final_host, approval_id):
        """The effect service: sends the object to (host, ip) and records, from live state, what really happened."""
        with self.tx():
            o = self.obj(obj_id); rules, vers = self.rules()
            fr = rules.get("dest." + final_host)
            self.db.execute("INSERT INTO effects(actor,obj,obj_version,obj_cls,content_d,canary,host,ip,final_host,scopes,grant_version,slice,slice_rules,approval,at,rev_seq) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (actor, obj_id, o["version"], o["cls"], C.short(o["content"]), int(C.CANARY in o["content"]), host, ip, final_host, json.dumps(self.scopes(actor)), self.grant_version(actor), C.slice_digest(rules, vers, o["cls"], host), json.dumps({**{i: rules.get(i) for i in C.slice_ids(o["cls"], host)}, "dest." + final_host: fr}, sort_keys=True), approval_id, self.clock(), self.rev_seq()))
    def effects(self):
        cols = ("seq", "actor", "obj", "obj_version", "obj_cls", "content_d", "canary", "host", "ip", "final_host", "scopes", "grant_version", "slice", "slice_rules", "approval", "at", "rev_seq")
        return [dict(zip(cols, r)) for r in self.db.execute("SELECT %s FROM effects ORDER BY seq" % ",".join(cols)).fetchall()]
    def events(self): return [{"seq": a, "kind": b, "subject": c, "at": d} for a, b, c, d in self.db.execute("SELECT seq,kind,subject,at FROM events ORDER BY seq").fetchall()]
    def approvals(self):
        out = {}
        for r in self.db.execute("SELECT id FROM approvals").fetchall(): out[r[0]] = self.approval(r[0])
        return out
