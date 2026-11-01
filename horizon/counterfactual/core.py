"""Effect-diff schema, effect contracts, and the DB / file / publication preview adapters (P41-01..05). Synthetic data only; everything is local."""
from __future__ import annotations
import hashlib, json, os, re, shutil, sqlite3, tempfile
from dataclasses import dataclass, field

SCHEMA_V = "effect-diff/1.0.0"
CANARY = "TEST_CANARY_NOT_SECRET"
INTERNAL = ("sqlite_",)


def dig(o) -> str: return hashlib.sha256(json.dumps(o, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


@dataclass
class Contract:
    """Threat-aware effect contract: what the operation may touch, independent of the agent's permissions (ACL)."""
    expected_rows: tuple = (0, 1)                 # inclusive cardinality range of changed rows
    allowed_tables: tuple = ()
    allowed_prefixes: tuple = ()                  # file adapter: relative path prefixes that may be written
    public_prefixes: tuple = ()                   # subset where sensitive content classes are forbidden
    max_bytes: int = 1_000_000
    allowed_destinations: tuple = ()
    forbidden_package_classes: tuple = ("SENSITIVE_SYNTHETIC",)
    def d(self): return {k: (list(v) if isinstance(v, tuple) else v) for k, v in self.__dict__.items()}


@dataclass
class Diff:
    adapter: str; op_digest: str; changes: list; irreversible: bool = False; external: bool = False; unknown: list = field(default_factory=list); notes: dict = field(default_factory=dict)
    def body(self): return {"v": SCHEMA_V, "adapter": self.adapter, "op_digest": self.op_digest, "changes": self.changes, "irreversible": self.irreversible, "external": self.external, "unknown": self.unknown}
    def digest(self): return dig(self.body())
    def d(self): return {**self.body(), "digest": self.digest(), "notes": self.notes}


def validate_diff(d: dict):
    need = {"v", "adapter", "op_digest", "changes", "irreversible", "external", "unknown"}
    if not need <= set(d) or d["v"] != SCHEMA_V: raise ValueError("bad diff schema")
    for c in d["changes"]:
        if not {"kind", "target", "key", "before", "after"} <= set(c) or c["kind"] not in ("INSERT", "UPDATE", "DELETE", "WRITE", "REMOVE", "PUBLISH"): raise ValueError("bad change")
    return d


# ---------------- DB adapter -----------------------------------------------------------------------------------------------------------------------------------
BAD_KW = re.compile(r"\b(attach|detach|pragma|vacuum|drop|alter|create|reindex|load_extension)\b", re.I)
NONDET = re.compile(r"\b(random|randomblob|datetime|date|time|strftime|julianday|current_timestamp|current_time|current_date|changes|last_insert_rowid)\b", re.I)


def _tables(conn): return [r[0] for r in conn.execute("select name from sqlite_master where type='table' and name not like 'sqlite_%' order by name")]


def table_digests(conn) -> dict:
    out = {}
    for t in _tables(conn):
        cols = [r[1] for r in conn.execute("pragma table_info(%s)" % t)]; pk = [r[1] for r in conn.execute("pragma table_info(%s)" % t) if r[5]] or ["rowid"]
        rows = conn.execute("select %s, %s from %s" % (", ".join(pk), ", ".join(cols), t)).fetchall()
        out[t] = {json.dumps(list(r[:len(pk)])): dig(list(r[len(pk):])) for r in rows}
    return out


def diff_digests(a: dict, b: dict) -> list:
    ch = []
    for t in sorted(set(a) | set(b)):
        x, y = a.get(t, {}), b.get(t, {})
        for k in sorted(set(x) | set(y)):
            if k not in x: ch.append({"kind": "INSERT", "target": t, "key": k, "before": None, "after": y[k]})
            elif k not in y: ch.append({"kind": "DELETE", "target": t, "key": k, "before": x[k], "after": None})
            elif x[k] != y[k]: ch.append({"kind": "UPDATE", "target": t, "key": k, "before": x[k], "after": y[k]})
    return ch


class DbAdapter:
    name = "db"
    def __init__(self, path): self.path = path
    def conn(self): c = sqlite3.connect(self.path, timeout=5, isolation_level=None); return c
    @staticmethod
    def screen(sql: str):
        s = sql.strip().rstrip(";").strip(); body = re.sub(r"'(?:[^']|'')*'", "''", s)
        if not s or ";" in body: return "UNSUPPORTED:multi-statement"
        if BAD_KW.search(body): return "UNSUPPORTED:forbidden-keyword"
        if not re.match(r"(insert|update|delete|replace|select)\b", s, re.I): return "UNSUPPORTED:statement-kind"
        return None
    def _clone(self):
        src = self.conn(); c = sqlite3.connect(":memory:", isolation_level=None); src.backup(c); src.close(); return c
    def preview(self, sql, params=()) -> Diff:
        od = dig({"sql": sql, "params": list(params)}); bad = self.screen(sql)
        if bad: return Diff(self.name, od, [], unknown=[bad])
        ds = []
        for _ in range(2):                                   # run twice on independent clones: differing results => non-deterministic operation
            c = self._clone(); before = table_digests(c)
            try: c.execute(sql, tuple(params))
            except sqlite3.Error as e: return Diff(self.name, od, [], unknown=["PREVIEW_ERROR:" + type(e).__name__])
            ds.append(diff_digests(before, table_digests(c))); c.close()
        d = Diff(self.name, od, ds[0], notes={"rows": len(ds[0])})
        if ds[0] != ds[1] or NONDET.search(re.sub(r"'[^']*'", "''", sql)): d.unknown.append("NONDETERMINISTIC")
        return d
    def apply_verified(self, sql, params, approved_digest, op_digest, expect_version=None):
        """CAS: inside one IMMEDIATE transaction re-derive the diff against the CURRENT state; commit only if it equals the approved diff."""
        c = self.conn()
        try:
            c.execute("begin immediate"); before = table_digests(c)
            if expect_version is not None and c.execute("pragma user_version").fetchone()[0] != expect_version: c.execute("rollback"); return {"committed": False, "why": "STALE_VERSION"}
            c.execute(sql, tuple(params)); ch = diff_digests(before, table_digests(c)); got = Diff(self.name, op_digest, ch).digest()
            if got != approved_digest: c.execute("rollback"); return {"committed": False, "why": "STATE_CHANGED", "actual_rows": len(ch)}
            c.execute("pragma user_version = %d" % (c.execute("pragma user_version").fetchone()[0] + 1)); c.execute("commit"); return {"committed": True}
        except sqlite3.Error as e:
            try: c.execute("rollback")
            except sqlite3.Error: pass
            return {"committed": False, "why": "DB_ERROR:" + type(e).__name__}
        finally: c.close()
    def apply_unverified(self, sql, params):
        c = self.conn()
        try:
            if ";" in re.sub(r"'(?:[^']|'')*'", "''", sql.strip().rstrip(";")) and not params: c.executescript(sql)      # a driver/ORM that allows stacked statements (the exposure the screen exists for)
            else: c.execute("begin immediate"); c.execute(sql, tuple(params)); c.execute("commit")
            return {"committed": True}
        except sqlite3.Error as e: return {"committed": False, "why": "DB_ERROR:" + type(e).__name__}
        finally: c.close()
    def version(self): c = self.conn(); v = c.execute("pragma user_version").fetchone()[0]; c.close(); return v


# ---------------- file adapter -----------------------------------------------------------------------------------------------------------------------------------
def classify(b: bytes) -> str:
    t = b.decode("utf-8", "replace")
    if CANARY in t: return "SENSITIVE_SYNTHETIC"
    if t.startswith("#!"): return "EXECUTABLE"
    return "TEXT" if all(c.isprintable() or c in "\n\t\r" for c in t) else "BINARY"


class FileAdapter:
    name = "file"
    def __init__(self, root): self.root = os.path.realpath(root)
    def manifest(self, root=None) -> dict:
        root = root or self.root; m = {}
        for dp, _, fs in os.walk(root):
            for f in fs:
                p = os.path.join(dp, f); m[os.path.relpath(p, root)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
        return m
    def resolve(self, rel):
        if os.path.isabs(rel) or ".." in rel.split("/"): return None
        p = os.path.realpath(os.path.join(self.root, rel))
        return p if p.startswith(self.root + os.sep) else None
    def _apply(self, root, op):
        p = os.path.join(root, op["path"])
        if op["kind"] == "write": os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "wb").write(op["content"].encode())
        elif op["kind"] == "delete": os.remove(p)
        else: raise ValueError(op["kind"])
    def preview(self, op) -> Diff:
        od = dig(op)
        if op.get("kind") not in ("write", "delete") or self.resolve(op.get("path", "")) is None: return Diff(self.name, od, [], unknown=["UNSUPPORTED:path-or-kind"])
        sh = tempfile.mkdtemp(prefix="p41f-"); shutil.copytree(self.root, sh, dirs_exist_ok=True)
        try:
            before = self.manifest(sh); self._apply(sh, op); after = self.manifest(sh)
        except OSError as e: shutil.rmtree(sh, ignore_errors=True); return Diff(self.name, od, [], unknown=["PREVIEW_ERROR:" + type(e).__name__])
        ch = []
        for k in sorted(set(before) | set(after)):
            if before.get(k) != after.get(k):
                cls = classify(open(os.path.join(sh, k), "rb").read()) if k in after else None
                ch.append({"kind": "REMOVE" if k not in after else "WRITE", "target": "file", "key": k, "before": before.get(k), "after": after.get(k), "class": cls, "bytes": os.path.getsize(os.path.join(sh, k)) if k in after else 0})
        shutil.rmtree(sh, ignore_errors=True); return Diff(self.name, od, ch, irreversible=any(c["kind"] == "REMOVE" for c in ch))
    def apply_verified(self, op, approved_digest):
        import fcntl
        lk = open(os.path.join(tempfile.gettempdir(), "p41f-%s.lock" % hashlib.sha1(self.root.encode()).hexdigest()[:10]), "w"); fcntl.flock(lk, fcntl.LOCK_EX)
        try:
            cur = self.preview(op)
            if cur.digest() != approved_digest: return {"committed": False, "why": "STATE_CHANGED"}
            self._apply(self.root, op); return {"committed": True}
        finally: fcntl.flock(lk, fcntl.LOCK_UN); lk.close()
    def apply_unverified(self, op):
        if self.resolve(op.get("path", "")) is None: return {"committed": True, "escaped": True} if self._raw_apply(op) else {"committed": False}
        self._apply(self.root, op); return {"committed": True}
    def _raw_apply(self, op):          # an un-gated writer follows '..' (path traversal), which is exactly why the adapter resolves first
        p = os.path.normpath(os.path.join(self.root, op["path"]))
        if op["kind"] == "write": os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "wb").write(op["content"].encode()); return True
        return False


# ---------------- publication adapter ----------------------------------------------------------------------------------------------------------------------------
class PublishAdapter:
    name = "publish"
    def __init__(self, registry_url=None): self.url = registry_url
    def preview(self, op) -> Diff:
        """Manifest of what would leave the machine. The effect is EXTERNAL and IRREVERSIBLE by construction; nothing is sent here."""
        od = dig({"dir": op["dir"], "dest": op["destination"], "name": op["name"]}); root = op["dir"]; ch = []
        for dp, _, fs in os.walk(root):
            for f in sorted(fs):
                p = os.path.join(dp, f); b = open(p, "rb").read(); ch.append({"kind": "PUBLISH", "target": op["destination"], "key": os.path.relpath(p, root), "before": None, "after": hashlib.sha256(b).hexdigest(), "class": classify(b), "bytes": len(b)})
        ch.sort(key=lambda c: c["key"]); return Diff(self.name, od, ch, irreversible=True, external=True, notes={"destination": op["destination"], "total_bytes": sum(c["bytes"] for c in ch)})
    def apply(self, op, expected_digest):
        from ..obligation import services as S
        if self.preview(op).digest() != expected_digest: return {"committed": False, "why": "STATE_CHANGED"}
        c, r = S.call(self.url + "/publish", "POST", {"name": op["name"], "destination": op["destination"], "files": sorted(self.preview(op).d()["changes"], key=lambda c: c["key"])}); return {"committed": c == 200}


# ---------------- verdicts -------------------------------------------------------------------------------------------------------------------------------------------
def decide(diff: Diff, contract: Contract) -> tuple:
    """(verdict, reasons). BLOCK > REVIEW > ALLOW. Unknown/irreversible/external never ALLOW."""
    R, review = [], []
    for u in diff.unknown:
        (R if u.startswith("UNSUPPORTED") else review).append(u)
    ch = diff.changes
    if diff.adapter == "db":
        for t in sorted({c["target"] for c in ch}):
            if t not in contract.allowed_tables: R.append("TABLE_NOT_ALLOWED:" + t)
        lo, hi = contract.expected_rows
        if not (lo <= len(ch) <= hi): R.append("CARDINALITY:%d_not_in_[%d,%d]" % (len(ch), lo, hi))
    if diff.adapter == "file":
        for c in ch:
            if not any(c["key"].startswith(p) for p in contract.allowed_prefixes): R.append("PATH_NOT_ALLOWED:" + c["key"])
            if c["kind"] == "WRITE" and any(c["key"].startswith(p) for p in contract.public_prefixes) and c.get("class") in contract.forbidden_package_classes: R.append("SENSITIVE_IN_PUBLIC:" + c["key"])
            if c.get("bytes", 0) > contract.max_bytes: R.append("TOO_LARGE:" + c["key"])
        if len(ch) > contract.expected_rows[1]: R.append("CARDINALITY:%d" % len(ch))
    if diff.adapter == "publish":
        if diff.notes.get("destination") not in contract.allowed_destinations: R.append("DESTINATION_NOT_ALLOWED")
        for c in ch:
            if c.get("class") in contract.forbidden_package_classes: R.append("SENSITIVE_IN_PACKAGE:" + c["key"])
    if R: return "BLOCK", sorted(set(R))
    if diff.irreversible or diff.external: review.append("IRREVERSIBLE_OR_EXTERNAL")
    if review: return "REVIEW", sorted(set(review))
    return "ALLOW", []
