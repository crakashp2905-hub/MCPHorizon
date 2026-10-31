"""Durable task ledger and state machine (candidate for P75/P76/P77).

Stdlib only. Local-trust design: roles/keys are supplied by the caller; this is NOT a
hardened multi-host security boundary (see docs/security/SUPERVISOR_THREAT_MODEL.md).
Invariants enforced here:
  * only a registered 'verifier' (distinct from the leasing worker) can produce VERIFIED,
    and only with a valid HMAC receipt whose git sha / epoch / task match the submission;
  * no READY/LEASE while the plan is unreviewed or a gate prerequisite is unmet;
  * RC-R requires a registered external signature (an agent cannot synthesize it);
  * every transition is journaled in a hash chain; tampering is detectable;
  * stale lease epochs are rejected; VERIFIED is revoked transitively on invalidation.
"""
from __future__ import annotations
import hashlib, hmac, json, sqlite3, time
from pathlib import Path

STATES = {"PENDING", "READY", "LEASED", "RUNNING", "VERIFYING", "VERIFIED", "RETRY_WAIT",
          "WAITING_EXTERNAL", "NEEDS_APPROVAL", "NEEDS_RECONCILIATION", "BLOCKED_SECURITY",
          "REJECTED", "NOT_APPLICABLE_APPROVED", "NEEDS_REVALIDATION"}
ALLOWED = {
    "PENDING": {"READY", "WAITING_EXTERNAL", "NEEDS_APPROVAL", "BLOCKED_SECURITY"},
    "READY": {"LEASED", "NEEDS_APPROVAL", "BLOCKED_SECURITY"},
    "LEASED": {"RUNNING", "VERIFYING", "RETRY_WAIT", "BLOCKED_SECURITY", "WAITING_EXTERNAL", "NEEDS_APPROVAL"},
    "RUNNING": {"VERIFYING", "RETRY_WAIT", "BLOCKED_SECURITY", "WAITING_EXTERNAL", "NEEDS_APPROVAL"},
    "VERIFYING": {"VERIFIED", "RETRY_WAIT", "REJECTED", "NEEDS_RECONCILIATION"},
    "RETRY_WAIT": {"READY", "BLOCKED_SECURITY"},
    "WAITING_EXTERNAL": {"READY", "BLOCKED_SECURITY"},
    "NEEDS_APPROVAL": {"READY", "NOT_APPLICABLE_APPROVED", "REJECTED", "BLOCKED_SECURITY"},
    "NEEDS_RECONCILIATION": {"READY", "REJECTED"},
    "BLOCKED_SECURITY": {"NEEDS_APPROVAL"},
    "REJECTED": set(),
    "NOT_APPLICABLE_APPROVED": set(),
    "VERIFIED": {"NEEDS_REVALIDATION"},
    "NEEDS_REVALIDATION": {"READY"},
}
SUPERVISOR_ONLY = {"READY", "LEASED", "RETRY_WAIT", "NEEDS_REVALIDATION", "NEEDS_RECONCILIATION",
                   "WAITING_EXTERNAL", "NEEDS_APPROVAL", "BLOCKED_SECURITY"}


class LedgerError(Exception):
    pass


def _h(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def sign(key: bytes, payload: dict) -> str:
    return hmac.new(key, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()


class Ledger:
    def __init__(self, path: str | Path, principals: dict[str, tuple[str, bytes]]):
        """principals: id -> (role, key). roles: supervisor | worker | verifier | external | approver."""
        self.principals = principals
        self.db = sqlite3.connect(str(path), isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL"); self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS plan(k TEXT PRIMARY KEY, v TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY, phase INTEGER NOT NULL, status TEXT NOT NULL,
            depends TEXT NOT NULL, epoch INTEGER NOT NULL DEFAULT 0, worker TEXT, lease_until REAL,
            attempts INTEGER NOT NULL DEFAULT 0, sub_sha TEXT, sub_epoch INTEGER, verified_sha TEXT);
        CREATE TABLE IF NOT EXISTS journal(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, task TEXT, frm TEXT,
            to_ TEXT, actor TEXT, detail TEXT, prev TEXT, hash TEXT);
        CREATE TABLE IF NOT EXISTS signatures(gate TEXT, signer TEXT, sig TEXT, PRIMARY KEY(gate, signer));
        """)

    # ---- plan -------------------------------------------------------------
    def load_plan(self, rows: list[dict], lock: dict) -> None:
        if self.db.execute("SELECT 1 FROM plan WHERE k='digest'").fetchone():
            raise LedgerError("ledger already initialised; use explicit reconciliation for a new plan revision")
        with self._tx():
            for r in rows:
                self.db.execute("INSERT INTO tasks(id,phase,status,depends) VALUES(?,?,?,?)",
                                (r["task_id"], r["phase"], "PENDING", json.dumps(r["depends_on"])))
            self.db.execute("INSERT INTO plan VALUES('digest',?)", (lock["plan_digest_sha256"],))
            self.db.execute("INSERT INTO plan VALUES('reviewed',?)",
                            ("1" if lock.get("reviewed") and lock.get("reviewer_signature") and lock.get("scheduling_enabled") else "0",))

    def _tx(self):
        led = self
        class T:
            def __enter__(s): led.db.execute("BEGIN IMMEDIATE")
            def __exit__(s, et, ev, tb): led.db.execute("ROLLBACK" if et else "COMMIT")
        return T()

    def status(self, tid: str) -> str:
        r = self.db.execute("SELECT status FROM tasks WHERE id=?", (tid,)).fetchone()
        if not r: raise LedgerError(f"unknown task {tid}")
        return r[0]

    # ---- journal ----------------------------------------------------------
    def _journal(self, task, frm, to, actor, detail):
        prev = self.db.execute("SELECT hash FROM journal ORDER BY seq DESC LIMIT 1").fetchone()
        prev = prev[0] if prev else "GENESIS"
        ts, d = time.time(), json.dumps(detail, sort_keys=True)
        self.db.execute("INSERT INTO journal(ts,task,frm,to_,actor,detail,prev,hash) VALUES(?,?,?,?,?,?,?,?)",
                        (ts, task, frm, to, actor, d, prev, _h(prev, repr(ts), task, frm or "", to, actor, d)))

    def verify_journal(self) -> bool:
        prev = "GENESIS"
        for ts, task, frm, to, actor, d, p, h in self.db.execute(
                "SELECT ts,task,frm,to_,actor,detail,prev,hash FROM journal ORDER BY seq"):
            if p != prev or h != _h(p, repr(ts), task, frm or "", to, actor, d):
                return False
            prev = h
        return True

    def _role(self, actor: str) -> str:
        if actor not in self.principals: raise LedgerError(f"unknown principal {actor!r}")
        return self.principals[actor][0]

    def _set(self, tid, to, actor, detail=None, **cols):
        frm = self.status(tid)
        if to not in STATES or to not in ALLOWED[frm]:
            raise LedgerError(f"illegal transition {frm}->{to} for {tid}")
        sets = ",".join(f"{k}=?" for k in cols); vals = list(cols.values())
        self.db.execute(f"UPDATE tasks SET status=?{',' + sets if sets else ''} WHERE id=?", [to, *vals, tid])
        self._journal(tid, frm, to, actor, detail or {})

    # ---- gates ------------------------------------------------------------
    def gate_ok(self, gate: str) -> bool:
        name = gate.split(":", 1)[1]
        if name == "RC-R":
            need = self.db.execute("SELECT v FROM plan WHERE k='rcr_inputs'").fetchone()
            sigs = [r for r in self.db.execute("SELECT signer,sig FROM signatures WHERE gate=?", (gate,))
                    if self.principals.get(r[0], ("",))[0] == "external"
                    and hmac.compare_digest(r[1], sign(self.principals[r[0]][1], {"gate": gate, "plan": self.plan_digest()}))]
            if not sigs: return False
            return all(self.gate_ok(g) for g in (json.loads(need[0]) if need else []))
        n = int(name[1:])
        left = self.db.execute("SELECT COUNT(*) FROM tasks WHERE phase=? AND status!='VERIFIED'", (n,)).fetchone()[0]
        total = self.db.execute("SELECT COUNT(*) FROM tasks WHERE phase=?", (n,)).fetchone()[0]
        return total > 0 and left == 0

    def plan_digest(self) -> str:
        return self.db.execute("SELECT v FROM plan WHERE k='digest'").fetchone()[0]

    def set_rcr_inputs(self, gates: list[str]) -> None:
        self.db.execute("INSERT OR REPLACE INTO plan VALUES('rcr_inputs',?)", (json.dumps(gates),))

    def record_external_signature(self, gate: str, signer: str, sig: str) -> None:
        if self._role(signer) != "external": raise LedgerError("signer is not a registered external signatory")
        self.db.execute("INSERT OR REPLACE INTO signatures VALUES(?,?,?)", (gate, signer, sig))

    # ---- scheduling -------------------------------------------------------
    def refresh_ready(self, actor: str) -> list[str]:
        if self._role(actor) != "supervisor": raise LedgerError("only supervisor may schedule")
        if self.db.execute("SELECT v FROM plan WHERE k='reviewed'").fetchone()[0] != "1":
            return []  # unreviewed plan: scheduling disabled
        out = []
        with self._tx():
            for tid, dep in self.db.execute("SELECT id,depends FROM tasks WHERE status='PENDING'").fetchall():
                if all(self.gate_ok(g) for g in json.loads(dep)):
                    self._set(tid, "READY", actor); out.append(tid)
        return out

    def lease(self, tid: str, supervisor: str, worker: str, ttl: float = 3600) -> int:
        if self._role(supervisor) != "supervisor" or self._role(worker) != "worker":
            raise LedgerError("lease needs a supervisor granting to a registered worker")
        with self._tx():
            dep = json.loads(self.db.execute("SELECT depends FROM tasks WHERE id=?", (tid,)).fetchone()[0])
            if not all(self.gate_ok(g) for g in dep): raise LedgerError("prerequisite gate no longer satisfied")
            ep = self.db.execute("SELECT epoch FROM tasks WHERE id=?", (tid,)).fetchone()[0] + 1
            self._set(tid, "LEASED", supervisor, {"worker": worker, "epoch": ep}, epoch=ep, worker=worker,
                      lease_until=time.time() + ttl)
        return ep

    def submit(self, tid: str, worker: str, epoch: int, git_sha: str) -> None:
        """Worker output is only ever a CANDIDATE: moves to VERIFYING, never VERIFIED."""
        with self._tx():
            w, ep, until = self.db.execute("SELECT worker,epoch,lease_until FROM tasks WHERE id=?", (tid,)).fetchone()
            if self.status(tid) not in ("LEASED", "RUNNING"): raise LedgerError("task not leased")
            if worker != w or epoch != ep: raise LedgerError("stale or foreign lease epoch")
            if time.time() > until: raise LedgerError("lease expired")
            if len(git_sha) != 40: raise LedgerError("submission requires exact 40-hex git sha")
            self._set(tid, "VERIFYING", worker, {"git_sha": git_sha}, sub_sha=git_sha, sub_epoch=epoch)

    def accept_receipt(self, tid: str, receipt: dict, signature: str) -> str:
        """receipt: {task, verifier, git_sha, epoch, plan, cmd, exit_code, report_hash}"""
        with self._tx():
            vid = receipt.get("verifier")
            if self._role(vid) != "verifier": raise LedgerError("receipt signer is not a registered verifier")
            if not hmac.compare_digest(signature, sign(self.principals[vid][1], receipt)):
                raise LedgerError("invalid receipt signature")
            w, sha, ep = self.db.execute("SELECT worker,sub_sha,sub_epoch FROM tasks WHERE id=?", (tid,)).fetchone()
            if self.status(tid) != "VERIFYING": raise LedgerError("task not awaiting verification")
            if vid == w: raise LedgerError("worker may not verify its own work")
            if receipt["task"] != tid or receipt["git_sha"] != sha or receipt["epoch"] != ep \
                    or receipt["plan"] != self.plan_digest():
                raise LedgerError("receipt does not match submission (task/sha/epoch/plan)")
            if receipt["exit_code"] == 0:
                self._set(tid, "VERIFIED", vid, receipt, verified_sha=sha)
                return "VERIFIED"
            att = self.db.execute("SELECT attempts FROM tasks WHERE id=?", (tid,)).fetchone()[0] + 1
            self._set(tid, "RETRY_WAIT", vid, receipt, attempts=att)
            return "RETRY_WAIT"

    def mark(self, tid: str, to: str, actor: str, reason: str, approval_sig: str | None = None) -> None:
        role = self._role(actor)
        with self._tx():
            if to == "VERIFIED": raise LedgerError("VERIFIED only via accept_receipt")
            if to == "NOT_APPLICABLE_APPROVED":
                if role != "approver" or not reason or not approval_sig or not hmac.compare_digest(
                        approval_sig, sign(self.principals[actor][1], {"task": tid, "reason": reason})):
                    raise LedgerError("NOT_APPLICABLE_APPROVED needs a signed approver reason")
            elif to in SUPERVISOR_ONLY and role != "supervisor":
                raise LedgerError(f"{role} may not set {to}")
            self._set(tid, to, actor, {"reason": reason})

    def invalidate(self, tid: str, actor: str, reason: str) -> list[str]:
        """Revoke a VERIFIED task and transitively every VERIFIED task whose gates depended on its phase."""
        if self._role(actor) != "supervisor": raise LedgerError("only supervisor invalidates")
        hit, todo = [], [tid]
        with self._tx():
            while todo:
                t = todo.pop()
                if self.status(t) == "VERIFIED":
                    self._set(t, "NEEDS_REVALIDATION", actor, {"reason": reason}, verified_sha=None); hit.append(t)
                    ph = self.db.execute("SELECT phase FROM tasks WHERE id=?", (t,)).fetchone()[0]
                    for oid, dep in self.db.execute("SELECT id,depends FROM tasks").fetchall():
                        if f"GATE:P{ph}" in json.loads(dep) and self.status(oid) in ("VERIFIED", "READY"):
                            if self.status(oid) == "VERIFIED": todo.append(oid)
        return hit
