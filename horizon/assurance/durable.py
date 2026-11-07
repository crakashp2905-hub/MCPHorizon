"""Durable, signed, scoped assurance claims with append-only history (blueprint S4-01..S4-07). CANDIDATE; denies, never grants (cannot create authority by itself).
State = replay of a hash-chained append-only SQLite event log; claim bodies are Ed25519-signed by an issuer in an operator-owned TrustStore. Any anomaly (broken chain, bad signature,
db error, unknown claim) FAILS CLOSED. Revocation and permit issuance are ordered in ONE log under BEGIN IMMEDIATE, so across processes no PERMIT is logged after a REVOKE/INVALIDATE that affects it.
Old claims and receipts are never rewritten: invalidation/restoration are new events. Evidence grades above SOURCE_VERIFIED need a signature by a DIFFERENT key held under the matching role issuer."""
from __future__ import annotations
import hashlib, json, sqlite3
from .registry import AssuranceClaim, Registry
from horizon.authz.keys import TrustError

BINDING_FIELDS = ("agent", "runtime", "policy", "tool", "witness", "artifact", "issuer", "verifier")
INVALIDATION_REASONS = ("adapter_changed", "tool_changed", "agent_changed", "consent_revoked", "journal_lost", "proof_expired", "policy_changed", "witness_unhealthy", "operator_revoked")
GRADES = ("SOURCE_VERIFIED", "INDEPENDENTLY_REPRODUCED", "EXTERNALLY_AUDITED")
GRADE_ROLE = {"INDEPENDENTLY_REPRODUCED": "reproducer", "EXTERNALLY_AUDITED": "auditor"}
CLAIM_ISSUER_ROLE = "assurance-issuer"


class DurableError(Exception):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


def _canon(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def claim_body(c: AssuranceClaim, binding: dict) -> dict:
    return {"claim_id": c.claim_id, "scope": list(c.scope), "epoch": c.epoch, "expires_at": c.expires_at, "depends_on": list(c.depends_on), "digests": [list(x) for x in c.digests], "binding": binding}


def sign_claim(c: AssuranceClaim, binding: dict, signer) -> dict:
    if set(binding) != set(BINDING_FIELDS) or not all(isinstance(v, str) and v for v in binding.values()): raise DurableError("BAD_BINDING", "binding must name exactly " + ",".join(BINDING_FIELDS))
    if signer.iss != CLAIM_ISSUER_ROLE: raise DurableError("WRONG_ISSUER_ROLE")
    body = claim_body(c, binding); return {"body": body, "kid": signer.kid, "sig": signer.sign(_canon(body)).hex()}


def sign_attestation(claim_id: str, grade: str, signer) -> dict:
    if grade not in GRADE_ROLE: raise DurableError("BAD_GRADE")
    body = {"claim_id": claim_id, "grade": grade}; return {"body": body, "kid": signer.kid, "iss": signer.iss, "sig": signer.sign(_canon(body)).hex()}


class DurableRegistry:
    def __init__(self, path: str, trust, clock):
        self.path, self.trust, self.clock = path, trust, clock
        c = self._conn(); c.execute("CREATE TABLE IF NOT EXISTS ev(seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, subject TEXT NOT NULL, data TEXT NOT NULL, prev TEXT NOT NULL, h TEXT NOT NULL)"); c.close()

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None); c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA busy_timeout=30000"); return c

    # ---- log ----
    @staticmethod
    def _h(prev, kind, subject, data): return hashlib.sha256(prev.encode() + _canon([kind, subject, data])).hexdigest()

    def _append(self, c, kind, subject, data):
        row = c.execute("SELECT h FROM ev ORDER BY seq DESC LIMIT 1").fetchone(); prev = row[0] if row else "0" * 64
        c.execute("INSERT INTO ev(kind,subject,data,prev,h) VALUES(?,?,?,?,?)", (kind, subject, json.dumps(data, sort_keys=True), prev, self._h(prev, kind, subject, data)))

    def _events(self, c):
        prev, out = "0" * 64, []
        for seq, kind, subject, data, p, h in c.execute("SELECT seq,kind,subject,data,prev,h FROM ev ORDER BY seq"):
            d = json.loads(data)
            if p != prev or h != self._h(prev, kind, subject, d): raise DurableError("LOG_TAMPERED", f"chain broken at seq {seq}")
            out.append((seq, kind, subject, d)); prev = h
        return out

    def _replay(self, c):
        """-> (Registry, grades). Claims with bad signatures are simply absent -> unknown -> fail closed."""
        reg = Registry(self.clock); permanent = set(); grades = {}; issued = {}
        for seq, kind, subject, d in self._events(c):
            if kind == "NODE": reg.set_node(subject, d["digest"])
            elif kind == "ISSUE":
                try:
                    pub = self.trust.resolve(d["kid"], CLAIM_ISSUER_ROLE); pub.verify(bytes.fromhex(d["sig"]), _canon(d["body"]))
                    b = d["body"]; reg.add(AssuranceClaim(b["claim_id"], tuple(b["scope"]), b["epoch"], b["expires_at"], tuple(b["depends_on"]), tuple(tuple(x) for x in b["digests"]))); issued[b["claim_id"]] = d["kid"]
                except Exception: pass
            elif kind == "INVALIDATE": reg.invalidate(subject, d["reason"])
            elif kind == "RESTORE":
                if subject not in permanent: reg.invalid.pop(subject, None)
            elif kind == "REVOKE":
                if subject in reg.claims: reg.revoke(subject); permanent.add(subject)
            elif kind == "ATTEST":
                try:
                    a = d["att"]; role = GRADE_ROLE[a["body"]["grade"]]
                    if a["body"]["claim_id"] != subject or a["kid"] == issued.get(subject, None) or subject not in issued: continue
                    self.trust.resolve(a["kid"], role).verify(bytes.fromhex(a["sig"]), _canon(a["body"]))
                    if a["iss"] != role: continue
                    grades.setdefault(subject, set()).add(a["body"]["grade"])
                except Exception: pass
        return reg, grades

    # ---- writes ----
    def _write(self, kind, subject, data):
        c = self._conn()
        try:
            c.execute("BEGIN IMMEDIATE"); self._events(c); self._append(c, kind, subject, data); c.execute("COMMIT")
        except Exception:
            try: c.execute("ROLLBACK")
            except Exception: pass
            raise
        finally: c.close()

    def issue(self, signed: dict): self._write("ISSUE", signed["body"]["claim_id"], signed)
    def set_node(self, dep_id: str, digest: str): self._write("NODE", dep_id, {"digest": digest})
    def invalidate(self, dep_id: str, reason: str):
        if reason not in INVALIDATION_REASONS: raise DurableError("BAD_REASON")
        self._write("INVALIDATE", dep_id, {"reason": reason})
    def restore(self, dep_id: str, evidence: str):
        if not evidence: raise DurableError("RESTORE_NEEDS_EVIDENCE")
        self._write("RESTORE", dep_id, {"evidence": evidence})
    def revoke(self, claim_id: str): self._write("REVOKE", claim_id, {})
    def attest(self, att: dict): self._write("ATTEST", att["body"]["claim_id"], {"att": att})

    # ---- reads ----
    def status(self, claim_id: str, epoch_now: int) -> tuple:
        try:
            c = self._conn()
            try: reg, _ = self._replay(c); return reg.status(claim_id, epoch_now)
            finally: c.close()
        except Exception as e: return "REVOKED", "fail_closed:" + getattr(e, "code", type(e).__name__)

    def grade(self, claim_id: str) -> str:
        """SOURCE_VERIFIED unless a valid attestation by a DIFFERENT key under the role issuer exists. Reproduction needs an independent party; this code cannot supply one."""
        try:
            c = self._conn()
            try: _, g = self._replay(c)
            finally: c.close()
        except Exception: return "UNVERIFIED"
        s = g.get(claim_id, set()); return "EXTERNALLY_AUDITED" if "EXTERNALLY_AUDITED" in s else "INDEPENDENTLY_REPRODUCED" if "INDEPENDENTLY_REPRODUCED" in s else "SOURCE_VERIFIED"

    def permit(self, claim_id: str, epoch_now: int) -> tuple:
        """Atomic check-and-log: the PERMIT event is appended in the same IMMEDIATE transaction that checks status, so it is ordered against every revoke/invalidate."""
        try:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE"); reg, _ = self._replay(c); st = reg.status(claim_id, epoch_now)
                if st[0] != "VALID": c.execute("COMMIT"); return False, st[1] or st[0]
                self._append(c, "PERMIT", claim_id, {"epoch": epoch_now}); c.execute("COMMIT"); return True, ""
            except Exception:
                try: c.execute("ROLLBACK")
                except Exception: pass
                raise
            finally: c.close()
        except Exception as e: return False, "fail_closed:" + getattr(e, "code", type(e).__name__)

    def head(self) -> tuple:
        """(seq, hash) of the log tail. Hash chains cannot detect TRUNCATION of the tail on their own: export this to an independent anchor (receiver/operator-owned) and pass it to check_anchor."""
        c = self._conn()
        try:
            self._events(c); row = c.execute("SELECT seq,h FROM ev ORDER BY seq DESC LIMIT 1").fetchone(); return row if row else (0, "0" * 64)
        finally: c.close()

    def check_anchor(self, seq: int, h: str) -> bool:
        """True only if the (verified) log still contains the anchored event at exactly this seq/hash. A truncated or rewritten tail returns False."""
        try:
            c = self._conn()
            try: self._events(c); row = c.execute("SELECT h FROM ev WHERE seq=?", (seq,)).fetchone(); return bool(row) and row[0] == h
            finally: c.close()
        except Exception: return False

    def history(self) -> list:
        c = self._conn()
        try: return [(s, k, sub) for s, k, sub, _ in self._events(c)]
        finally: c.close()
