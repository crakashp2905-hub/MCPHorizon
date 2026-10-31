"""Approval audit with operator role separation (P10-04): requester != approver, approver must hold a distinct role, high-risk needs two distinct approvers; every step hash-chained."""
from __future__ import annotations
import time
from horizon.service.audit import AuditLog


class ApprovalError(Exception):
    def __init__(self, code, msg): super().__init__(msg); self.code = code


ROLES = {"requester": {"request"}, "approver": {"approve", "reject"}, "admin": {"request", "approve", "reject", "revoke"}}


class ApprovalLog:
    def __init__(self, audit_path: str, roles: dict[str, str], clock=time.time, two_person: set[str] = frozenset()):
        self.audit, self.roles, self.clock, self.two = AuditLog(audit_path), roles, clock, set(two_person); self.req: dict[str, dict] = {}; self.n = 0

    def close(self): self.audit.close()
    def _can(self, who: str, act: str):
        if act not in ROLES.get(self.roles.get(who, ""), set()): raise ApprovalError("ROLE_FORBIDDEN", f"{who!r} (role {self.roles.get(who)!r}) may not {act}")

    def request(self, who: str, kind: str, subject_digest: str, reason: str) -> str:
        self._can(who, "request"); self.n += 1; rid = f"ap-{self.n}"; self.req[rid] = {"who": who, "kind": kind, "digest": subject_digest, "approvers": [], "status": "PENDING"}
        self.audit.write({"ev": "approval_request", "id": rid, "by": who, "kind": kind, "digest": subject_digest, "t": self.clock()}); return rid

    def decide(self, who: str, rid: str, approve: bool, subject_digest: str) -> str:
        r = self.req.get(rid)
        if r is None: raise ApprovalError("UNKNOWN", "no such request")
        self._can(who, "approve" if approve else "reject")
        if who == r["who"]: raise ApprovalError("SELF_APPROVAL", "requester cannot decide their own request")
        if r["status"] != "PENDING": raise ApprovalError("NOT_PENDING", f"request is {r['status']}")
        if subject_digest != r["digest"]: raise ApprovalError("DIGEST_MISMATCH", "approval is bound to the exact digest requested")     # no approving a different artifact
        if who in r["approvers"]: raise ApprovalError("DUPLICATE_APPROVER", "same approver cannot count twice")
        if not approve: r["status"] = "REJECTED"
        else:
            r["approvers"].append(who)
            if len(r["approvers"]) >= (2 if r["kind"] in self.two else 1): r["status"] = "APPROVED"
        self.audit.write({"ev": "approval_decision", "id": rid, "by": who, "approve": approve, "status": r["status"], "t": self.clock()}); return r["status"]

    def is_approved(self, rid: str, subject_digest: str) -> bool:
        r = self.req.get(rid); return bool(r and r["status"] == "APPROVED" and r["digest"] == subject_digest)

    def revoke(self, who: str, rid: str):
        self._can(who, "revoke"); self.req[rid]["status"] = "REVOKED"; self.audit.write({"ev": "approval_revoke", "id": rid, "by": who, "t": self.clock()})
