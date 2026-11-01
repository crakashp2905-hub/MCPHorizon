"""Obligation inference from TRUSTED effect templates (P40-09) and an UNTRUSTED proposal hook with owner approval + immutable change log (P40-10).
An LLM (or any agent) can only PROPOSE; a proposal never takes effect without a policy-owner APPROVAL evidence token bound to the proposal digest, and it may only TIGHTEN."""
from __future__ import annotations
import hashlib, json
from ..hpolicy.authority import EvidenceError
from .terms import parse, Obligation, ObligationError

EFFECT_CLASSES = {"deploy_prod": "release_prod", "deploy_staging": "release_staging", "read_logs": "read_only", "status": "read_only"}     # trusted action -> effect class
TEMPLATES = {"read_only": []}      # release_* classes are filled from the policy catalog (see infer)


def infer(action, catalog_obligations, *, classes=EFFECT_CLASSES):
    """Returns (status, obligations). status: OK | UNKNOWN. An action the catalog does not know is UNKNOWN, never 'no obligations'."""
    if action not in classes: return "UNKNOWN", []
    if classes[action] == "read_only": return "OK", []
    return "OK", [o for o in catalog_obligations if o.action == action]


def tightens_only(base: Obligation, new: Obligation) -> list:
    """Reasons a replacement is NOT a tightening of `base` (empty list = tightening or equal)."""
    r = []
    if not set(new.roles) <= set(base.roles): r.append("roles widened")
    if base.bind_args and not new.bind_args: r.append("args binding dropped")
    if base.distinct_from_requester and not new.distinct_from_requester: r.append("self-approval allowed")
    if base.consume and not new.consume: r.append("single-use dropped")
    if not set(base.order_after) <= set(new.order_after): r.append("ordering dropped")
    if not set(base.claim_equals) <= set(new.claim_equals): r.append("claim constraint dropped")
    if base.deadline_s is not None and (new.deadline_s is None or new.deadline_s > base.deadline_s): r.append("deadline relaxed")
    if new.valid_until > base.valid_until or new.valid_from < base.valid_from: r.append("validity window widened")
    if (new.action, new.kind, new.evidence_kind) != (base.action, base.kind, base.evidence_kind): r.append("identity changed")
    return r


class ChangeLog:
    """Append-only, hash-chained. Detects edits, deletions and reordering of past entries (not truncation of the tail without an external anchor)."""
    def __init__(self): self.entries = []
    def append(self, event, payload):
        prev = self.entries[-1]["h"] if self.entries else "0" * 64; e = {"seq": len(self.entries), "prev": prev, "event": event, "payload": payload}
        e["h"] = hashlib.sha256(json.dumps({k: e[k] for k in ("seq", "prev", "event", "payload")}, sort_keys=True).encode()).hexdigest(); self.entries.append(e); return e
    def verify(self):
        prev = "0" * 64
        for i, e in enumerate(self.entries):
            h = hashlib.sha256(json.dumps({k: e[k] for k in ("seq", "prev", "event", "payload")}, sort_keys=True).encode()).hexdigest()
            if e["seq"] != i or e["prev"] != prev or e["h"] != h: return False
            prev = e["h"]
        return True


class Proposals:
    def __init__(self, authority, active: list, clock):
        self.auth, self.ver, self.clock, self.active, self.log, self.pending = authority, authority.verifier(), clock, {o.id: o for o in active}, ChangeLog(), {}
    @staticmethod
    def digest(dicts): return "sha256:" + hashlib.sha256(json.dumps(dicts, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    def propose(self, proposer: str, obligations: list) -> str:
        """Stored inert. Malformed proposals are rejected outright (and logged)."""
        d = self.digest(obligations)
        try: parsed = [parse(o, policy_version=self.auth.version, now=int(self.clock())) for o in obligations]
        except ObligationError as e: self.log.append("REJECT_MALFORMED", {"proposer": proposer, "digest": d, "code": e.code}); raise
        self.pending[d] = parsed; self.log.append("PROPOSED", {"proposer": proposer, "digest": d, "ids": [o.id for o in parsed]}); return d
    def decide(self, digest: str, approval_token: str) -> list:
        """Needs APPROVAL evidence from role 'policy_owner' bound to this exact proposal digest. Then tightening-only is enforced regardless of approval."""
        if digest not in self.pending: raise EvidenceError("UNKNOWN_PROPOSAL")
        p = self.ver.verify(approval_token, now=int(self.clock()))
        if p["role"] != "policy_owner" or p["kind"] != "APPROVAL" or p["artifact"] != digest: self.log.append("REJECT_APPROVAL", {"digest": digest, "why": "wrong role/kind/binding"}); raise EvidenceError("NOT_OWNER_APPROVAL")
        bad = {}
        for o in self.pending[digest]:
            if o.id in self.active:
                r = tightens_only(self.active[o.id], o)
                if r: bad[o.id] = r
        if bad: self.log.append("REJECT_RELAXATION", {"digest": digest, "violations": bad}); raise EvidenceError("RELAXATION_REJECTED", json.dumps(bad, sort_keys=True))
        for o in self.pending.pop(digest): self.active[o.id] = o
        self.log.append("ACTIVATED", {"digest": digest, "approved_by": p["iss"]}); return sorted(self.active)
