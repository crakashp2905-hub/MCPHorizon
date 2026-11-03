"""HorizonZero claim registry slice (HF-016..021). RESEARCH PROTOTYPE, CANDIDATE, outside the trusted kernel.
An AssuranceClaim is scoped, versioned and bound to dependency digests; invalidating any dependency (transitively) suspends every claim resting on it, and permits are refused for suspended/expired/unknown claims.
Outcome states keep prevention and observation apart: an effect is VERIFIED_COMMITTED only with a valid, independent witness claim; otherwise UNKNOWN/DISPATCHED. Unknown claims fail closed."""
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass

STATES = ("VALID", "SUSPENDED", "EXPIRED", "REVOKED")


class ClaimError(Exception):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


@dataclass(frozen=True)
class AssuranceClaim:
    claim_id: str; scope: tuple; epoch: int; expires_at: int
    depends_on: tuple          # ids of assumptions/adapters/witnesses/other claims
    digests: tuple             # ((dep_id, digest),...) bound at issue time
    def digest(self): return hashlib.sha256(json.dumps([self.claim_id, self.scope, self.epoch, self.expires_at, self.depends_on, self.digests], sort_keys=True).encode()).hexdigest()


class Registry:
    def __init__(self, clock): self.clock, self.claims, self.nodes, self.invalid = clock, {}, {}, {}   # nodes: dep_id -> current digest; invalid: dep_id -> reason
    def set_node(self, dep_id, digest): self.nodes[dep_id] = digest
    def add(self, c: AssuranceClaim):
        if c.claim_id in self.claims: raise ClaimError("DUPLICATE")
        if not c.depends_on or not c.scope: raise ClaimError("EMPTY_SCOPE_OR_DEPS")
        if set(c.depends_on) != {d for d, _ in c.digests}: raise ClaimError("DIGESTS_MUST_COVER_ALL_DEPS")
        self.claims[c.claim_id] = c
    def invalidate(self, dep_id, reason): self.invalid[dep_id] = reason
    def revoke(self, claim_id):
        if claim_id not in self.claims: raise ClaimError("UNKNOWN_CLAIM")
        self.invalid[claim_id] = "revoked"
    def _closure_bad(self, dep_id, seen=()):
        if dep_id in seen: return "cycle"
        if dep_id in self.invalid: return self.invalid[dep_id]
        if dep_id in self.claims:
            c = self.claims[dep_id]
            for d, dg in c.digests:
                if d in self.nodes and self.nodes[d] != dg: return f"digest_changed:{d}"
                if d not in self.nodes and d not in self.claims: return f"missing_dependency:{d}"
            for d in c.depends_on:
                r = self._closure_bad(d, seen + (dep_id,))
                if r: return f"{d}:{r}"
        return None
    def status(self, claim_id, epoch_now: int) -> tuple:
        c = self.claims.get(claim_id)
        if c is None: return "REVOKED", "unknown_claim"                                   # unknown fails closed
        if claim_id in self.invalid: return "REVOKED", self.invalid[claim_id]
        if self.clock() >= c.expires_at: return "EXPIRED", "lease"
        if epoch_now > c.epoch: return "SUSPENDED", "stale_epoch"
        for d, dg in c.digests:
            if d in self.nodes and self.nodes[d] != dg: return "SUSPENDED", f"digest_changed:{d}"
            if d not in self.nodes and d not in self.claims: return "SUSPENDED", f"missing_dependency:{d}"
        for d in c.depends_on:
            r = self._closure_bad(d)
            if r: return "SUSPENDED", f"{d}:{r}"
        return "VALID", ""
    def may_issue_permit(self, claim_id, epoch_now: int) -> bool: return self.status(claim_id, epoch_now)[0] == "VALID"


def outcome(committed_by_sink_journal: bool | None, witness_claim_valid: bool) -> str:
    """Prevention != observation: VERIFIED_COMMITTED needs a valid independent witness; without one a possibly-committed effect is UNKNOWN, never PASS."""
    if committed_by_sink_journal is None: return "UNKNOWN"
    if committed_by_sink_journal and witness_claim_valid: return "VERIFIED_COMMITTED"
    if committed_by_sink_journal: return "UNKNOWN"
    return "NOT_OBSERVED" if witness_claim_valid else "UNKNOWN"
