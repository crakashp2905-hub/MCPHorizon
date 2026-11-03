"""ENG-PR03 (E03-01..03, HARD-A02/B03 subset): CanonicalEffect = the ONE object adapters build for a concrete effect; the commit-time check derives every verifier input from it so
callers cannot pass mutually inconsistent fields. Session and server are bound through the args digest (the signed effect schema is unchanged and stays frozen).
Unknown effect types fail closed. CANDIDATE: in-process library; no durable ledger (ENG-PR04)."""
from __future__ import annotations
import hashlib
from dataclasses import dataclass
from horizon.authz import effect as E
from horizon.authz.gateway import ProofError, Verifier

DOMAIN = b"mcphorizon.canonical-effect.v1\x00"


@dataclass(frozen=True)
class CanonicalEffect:
    tenant: str; server_id: str; session_id: str; principal: str
    effect: str                      # must be in authz.effect.EFFECTS
    target_kind: str; target_raw: str
    args: object                     # JSON-serialisable

    def validate(self) -> "CanonicalEffect":
        for k in ("tenant", "server_id", "session_id", "principal", "target_kind", "target_raw"):
            v = getattr(self, k)
            if not isinstance(v, str) or not v or len(v) > 2048 or "\x00" in v: raise ProofError("MALFORMED", f"{k} must be a non-empty string")
        if self.effect not in E.EFFECTS: raise ProofError("UNKNOWN_EFFECT", "effect type not in the versioned registry")
        return self

    def bound_args_digest(self) -> str:
        """Digest over (tenant, server, session, args): a permit minted for one session/server cannot be presented in another."""
        self.validate()
        body = E.canonical({"tenant": self.tenant, "server": self.server_id, "session": self.session_id, "args": self.args})
        return "sha256:" + hashlib.sha256(DOMAIN + body).hexdigest()


def commit_verify(verifier: Verifier, token, ce: CanonicalEffect, *, consume: bool = True) -> dict:
    """Commit-time check immediately before the effect. Raises ProofError; returns the verified claim. Nothing else may authorise an effect."""
    ce.validate()
    return verifier.verify(token, principal=ce.principal, tenant=ce.tenant, effect=ce.effect, target={"kind": ce.target_kind, "raw": ce.target_raw}, args_digest=ce.bound_args_digest(), consume=consume)
