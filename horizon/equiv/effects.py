"""Bounded effect language and the equivalence relation ≈_P (P14-01, P14-02).
An Effect is what a protected operation DOES, independent of how it was requested. Typed semantics: kind ∈ KINDS; target is canonical; payload is the digest of the bytes actually delivered."""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from horizon import normalize as N

KINDS = ("read", "list", "write", "modify", "delete", "execute", "send")                 # `admin` and `receive` are outside the supported algebraic subset
SUPPORTED_HTTP = {"GET": "read", "POST": "send", "PUT": "write", "DELETE": "delete"}
VERDICTS = ("ALLOW", "DENY", "REVIEW", "UNKNOWN")


class Unsupported(Exception):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


@dataclass(frozen=True)
class Effect:
    kind: str
    target_kind: str
    target: str                                  # canonical identifier
    principal: str
    tenant: str
    payload: str | None = None                   # sha256 of delivered bytes (None for read/delete without a body)
    verdict: str = "ALLOW"
    parent: str | None = None                    # causality: id of the program/agent run that issued it
    protocol: str = field(default="", compare=False)       # provenance only: NOT part of the equivalence

    def __post_init__(self):
        if self.kind not in KINDS: raise Unsupported("UNSUPPORTED_KIND", self.kind)
        if self.verdict not in VERDICTS: raise Unsupported("BAD_VERDICT", self.verdict)


def payload_digest(b: bytes | str | None) -> str | None:
    if b is None or b == b"" or b == "": return None
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode()).hexdigest()


def make(kind, target_kind, raw, *, principal, tenant, payload=None, verdict="ALLOW", parent=None, protocol="") -> Effect:
    t = N.canonical_target(target_kind, raw); return Effect(kind, t["kind"], t["canonical_id"], principal, tenant, payload_digest(payload), verdict, parent, protocol)


def equivalent(a: Effect, b: Effect, *, causality: bool = False) -> bool:
    """≈_P: equal on (kind, target, principal, tenant, payload, verdict). Protocol never matters; causality only when requested. Reflexive/symmetric/transitive: kernel of a projection."""
    ka = lambda e: (e.kind, e.target_kind, e.target, e.principal, e.tenant, e.payload, e.verdict) + ((e.parent,) if causality else ())
    return ka(a) == ka(b)


def sequence_equivalent(xs: list, ys: list, **kw) -> bool: return len(xs) == len(ys) and all(equivalent(a, b, **kw) for a, b in zip(xs, ys))
