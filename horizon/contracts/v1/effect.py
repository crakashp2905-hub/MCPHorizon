"""CanonicalEffectV1: the ONE normative effect record (masterplan 2.2). CANDIDATE, stdlib only, imports nothing from the repo.
Fields come from trusted registries and authenticated session context; this class only VALIDATES shape and presence, it cannot make a value trustworthy. Presence rules differ by effect class
(mutating classes need an idempotency key and an assurance claim); unknown security-critical values (schema version, effect class, transport, target kind) are rejected, never defaulted.
`digest()` is domain-separated over every field, so changing ANY field (one byte of args, tenant, session, delegation, epoch, deadline...) changes it."""
from __future__ import annotations
import hashlib, json, re
from dataclasses import dataclass, fields, asdict

SCHEMA_VERSION = "1"
DOMAIN = b"mcphorizon.canonical-effect.v1.1\x00"
EFFECT_CLASSES = frozenset({"read", "list", "write", "modify", "delete", "execute", "send", "admin"})
MUTATING = frozenset({"write", "modify", "delete", "execute", "send", "admin"})
TRANSPORTS = frozenset({"mcp-stdio", "mcp-http", "utcp", "a2a", "codemode", "direct-kernel"})
TARGET_KINDS = frozenset({"file", "url", "process", "queue", "memory", "browser"})
SHA = re.compile(r"sha256:[0-9a-f]{64}")
EMPTY_CHAIN = "sha256:" + hashlib.sha256(b"mcphorizon.delegation-chain.v1\x00[]").hexdigest()   # explicit 'no delegation' marker, distinct from an absent field
_TEXT = re.compile(r"[^\x00-\x1f\x7f]{1,2048}")


class ContractError(ValueError):
    def __init__(self, code, msg=""): super().__init__(f"{code}: {msg}" if msg else code); self.code = code


@dataclass(frozen=True)
class CanonicalEffectV1:
    schema_version: str; effect_id: str; tenant_id: str; agent_id: str; session_id: str; principal_id: str
    delegation_chain_digest: str; tool_server_id: str; tool_id: str; transport: str; effect_class: str
    target_kind: str; target_canonical: str; arguments_digest: str; artifact_lineage_digests: tuple | None
    purpose: str; policy_digest: str; policy_epoch: int; assurance_claim_id: str | None; assurance_epoch: int | None
    approval_id: str | None; budget_reservation_id: str | None; deadline: int; idempotency_key: str | None; nonce: str; trace_id: str

    def validate(self) -> "CanonicalEffectV1":
        if self.schema_version != SCHEMA_VERSION: raise ContractError("VERSION", "unsupported schema_version")
        for k in ("effect_id", "tenant_id", "agent_id", "session_id", "principal_id", "tool_server_id", "tool_id", "target_canonical", "purpose", "nonce", "trace_id"):
            if not _text(getattr(self, k)): raise ContractError("MALFORMED", f"{k} must be a non-empty string without control characters")
        if self.effect_class not in EFFECT_CLASSES: raise ContractError("UNKNOWN_EFFECT", "effect_class not in the versioned registry")
        if self.transport not in TRANSPORTS: raise ContractError("UNSUPPORTED", "transport not supported")
        if self.target_kind not in TARGET_KINDS: raise ContractError("UNSUPPORTED", "target_kind not supported")
        for k in ("delegation_chain_digest", "arguments_digest", "policy_digest"):
            if not _sha(getattr(self, k)): raise ContractError("MALFORMED", f"{k} must be sha256:<64 hex>")
        for k in ("policy_epoch", "deadline"):
            if not _nonneg(getattr(self, k)): raise ContractError("MALFORMED", f"{k} must be a non-negative integer")
        for k in ("assurance_claim_id", "approval_id", "budget_reservation_id", "idempotency_key"):
            v = getattr(self, k)
            if v is not None and not _text(v): raise ContractError("MALFORMED", f"{k} must be absent or a non-empty string")
        if self.assurance_epoch is not None and not _nonneg(self.assurance_epoch): raise ContractError("MALFORMED", "assurance_epoch must be absent or a non-negative integer")
        if (self.assurance_claim_id is None) != (self.assurance_epoch is None): raise ContractError("MALFORMED", "assurance_claim_id and assurance_epoch go together")
        if self.artifact_lineage_digests is not None and not (isinstance(self.artifact_lineage_digests, tuple) and all(_sha(x) for x in self.artifact_lineage_digests)):
            raise ContractError("MALFORMED", "artifact_lineage_digests must be a tuple of sha256 digests (empty tuple = traced, none) or absent")
        if self.effect_class in MUTATING:
            for k in ("idempotency_key", "assurance_claim_id", "assurance_epoch"):
                if getattr(self, k) is None: raise ContractError("MISSING_FIELD", f"{k} is required for effect_class {self.effect_class}")
        if self.effect_class == "send" and self.artifact_lineage_digests is None: raise ContractError("MISSING_FIELD", "artifact_lineage_digests is required for send (an empty tuple is an explicit 'traced, none')")
        return self

    def digest(self) -> str:
        self.validate()
        body = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return "sha256:" + hashlib.sha256(DOMAIN + body).hexdigest()


FIELD_NAMES = tuple(f.name for f in fields(CanonicalEffectV1))


def _text(v): return isinstance(v, str) and _TEXT.fullmatch(v) is not None
def _sha(v): return isinstance(v, str) and SHA.fullmatch(v) is not None
def _nonneg(v): return isinstance(v, int) and not isinstance(v, bool) and v >= 0
