"""Request / decision / permit / receipt records (masterplan 2.3). CANDIDATE, stdlib only. Pure data + deny-only checks; nothing here signs, stores or executes anything."""
from __future__ import annotations
from dataclasses import dataclass
from .effect import CanonicalEffectV1, ContractError, _sha, _text
from .states import Decision, EffectState


@dataclass(frozen=True)
class TrustedIdentity:
    tenant_id: str; principal_id: str; agent_id: str; session_id: str
    authenticated_by: str                      # who vouched (e.g. an authenticator id); NOT a model-supplied string

    def validate(self):
        for k in ("tenant_id", "principal_id", "agent_id", "session_id", "authenticated_by"):
            if not _text(getattr(self, k)): raise ContractError("MALFORMED", f"identity.{k}")
        return self


@dataclass(frozen=True)
class DelegatedPrincipal:
    principal_id: str; chain: tuple = ()      # ordered principal ids from the root grantor to this principal


@dataclass(frozen=True)
class ArtifactRef:
    digest: str; label: str = "UNKNOWN"      # lineage label; an unlabelled artifact is UNKNOWN, never PUBLIC


@dataclass(frozen=True)
class EffectRequestV1:
    identity: TrustedIdentity; effect: CanonicalEffectV1; provenance: tuple; requested_by: DelegatedPrincipal; trace_id: str

    def validate(self):
        self.identity.validate(); self.effect.validate()
        e, i = self.effect, self.identity
        if (e.tenant_id, e.principal_id, e.agent_id, e.session_id) != (i.tenant_id, i.principal_id, i.agent_id, i.session_id): raise ContractError("BINDING_MISMATCH", "effect identity differs from authenticated identity")
        if e.trace_id != self.trace_id: raise ContractError("BINDING_MISMATCH", "trace_id differs")
        if not all(isinstance(a, ArtifactRef) and _sha(a.digest) for a in self.provenance): raise ContractError("MALFORMED", "provenance must be ArtifactRef(sha256) items")
        if e.artifact_lineage_digests is not None and tuple(sorted(a.digest for a in self.provenance)) != tuple(sorted(e.artifact_lineage_digests)): raise ContractError("BINDING_MISMATCH", "provenance differs from effect.artifact_lineage_digests")
        return self


@dataclass(frozen=True)
class DecisionV1:
    decision: Decision; effect_digest: str; policy_digest: str; policy_epoch: int; reasons: tuple = ()

    def validate(self):
        if not isinstance(self.decision, Decision): raise ContractError("MALFORMED", "decision")
        if not (_sha(self.effect_digest) and _sha(self.policy_digest)): raise ContractError("MALFORMED", "digests")
        return self


@dataclass(frozen=True)
class PermitV1:
    effect_digest: str; nonce: str; issuer_role: str; policy_epoch: int; assurance_claim_id: str | None; assurance_epoch: int | None; not_after: int; token: str   # opaque signed token, verified elsewhere

    def validate(self):
        if not (_sha(self.effect_digest) and _text(self.nonce) and _text(self.issuer_role) and _text(self.token)): raise ContractError("MALFORMED", "permit")
        return self


def permit_covers(permit: PermitV1, effect: CanonicalEffectV1, *, now: int, current_policy_epoch: int, current_assurance_epoch: int | None) -> str | None:
    """Deny-only pre-check (the signature and nonce are verified by the authority/verifier, not here). Returns None if consistent, else the first error code. Fail-closed on any doubt."""
    try: permit.validate(); eff = effect.digest()
    except ContractError as e: return e.code
    if permit.effect_digest != eff: return "EFFECT_MISMATCH"
    if now > permit.not_after or now > effect.deadline: return "EXPIRED"
    if permit.policy_epoch != effect.policy_epoch or effect.policy_epoch != current_policy_epoch: return "STALE_POLICY"
    if effect.assurance_claim_id is not None:
        if permit.assurance_claim_id != effect.assurance_claim_id or permit.assurance_epoch != effect.assurance_epoch or current_assurance_epoch != effect.assurance_epoch: return "ASSURANCE_DENIED"
    elif permit.assurance_claim_id is not None: return "ASSURANCE_DENIED"
    return None


WITNESS_KINDS = ("sink-journal", "receiver", "broker-report", "caller-supplied")
INDEPENDENT_WITNESS_KINDS = ("sink-journal", "receiver")


@dataclass(frozen=True)
class EffectReceiptV1:
    effect_id: str; effect_digest: str; state: EffectState; witness: str | None = None; observation: str | None = None   # witness: an id of the trusted observer, never the gateway/agent
    witness_kind: str | None = None      # one of WITNESS_KINDS; only "sink-journal" and "receiver" count as independent evidence (see is_independent_evidence); "broker-report"/"caller-supplied" are the enforcement path's own claims

    def is_independent_evidence(self) -> bool: return self.witness_kind in INDEPENDENT_WITNESS_KINDS and _text(self.witness)

    def validate(self):
        if not (_text(self.effect_id) and _sha(self.effect_digest) and isinstance(self.state, EffectState)): raise ContractError("MALFORMED", "receipt")
        if self.witness_kind is not None and self.witness_kind not in WITNESS_KINDS: raise ContractError("MALFORMED", "unknown witness_kind")
        if self.state in (EffectState.COMMITTED, EffectState.RECONCILED_COMMITTED, EffectState.RECONCILED_BLOCKED) and not _text(self.witness): raise ContractError("MISSING_FIELD", "a committed or reconciled receipt must name the trusted witness")
        return self
