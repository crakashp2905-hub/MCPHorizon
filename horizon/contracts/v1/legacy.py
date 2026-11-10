"""Adapter between the existing `horizon.effects.canonical.CanonicalEffect` and CanonicalEffectV1. CANDIDATE. This is the ONLY contracts module that imports repo code.
The legacy object does not carry agent/tool/transport/policy/epoch/delegation fields, so `from_legacy` takes every one of them EXPLICITLY from the caller (a trusted registry); nothing trust-bearing is defaulted."""
from __future__ import annotations
import hashlib
from horizon.authz import effect as E
from horizon.effects.canonical import CanonicalEffect
from .effect import CanonicalEffectV1, ContractError, EFFECT_CLASSES, EMPTY_CHAIN, SCHEMA_VERSION


def from_legacy(ce: CanonicalEffect, *, effect_id: str, agent_id: str, tool_id: str, transport: str, purpose: str, policy_digest: str, policy_epoch: int, deadline: int, nonce: str, trace_id: str,
                delegation_chain_digest: str = EMPTY_CHAIN, artifact_lineage_digests=None, assurance_claim_id=None, assurance_epoch=None, approval_id=None, budget_reservation_id=None,
                idempotency_key=None) -> CanonicalEffectV1:
    ce.validate()
    if ce.effect not in EFFECT_CLASSES: raise ContractError("UNKNOWN_EFFECT", "legacy effect not in the V1 registry")
    args = "sha256:" + hashlib.sha256(E.canonical({"args": ce.args})).hexdigest()
    return CanonicalEffectV1(SCHEMA_VERSION, effect_id, ce.tenant, agent_id, ce.session_id, ce.principal, delegation_chain_digest, ce.server_id, tool_id, transport, ce.effect, ce.target_kind, ce.target_raw, args,
                             artifact_lineage_digests, purpose, policy_digest, policy_epoch, assurance_claim_id, assurance_epoch, approval_id, budget_reservation_id, deadline, idempotency_key, nonce, trace_id).validate()


def same_effect(ce: CanonicalEffect, v1: CanonicalEffectV1) -> bool:
    """True iff the V1 record describes the same tenant/server/session/principal/effect/target as the legacy object and its args digest was derived from the same args."""
    ce.validate(); v1.validate()
    return (ce.tenant, ce.server_id, ce.session_id, ce.principal, ce.effect, ce.target_kind, ce.target_raw) == (v1.tenant_id, v1.tool_server_id, v1.session_id, v1.principal_id, v1.effect_class, v1.target_kind, v1.target_canonical) \
        and v1.arguments_digest == "sha256:" + hashlib.sha256(E.canonical({"args": ce.args})).hexdigest()
