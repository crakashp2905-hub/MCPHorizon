"""Role interfaces (masterplan 2.3). Specification only: nothing implements them yet. CANDIDATE, stdlib only.
Role isolation is a RUNTIME property (OS identity, file and RPC access); the import list below is only the static half and is checked by tests, it does not prove separation."""
from __future__ import annotations
from typing import Protocol
from .effect import CanonicalEffectV1
from .messages import DecisionV1, EffectReceiptV1, EffectRequestV1, PermitV1

# Roles that must not import, at all, any of these repo areas (checked statically by tests/blueprint/test_contracts_v1.py).
UNTRUSTED_ROLE_FORBIDDEN_IMPORT_PREFIXES = ("horizon.authz.keys", "horizon.effects.ledger", "horizon.effects.filesink", "horizon.effects.netbroker", "horizon.effects.procbroker", "horizon.effects.sinkproc",
                                            "horizon.assurance.durable", "horizon.runtime.sandbox")


class TrustedEffectKernel(Protocol):
    def evaluate(self, request: EffectRequestV1) -> DecisionV1: ...
    def issue_permit(self, decision: DecisionV1, approved_context: object) -> PermitV1: ...
    def commit(self, permit: PermitV1, exact_effect: CanonicalEffectV1) -> EffectReceiptV1: ...


class ProtectedSink(Protocol):
    def fence_and_observe(self, effect_id: str) -> object: ...
    def dispatch(self, permit: PermitV1, request: EffectRequestV1) -> object: ...


class Analyzer(Protocol):
    def analyze(self, metadata: object) -> object: ...


class BoundaryProposer(Protocol):
    def propose(self, observations: object) -> object: ...


class IndependentPlanChecker(Protocol):
    def check(self, proposal: object, supported_controls: object) -> object: ...
