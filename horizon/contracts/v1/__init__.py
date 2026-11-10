"""horizon.contracts.v1: normative shared contracts (masterplan PR-01). CANDIDATE. No live module imports this yet; adapters in `legacy.py` map the existing CanonicalEffect to it."""
from .effect import CanonicalEffectV1, ContractError, EFFECT_CLASSES, EMPTY_CHAIN, FIELD_NAMES, MUTATING, SCHEMA_VERSION
from .errors import ERRORS, ErrorInfo, lookup
from .messages import ArtifactRef, DecisionV1, DelegatedPrincipal, EffectReceiptV1, EffectRequestV1, PermitV1, TrustedIdentity, permit_covers
from .states import Assurance, Coverage, Decision, EffectState, ModuleStatus, StateError, commit_authorising, may_retry, outcome, transition
