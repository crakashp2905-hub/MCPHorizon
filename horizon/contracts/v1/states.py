"""Normative state vocabularies (masterplan 2.2). CANDIDATE, stdlib only, imports nothing from the repo.
Rules enforced here, not left to callers: states are distinct types (no implicit coercion between them), ALLOW_CANDIDATE never authorises a commit, UNKNOWN is never read as COMMITTED or BLOCKED,
and effect-state changes follow ONE transition table; anything else is refused."""
from __future__ import annotations
from enum import Enum


class Decision(str, Enum):
    ALLOW_CANDIDATE = "ALLOW_CANDIDATE"; DENY = "DENY"; REQUIRE_APPROVAL = "REQUIRE_APPROVAL"; UNKNOWN = "UNKNOWN"; UNSUPPORTED = "UNSUPPORTED"


class EffectState(str, Enum):
    REQUESTED = "REQUESTED"; AUTHORIZED = "AUTHORIZED"; STARTED = "STARTED"; COMMITTED = "COMMITTED"; BLOCKED = "BLOCKED"; UNKNOWN = "UNKNOWN"
    RECONCILED_COMMITTED = "RECONCILED_COMMITTED"; RECONCILED_BLOCKED = "RECONCILED_BLOCKED"


class Coverage(str, Enum):
    OBSERVED = "OBSERVED"; NOT_OBSERVED_WITH_TRUSTED_COMPLETENESS = "NOT_OBSERVED_WITH_TRUSTED_COMPLETENESS"; UNOBSERVABLE = "UNOBSERVABLE"; OUT_OF_SCOPE = "OUT_OF_SCOPE"


class Assurance(str, Enum):
    CANDIDATE = "CANDIDATE"; VALID_FOR_SCOPE = "VALID_FOR_SCOPE"; SUSPENDED = "SUSPENDED"; REVOKED = "REVOKED"; EXPIRED = "EXPIRED"; UNIDENTIFIABLE = "UNIDENTIFIABLE"


class ModuleStatus(str, Enum):
    UNMAPPED = "UNMAPPED"; CANDIDATE = "CANDIDATE"; INTEGRATED = "INTEGRATED"; ADVERSARIAL_TESTED = "ADVERSARIAL_TESTED"; INDEPENDENTLY_VERIFIED = "INDEPENDENTLY_VERIFIED"; HARDENED_FOR_SCOPE = "HARDENED_FOR_SCOPE"; BLOCKED = "BLOCKED"


S = EffectState
TRANSITIONS = {
    S.REQUESTED: {S.AUTHORIZED, S.BLOCKED},
    S.AUTHORIZED: {S.STARTED, S.BLOCKED},
    S.STARTED: {S.COMMITTED, S.BLOCKED, S.UNKNOWN},
    S.UNKNOWN: {S.RECONCILED_COMMITTED, S.RECONCILED_BLOCKED},
    S.COMMITTED: set(), S.BLOCKED: set(), S.RECONCILED_COMMITTED: set(), S.RECONCILED_BLOCKED: set(),
}
TERMINAL = frozenset(s for s, nxt in TRANSITIONS.items() if not nxt)
EFFECT_HAPPENED = frozenset({S.COMMITTED, S.RECONCILED_COMMITTED})
EFFECT_DID_NOT_HAPPEN = frozenset({S.BLOCKED, S.RECONCILED_BLOCKED})


class StateError(ValueError):
    pass


def transition(cur: EffectState, nxt: EffectState) -> EffectState:
    """Return `nxt` if the move is allowed, else raise. Never silently coerces a string: both arguments must already be EffectState."""
    if not isinstance(cur, EffectState) or not isinstance(nxt, EffectState): raise StateError("states must be EffectState members")
    if nxt not in TRANSITIONS[cur]: raise StateError(f"illegal transition {cur.value} -> {nxt.value}")
    return nxt


def commit_authorising(d: Decision) -> bool:
    """No decision value authorises a commit by itself: ALLOW_CANDIDATE only means 'may proceed to permit issuance and commit-time checks'."""
    if not isinstance(d, Decision): raise StateError("not a Decision")
    return False


def may_retry(state: EffectState) -> bool:
    """An ambiguous effect (UNKNOWN) is never retried automatically; terminal states need no retry; only a not-yet-started effect may be (re)attempted."""
    if not isinstance(state, EffectState): raise StateError("not an EffectState")
    return state in (S.REQUESTED, S.AUTHORIZED)


def outcome(state: EffectState) -> str:
    """Three-valued: 'HAPPENED' | 'DID_NOT_HAPPEN' | 'UNDETERMINED'. UNKNOWN (and any in-flight state) is UNDETERMINED, never mapped to either."""
    if not isinstance(state, EffectState): raise StateError("not an EffectState")
    return "HAPPENED" if state in EFFECT_HAPPENED else "DID_NOT_HAPPEN" if state in EFFECT_DID_NOT_HAPPEN else "UNDETERMINED"
