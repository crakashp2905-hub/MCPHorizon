"""Versioned error / UNKNOWN table (masterplan M0-05). CANDIDATE, stdlib only.
Every code the existing authz, effects and broker modules emit is listed with: category, whether a caller may retry, and what it implies about the effect.
`lookup` of a code NOT in the table returns a fail-closed entry (never retryable, never read as success). Table is data; `tests/blueprint/test_contracts_v1.py` checks it against the codes in the source."""
from __future__ import annotations
from dataclasses import dataclass

VERSION = "1"
# effect: DID_NOT_HAPPEN (refused before dispatch) | UNDETERMINED (may or may not have happened) | HAPPENED | NA (no effect involved)


@dataclass(frozen=True)
class ErrorInfo:
    code: str; category: str; retryable: bool; effect: str; note: str = ""


def _rows():
    d = lambda c, cat, note="": ErrorInfo(c, cat, False, "DID_NOT_HAPPEN", note)
    for c in ("MALFORMED", "VERSION", "UNKNOWN_EFFECT", "BAD_BINDING", "BAD_GRADE", "BAD_REASON", "BAD_HOST", "BAD_URL", "BAD_METHOD", "BAD_HEADER", "BAD_ARGV", "USERINFO_NOT_ALLOWED",
              "REQUEST_TOO_LARGE", "DESCRIBE_FAILED", "TARGET_REJECTED", "BAD_OP", "ERROR"): yield d(c, "INVALID_INPUT")
    for c in ("BAD_SIGNATURE", "BAD_ISSUER", "BAD_AUDIENCE", "WRONG_ISSUER_ROLE", "CONTRACT_MISMATCH", "PEER_NOT_GATEWAY", "ISSUER_DOWN"): yield d(c, "AUTHENTICATION")
    for c in ("ARGS_MISMATCH", "EFFECT_MISMATCH", "PRINCIPAL_MISMATCH", "TARGET_MISMATCH", "TENANT_MISMATCH", "DATA_NOT_BOUND_TO_PERMIT"): yield d(c, "BINDING_MISMATCH", "permit does not cover this exact effect")
    for c in ("EXPIRED", "NOT_YET_VALID", "TTL_TOO_LONG", "STALE_POLICY", "DEADLINE_EXCEEDED"): yield d(c, "TEMPORAL")
    for c in ("REPLAY", "NONCE_REUSE", "NONCE_STORE_FULL", "FENCED", "ALREADY_WRITTEN"): yield d(c, "REPLAY_OR_FENCE", "single-use / fenced: do not retry with the same permit")
    for c in ("POLICY_DENIED", "OUTSIDE_ROOT", "OUTSIDE_ALLOWED_TARGETS", "PRIVATE_ADDRESS", "DNS_NO_ANSWER", "DNS_BAD_ADDRESS", "PROGRAM_NOT_ALLOWED", "PROGRAM_NOT_ABSOLUTE", "ARG_NOT_ALLOWED",
              "CWD_NOT_ALLOWED", "CWD_OUTSIDE_ROOT", "UNSUPPORTED_EFFECT", "ASSURANCE_DENIED", "HTTP_REJECTED", "TLS_VERIFY_FAILED", "IS_DIRECTORY", "V1_BINDING_MISMATCH", "IDENTITY_NOT_SEPARATED"): yield d(c, "POLICY_FINAL", "final denial: repeating the call will not succeed")
    # PR-04 corrections to the PR-01 table (found by wiring the kernel): REDIRECT_REFUSED is raised AFTER the request completed and a response arrived; TLS_ERROR can occur mid-stream; LEDGER_MOVED_ON means the sink effect HAPPENED while the ledger was already UNKNOWN. All three are UNDETERMINED, not DID_NOT_HAPPEN.
    for c in ("LOG_TAMPERED", "JOURNAL_TAMPERED", "RESTORE_NEEDS_EVIDENCE"): yield ErrorInfo(c, "INTEGRITY", False, "NA", "fail closed; needs operator evidence")
    for c in ("RESPONSE_TOO_LARGE", "OUTPUT_TOO_LARGE", "TIMEOUT", "CONNECT_FAILED", "UPSTREAM_FAILED", "CLIENT_ERROR", "REDIRECT_REFUSED", "TLS_ERROR", "LEDGER_MOVED_ON"):
        yield ErrorInfo(c, "AMBIGUOUS_OR_TRANSPORT", False, "UNDETERMINED", "the effect may have happened; reconcile with receiver evidence, never blind-retry")


ERRORS = {e.code: e for e in _rows()}
UNKNOWN_CODE = ErrorInfo("UNKNOWN_ERROR_CODE", "UNKNOWN", False, "UNDETERMINED", "unlisted code: treated as a denial and as an undetermined effect")


def lookup(code) -> ErrorInfo:
    return ERRORS.get(code, UNKNOWN_CODE) if isinstance(code, str) else UNKNOWN_CODE
