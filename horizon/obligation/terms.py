"""Typed obligation terms + strict schema (P40-01/02). Supported temporal operators are exactly those listed in OPERATORS (P40-16)."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
import hashlib, json

OPERATORS = {
    "PRE(e, a)": "action a may occur only if evidence e (valid at the time of a) was presented earlier",
    "ORDER(e1 < e2)": "evidence e2 counts only if e1 had already been presented when e2 was presented",
    "POST(a -> e within d)": "after a commits, evidence e must be presented within d seconds of the commit, else the task is frozen for guarded actions",
    "VALID(e, [from, until))": "evidence and obligation are only effective inside their validity windows (checked at action time, not only at presentation)",
    "ONCE(e)": "single-use evidence (consumed by the commit it authorised)",
}
FIELDS = ("id", "kind", "action", "evidence_kind", "roles", "bind_args", "distinct_from_requester", "consume", "order_after", "deadline_s", "claim_equals", "policy_version", "valid_from", "valid_until", "issuer")
KINDS = ("PRE", "POST")
CAP = 256


class ObligationError(ValueError):
    def __init__(self, code, msg=""): super().__init__(code + (": " + msg if msg else "")); self.code = code


@dataclass(frozen=True)
class Obligation:
    id: str; kind: str; action: str; evidence_kind: str; roles: tuple
    policy_version: str; valid_from: int; valid_until: int; issuer: str
    bind_args: bool = True; distinct_from_requester: bool = False; consume: bool = False
    order_after: tuple = (); deadline_s: int | None = None; claim_equals: tuple = ()
    def d(self):
        x = asdict(self); x["roles"] = list(self.roles); x["order_after"] = list(self.order_after); x["claim_equals"] = [list(p) for p in self.claim_equals]; return x
    def digest(self): return hashlib.sha256(json.dumps(self.d(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def parse(d: dict, *, policy_version: str, now: int) -> Obligation:
    """Strict: exact field set, types, bounds, policy-version binding, and expiry. Unknown fields are an error (nothing unsigned-but-trusted)."""
    if not isinstance(d, dict) or set(d) != set(FIELDS): raise ObligationError("MALFORMED", "fields must be exactly %s" % (FIELDS,))
    if d["kind"] not in KINDS: raise ObligationError("MALFORMED", "kind")
    for k in ("id", "action", "evidence_kind", "policy_version", "issuer"):
        if not isinstance(d[k], str) or not d[k] or len(d[k]) > CAP: raise ObligationError("MALFORMED", k)
    if not (isinstance(d["roles"], (list, tuple)) and d["roles"] and all(isinstance(r, str) and r for r in d["roles"])): raise ObligationError("MALFORMED", "roles")
    if not (isinstance(d["order_after"], (list, tuple)) and all(isinstance(r, str) for r in d["order_after"])): raise ObligationError("MALFORMED", "order_after")
    for k in ("bind_args", "distinct_from_requester", "consume"):
        if not isinstance(d[k], bool): raise ObligationError("MALFORMED", k)
    for k in ("valid_from", "valid_until"):
        if not isinstance(d[k], int) or isinstance(d[k], bool) or d[k] < 0: raise ObligationError("MALFORMED", k)
    if d["valid_until"] <= d["valid_from"]: raise ObligationError("MALFORMED", "empty validity window")
    if (d["kind"] == "POST") != (d["deadline_s"] is not None): raise ObligationError("MALFORMED", "deadline_s is required for POST and forbidden for PRE")
    if d["deadline_s"] is not None and (not isinstance(d["deadline_s"], int) or isinstance(d["deadline_s"], bool) or not 0 < d["deadline_s"] <= 86400 * 7): raise ObligationError("MALFORMED", "deadline_s")
    if d["policy_version"] != policy_version: raise ObligationError("POLICY_VERSION", "obligation bound to %s, current %s" % (d["policy_version"], policy_version))
    if now >= d["valid_until"]: raise ObligationError("EXPIRED", "obligation validity ended")
    ce = d["claim_equals"]
    if not (isinstance(ce, (list, tuple)) and all(isinstance(p, (list, tuple)) and len(p) == 2 and isinstance(p[0], str) for p in ce)): raise ObligationError("MALFORMED", "claim_equals")
    return Obligation(d["id"], d["kind"], d["action"], d["evidence_kind"], tuple(d["roles"]), d["policy_version"], d["valid_from"], d["valid_until"], d["issuer"], d["bind_args"], d["distinct_from_requester"], d["consume"],
                      tuple(d["order_after"]), d["deadline_s"], tuple((p[0], p[1]) for p in ce))
