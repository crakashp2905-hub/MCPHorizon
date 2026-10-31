"""Pre-effect policy evaluation with deny precedence and explicit defaults (P2-08, P2-09, P2-18).
Reference ("oracle") implementation; the Rust core must agree exactly on the differential corpus.

Context (trusted, supplied by the service — never by the agent):
  identity_valid, mapping_complete, interceptable, protected_effect : bool
  effect (action str), sink_zone, purpose : str | None
  input_label : effective (joined) confidentiality of inputs
  lineage_complete, authorized_flow : bool
  approval : None | {"valid": bool}  (exact one-shot human approval already validated against the request)
Precedence (spec §7.4): 1 invalid identity → DENY; 2 uninterceptable known-risky effect → DENY; 3 hard DENY rule → DENY;
4 incomplete mapping → DENY (protected) / UNKNOWN (not protected); 5 REVIEW rule (satisfied only by a valid approval, which
never overrides 1-3); 6 ALLOW rule; 7 default.
"""
from __future__ import annotations
from .labels import C

WHEN_KEYS = {"effect", "sink_zone", "input_label_at_least", "maximum_input_label", "authorized_flow",
             "lineage_complete", "purpose", "unknown_effect_or_destination"}


def rule_matches(when: dict, ctx: dict) -> bool:
    if not when: return False                                   # empty condition never matches (policy validation rejects it too)
    if set(when) - WHEN_KEYS: return False
    for k, want in when.items():
        if k == "effect" and ctx["effect"] != want: return False
        if k == "sink_zone" and ctx.get("sink_zone") != want: return False
        if k == "purpose" and ctx.get("purpose") != want: return False
        if k == "input_label_at_least" and C[ctx["input_label"]] < C[want]: return False
        if k == "maximum_input_label" and C[ctx["input_label"]] > C[want]: return False
        if k == "authorized_flow" and ctx["authorized_flow"] is not want: return False
        if k == "lineage_complete" and ctx["lineage_complete"] is not want: return False
        if k == "unknown_effect_or_destination" and (not ctx["mapping_complete"]) is not want: return False
    return True


def decide(policy: dict, ctx: dict) -> dict:
    rules = sorted(policy["rules"], key=lambda r: r["id"])
    d = policy["defaults"]
    def out(v, codes, rid=None): return {"verdict": v, "reason_codes": codes, "rule": rid}
    if not ctx["identity_valid"]: return out("DENY", ["INVALID_IDENTITY"])
    if not ctx["interceptable"]: return out("DENY", ["UNINTERCEPTABLE_EFFECT"])
    hit = {"DENY": [], "REVIEW": [], "ALLOW": [], "QUARANTINE": [], "UNKNOWN": []}
    for r in rules:
        if rule_matches(r["when"], ctx): hit[r["decision"]].append(r["id"])
    if hit["DENY"]: return out("DENY", ["HARD_POLICY_PROHIBITION"], hit["DENY"][0])
    if not ctx["mapping_complete"]:
        if ctx["protected_effect"]: return out("DENY", ["UNKNOWN_MAPPING_PROTECTED"])
        return out("UNKNOWN", ["UNKNOWN_MAPPING"])
    if hit["REVIEW"] and not (ctx.get("approval") or {}).get("valid"): return out("REVIEW", ["REVIEW_REQUIRED"], hit["REVIEW"][0])
    if hit["ALLOW"]:
        if not ctx["lineage_complete"] and ctx["protected_effect"]: return out("REVIEW", ["INCOMPLETE_LINEAGE"], hit["ALLOW"][0])
        return out("ALLOW", ["EXPLICIT_ALLOW"] + (["APPROVED_REVIEW"] if hit["REVIEW"] else []), hit["ALLOW"][0])
    if hit["QUARANTINE"]: return out("QUARANTINE", ["POLICY_QUARANTINE"], hit["QUARANTINE"][0])
    if hit["UNKNOWN"]: return out("UNKNOWN", ["POLICY_UNKNOWN"], hit["UNKNOWN"][0])
    if ctx["protected_effect"]: return out(d["protected_effect"], ["DEFAULT_PROTECTED_EFFECT"])
    return out(d["inspection_only"], ["DEFAULT_INSPECTION_ONLY"])
