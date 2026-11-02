"""P83-12: work classifications with authorization profiles; P83-13 coverage report for high-risk tasks."""
PROFILES = {
 "CODE":        {"network": "none", "secrets": "none", "live_effect": False, "external_party": False, "approval": "none", "evidence": ["tests", "diff"]},
 "EXPERIMENT":  {"network": "none", "secrets": "none", "live_effect": False, "external_party": False, "approval": "none", "evidence": ["preregistration", "raw_results", "seeds"]},
 "EXTERNAL":    {"network": "none", "secrets": "none", "live_effect": False, "external_party": True, "approval": "external_signature", "evidence": ["third_party_artifact"]},
 "DECISION":    {"network": "none", "secrets": "none", "live_effect": False, "external_party": False, "approval": "human_signature", "evidence": ["decision_record"]},
 "LIVE_EFFECT": {"network": "allowlist", "secrets": "scoped", "live_effect": True, "external_party": False, "approval": "human_signature_per_effect", "evidence": ["effect_log", "rollback_plan"]},
}


def authorize(cls, req):
    """req: dict of requested capabilities. Returns (ok, reasons). Unknown class or capability beyond profile -> deny."""
    p = PROFILES.get(cls)
    if p is None: return False, ["unknown work class"]
    why = []
    if req.get("network", "none") != "none" and p["network"] == "none": why.append("network not allowed for " + cls)
    if req.get("secrets", "none") != "none" and p["secrets"] == "none": why.append("secrets not allowed for " + cls)
    if req.get("live_effect") and not p["live_effect"]: why.append("live effect not allowed for " + cls)
    if p["approval"] != "none" and not req.get("approval"): why.append("approval '%s' required" % p["approval"])
    elif p["approval"] != "none" and req.get("approval") != p["approval"]: why.append("wrong approval kind")
    return (not why), why


def high_risk_coverage(rows, acceptance):
    """P83-13: which high-risk tasks have exact commands AND a named effect oracle. Reports gaps; never invents oracles."""
    rep = {"high_risk": 0, "with_commands": 0, "with_named_oracle": 0, "gaps": []}
    for r in rows:
        if r["risk_tier"] != "high": continue
        rep["high_risk"] += 1; a = acceptance.get(r["task_id"])
        cm = bool(a and a.get("cmds")); orc = bool(a and a.get("oracle"))
        rep["with_commands"] += cm; rep["with_named_oracle"] += orc
        if not (cm and orc): rep["gaps"].append(r["task_id"])
    return rep
