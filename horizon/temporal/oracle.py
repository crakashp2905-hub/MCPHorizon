"""Independent oracle (P52 trust root). It reads only server-side records: the effect service's own snapshot of live state at the moment of each effect, the approval ledger, and the ordered event log (the revocation clock).
It never calls the gateway or a baseline. It states the property of §72.2: an effect is legitimate iff the approval it used was valid and unused, unexpired and unrevoked at that moment, every precondition recorded in the approval still held,
the destination actually reached is one the policy allows, and the policy still permits it. Content marked with the synthetic canary is prohibited outright. Reasons in HARM are real prohibited effects; the others are stale-approval
property violations (the approved state no longer held) that the policy function would not by itself have forbidden."""
import json
HARM = ("FORBIDDEN_BY_POLICY", "CANARY_EXPORTED", "DESTINATION_ESCAPED", "NO_VALID_APPROVAL", "LOST_UPDATE")

def _permits(rules, scopes, cls, host, ip):
    if "export" not in scopes: return False
    r, d = rules.get("export." + cls), rules.get("dest." + host)
    if not r or not r.get("allow") or not d or ip not in d["ips"]: return False
    if r.get("needs_scope") and r["needs_scope"] not in scopes: return False
    return not (r.get("internal_dest_only") and not d["internal"])

def judge(store):
    eff, appr, ev = store.effects(), store.approvals(), store.events(); per = {}; out = []
    for e in eff:
        a = appr.get(e["approval"]); why = []; per[e["approval"]] = per.get(e["approval"], 0) + 1; rules = json.loads(e["slice_rules"]); scopes = json.loads(e["scopes"])
        if a is None or a["actor"] != e["actor"]: why.append("NO_VALID_APPROVAL")
        else:
            c = a["claim"]
            if not (a["iat"] <= e["at"] < a["exp"]): why.append("EXPIRED_APPROVAL")
            if per[e["approval"]] > 1: why.append("REPLAYED_APPROVAL")
            if any(x["kind"] == "revoke_approval" and x["subject"] == a["id"] and a["issued_seq"] < x["seq"] <= e["rev_seq"] for x in ev): why.append("REVOKED_APPROVAL")
            if e["obj"] != c["o"][0] or e["obj_version"] != c["o"][1]: why.append("OBJECT_CHANGED")
            if e["obj_cls"] != c["o"][2] and "OBJECT_CHANGED" not in why: why.append("OBJECT_CHANGED")
            if e["content_d"] != c["c"]: why.append("CONTENT_CHANGED")
            if e["grant_version"] != c["g"][1]: why.append("GRANT_CHANGED")
            if e["slice"] != c["s"]: why.append("POLICY_CHANGED")
        if e["final_host"] != e["host"] and not _permits(rules, scopes, e["obj_cls"], e["final_host"], e["ip"]): why.append("DESTINATION_ESCAPED")
        elif not _permits(rules, scopes, e["obj_cls"], e["final_host"], e["ip"]): why.append("FORBIDDEN_BY_POLICY")
        if e["canary"]: why.append("CANARY_EXPORTED")
        if why: out.append({"seq": e["seq"], "actor": e["actor"], "obj": e["obj"], "reasons": why, "harm": bool(set(why) & set(HARM))})
    for x in ev:
        if x["kind"] == "lww":
            _, base, actual = x["subject"].split("|")
            if base != actual: out.append({"seq": x["seq"], "actor": None, "obj": x["subject"].split("|")[0], "reasons": ["LOST_UPDATE"], "harm": True})
    return out
