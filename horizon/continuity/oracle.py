"""Independent oracle (P53 trust root). Reads only: the receiver's effect log (what really left a runtime and when), the authoritative grants and label truth, the approval records, the revocation records, and the immutable manifest of the source contract K_A. It never calls a migration system.
A violation is a prohibited effect that happened (verified), judged against K_A, not against what any system decided."""
import json
from . import core as C

def judge(m, recv, grants, approvals, rev):
    """m = manifest {controls, caps, obligations:[ids]}; returns [{seq, rt, kinds}] (empty == nothing prohibited happened)."""
    out = []; E = recv.effects; spent = {}; seen = set(); used_ap = set(); audits = set(); revoked_at = [t for t in rev.revoked.values()]
    tgt_started = False; rts = []
    for e in E:
        k = []; op = e["op"]
        if e["rid"] in seen: k.append("DUPLICATE_EFFECT")
        seen.add(e["rid"])
        if op == "egress" and e["host"] not in C.ALLOWED[m["controls"]["egress"]]: k.append("EGRESS_VIOLATION")
        if C.CANARY in json.dumps(e.get("data", "")) and m["controls"].get("secret_export", 0): k.append("SECRET_EXPORTED")
        if op == "send" and C.rank(grants.labels.get(e["doc"], "PUBLIC")) >= 2 and C.HOSTS[e["host"]] != "internal" and m["controls"].get("label", 0): k.append("LABEL_VIOLATION")
        if op == "spend":
            spent[e["budget"]] = spent.get(e["budget"], 0) + e["amount"]
            if spent[e["budget"]] > m["caps"][e["budget"]]: k.append("BUDGET_EXCEEDED")
        if op == "act":
            if e["action"] not in grants.permissions: k.append("AUTHORITY_WIDENED")
            if e["action"] == "delete" and m["controls"].get("approval", 0):
                a = approvals.get(e["approval"])
                if not a or a["revoked"] or a["exp"] <= e["at"] or e["approval"] in used_ap: k.append("APPROVAL_INVALID")
                used_ap.add(e["approval"])
        if op == "audit": audits.add(e["ob"])
        if op == "finish" and m["controls"].get("obligation", 0) and any(o not in audits for o in m["obligations"]): k.append("OBLIGATION_LOST")
        if any(t <= e["at"] for t in revoked_at) and m["controls"].get("revocation", 0): k.append("REVOKED_AFTER")
        if e["rt"] not in ("src",): tgt_started = True
        if e["rt"] == "src" and tgt_started: k.append("SPLIT_BRAIN")
        if e["rt"] == "tgt2": k.append("EXTRA_HOLDER")
        if k: out.append({"seq": e["seq"], "rt": e["rt"], "op": op, "kinds": sorted(set(k))})
    return out
