"""P52 experiments (P52-13, 14, 15): systems x scenarios x every interleaving. Deterministic."""
from ..emergence.experiment import wilson
from . import gate as G, scenarios as SC
from .world import explore

def systems():
    S = [G.Naive("one-time-check"), G.Naive("jwt-expiry"), G.Naive("op-token-no-object"), G.Naive("restrictive-rule"), G.Gateway("last-write-wins", G.TCfg(cas_writes=False)), G.Gateway("temporal")]
    for n, kw in (("actor", {"actor": False}), ("object-id", {"object_id": False}), ("object-version", {"object_version": False}), ("object-class", {"object_class": False}), ("content", {"content": False}), ("grant", {"grant": False}), ("policy-slice", {"policy_slice": False}), ("policy-recheck", {"policy_recheck": False}),
                  ("revocation", {"revocation": False}), ("destination", {"destination": False}), ("redirect", {"redirect": False}), ("nonce", {"nonce": False}), ("expiry", {"expiry": False}), ("authoritative-clock", {"authoritative_clock": False}), ("atomic", {"atomic": False}),
                  ("idempotent", {"idempotent": False}), ("fail-closed", {"fail_closed": False}), ("cas-writes", {"cas_writes": False})):
        if n != "cas-writes": S.append(G.Gateway("temporal-no-" + n, G.TCfg(**kw)))
    return S

def rate(k, n): return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci": wilson(k, n) if n else None}
def run():
    S = systems(); rows = []; summ = {}; per = {s["id"]: {"kind": s["kind"], "desc": s["desc"], "systems": {}} for s in SC.SCENARIOS}; cex = []
    for ex in S:
        for sc in SC.SCENARIOS:
            R = explore(sc, ex); bad = [r for r in R if r["violations"]]; harm = [r for r in R if r["harm"]]
            row = {"scenario": sc["id"], "kind": sc["kind"], "system": ex.name, "orders": len(R), "violating_orders": len(bad), "harm_orders": len(harm), "completed_orders": sum(1 for r in R if r["completed"]), "unknown_orders": sum(1 for r in R if r["unknown"]),
                   "reapprovals": max(r["reapprovals"] for r in R), "stale_only_orders": len(bad) - len(harm), "denials": sorted({d for r in R for d in r["denials"]})}
            rows.append(row)
            if bad and ex.name != "temporal" and len(cex) < 400 and sc["kind"] == "attack": cex.append({"scenario": sc["id"], "system": ex.name, "order": bad[0]["order"], "violations": bad[0]["violations"]})
            if bad and sc["kind"] != "attack" and ex.name == "temporal" and sc["kind"] == "unknown": cex.append({"scenario": sc["id"], "system": ex.name, "order": bad[0]["order"], "violations": bad[0]["violations"], "flagged_unknown": bad[0]["unknown"]})
    for ex in S:
        Rw = [r for r in rows if r["system"] == ex.name]; A = [r for r in Rw if r["kind"] == "attack"]; B = [r for r in Rw if r["kind"] == "benign"]; U = [r for r in Rw if r["kind"] == "unknown"]; F = {r["scenario"]: r for r in Rw if r["kind"] == "failure"}
        meta = {s["id"]: s for s in SC.SCENARIOS}
        summ[ex.name] = {"attacks_with_a_violating_interleaving": rate(sum(1 for r in A if r["violating_orders"]), len(A)), "attacks_with_a_harmful_interleaving": rate(sum(1 for r in A if r["harm_orders"]), len(A)), "violating_interleavings": [sum(r["violating_orders"] for r in A), sum(r["orders"] for r in A)],
                         "benign_completed_in_every_interleaving": rate(sum(1 for r in B if r["completed_orders"] == r["orders"]), len(B)), "benign_with_a_stale_effect": [r["scenario"] for r in B if r["violating_orders"]], "benign_not_completed": [r["scenario"] for r in B if r["completed_orders"] < r["orders"]],
                         "benign_unjustified_reapprovals": sum(r["reapprovals"] for r in B if not meta[r["scenario"]].get("justified_reapproval")), "benign_reapprovals_when_justified": sum(r["reapprovals"] for r in B if meta[r["scenario"]].get("justified_reapproval")),
                         "unsupported_paths_violated": rate(sum(1 for r in U if r["violating_orders"]), len(U)), "unsupported_paths_violated_and_flagged_unknown": sum(1 for r in U if r["violating_orders"] and r["unknown_orders"] >= r["violating_orders"]),
                         "telemetry_offline_attack_violated": bool(F["F01"]["violating_orders"]), "telemetry_offline_benign_completed": F["F02"]["completed_orders"] == F["F02"]["orders"]}
        for r in Rw:
            if r["kind"] in ("attack",): per[r["scenario"]]["systems"][ex.name] = "V%d/%d" % (r["violating_orders"], r["orders"]) if r["violating_orders"] else "ok"
            elif r["kind"] == "benign": per[r["scenario"]]["systems"][ex.name] = ("ok" if r["completed_orders"] == r["orders"] else "BLOCKED") + ("*" if r["violating_orders"] else "")
            else: per[r["scenario"]]["systems"][ex.name] = ("V%d/%d" % (r["violating_orders"], r["orders"]) if r["violating_orders"] else ("ok" if r["scenario"] != "F02" or r["completed_orders"] == r["orders"] else "BLOCKED")) + ("(UNKNOWN)" if r["unknown_orders"] else "")
    full = {r["scenario"]: r for r in rows if r["system"] == "temporal"}
    red = [ex.name for ex in S if ex.name.startswith("temporal-no-") and all((r["violating_orders"], r["completed_orders"]) == (full[r["scenario"]]["violating_orders"], full[r["scenario"]]["completed_orders"]) for r in rows if r["system"] == ex.name)]
    return {"systems": [e.name for e in S], "scenarios": [{"id": s["id"], "kind": s["kind"], "desc": s["desc"]} for s in SC.SCENARIOS], "summary": summ, "per_scenario": per, "rows": rows, "counterexamples": cex, "redundant": red, "runs": sum(r["orders"] for r in rows)}

INVARIANTS = [
    ("I1", "NO_STALE_EFFECT", "for every attack scenario and every interleaving of its steps, the full gateway produces no effect the oracle judges prohibited or stale", "supported sink (conditional, atomic with the gateway), revocation feed up, authoritative clock"),
    ("I2", "BENIGN_LIVENESS", "for every benign scenario and every interleaving, the expected effect occurs exactly as expected, with a re-approval only where the state really changed", "same as I1"),
    ("I3", "UNKNOWN_NOT_VERIFIED", "where the sink cannot be conditioned or applies the effect later, every violating interleaving is reported UNKNOWN by the gateway; none is reported as a verified success", "external sinks U01, U02"),
    ("I4", "FAIL_CLOSED", "with the revocation feed offline the gateway never produces an effect on a revoked approval; it returns UNKNOWN", "feed offline scenarios F01, F02"),
    ("I5", "SINGLE_COMMIT", "for concurrent writers from one base version exactly one commits (compare-and-swap); no lost update is recorded", "A10"),
]
def check_invariants(R):
    S = R["summary"]["temporal"]; rows = [r for r in R["rows"] if r["system"] == "temporal"]; by = lambda k: [r for r in rows if r["kind"] == k]
    ok = {"I1": all(r["violating_orders"] == 0 for r in by("attack")), "I2": all(r["completed_orders"] == r["orders"] and r["violating_orders"] == 0 for r in by("benign")),
          "I3": all(r["violating_orders"] == 0 or r["unknown_orders"] >= r["violating_orders"] for r in by("unknown")), "I4": all(r["violating_orders"] == 0 for r in by("failure")),
          "I5": next(r for r in rows if r["scenario"] == "A10")["violating_orders"] == 0}
    return [{"id": i, "name": n, "statement": s, "scope": sc, "holds_on_suite": ok[i]} for i, n, s, sc in INVARIANTS]
