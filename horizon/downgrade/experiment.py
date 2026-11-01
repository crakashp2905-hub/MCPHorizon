"""P46 experiments (P46-09, 10, 12, 13, 14): paired attack/benign scenarios x systems x reps against live loopback endpoints, judged by the independent journal oracle."""
import statistics
from ..emergence.experiment import wilson
from . import scenarios as SC, gateway as GW, engine as EG


def rate(k, n): return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci": wilson(k, n) if n else None}
def pct(xs, p): xs = sorted(xs); return round(xs[min(len(xs) - 1, int(p * len(xs)))], 1) if xs else None


def summarize(rows):
    out = {}
    for sy in SC.SYSTEMS:
        at = [r for r in rows if r["system"] == sy and r["kind"] == "attack"]; bn = [r for r in rows if r["system"] == sy and r["kind"] == "benign"]; rec = [r["recovery_ms"] for r in rows if r["system"] == sy and r["recovery_ms"] is not None and r["completed"]]
        out[sy] = {"attack_runs_with_unauthorized_effect": rate(sum(r["violated"] for r in at), len(at)), "attack_runs_completed_safely": rate(sum(1 for r in at if r["completed"] and not r["violated"]), len(at)), "attack_runs_stopped_without_completion": rate(sum(1 for r in at if not r["completed"] and not r["violated"]), len(at)),
                   "benign_completed": rate(sum(r["completed"] for r in bn), len(bn)), "benign_false_blocks": rate(sum(1 for r in bn if not r["completed"]), len(bn)), "benign_with_violation": rate(sum(r["violated"] for r in bn), len(bn)),
                   "median_recovery_ms": pct(rec, 0.5), "p95_recovery_ms": pct(rec, 0.95), "review_requested": sum(1 for r in rows if r["system"] == sy and r["review"]), "unknown_dims_seen": sum(r["unknown_dims_seen"] for r in rows if r["system"] == sy)}
    return out


def per_scenario(rows):
    out = {}
    for s in SC.SCENARIOS:
        d = {"kind": s[1], "note": s[3], "systems": {}}
        for sy in SC.SYSTEMS:
            rs = [r for r in rows if r["id"] == s[0] and r["system"] == sy]
            d["systems"][sy] = ("V%d" % sum(r["violated"] for r in rs) if s[1] == "attack" else "%d/%d" % (sum(r["completed"] and not r["violated"] for r in rs), len(rs))) + (" (%s)" % ",".join(sorted({str(r["used"]) for r in rs})) if rs and s[1] == "attack" else "")
        out[s[0]] = d
    return out


def cache_test(env):
    """P46-12: a cached verdict must not outlive a profile change, a revocation or a policy-version change. Each trigger is tested on a warm cache; the ablation shows which triggers it would miss."""
    out = {}
    for label, cfgname in (("guard", "guard"), ("no-cache-invalidation", "guard-no-cache-invalidation")):
        res = {}
        for trigger in ("profile_update", "revocation", "policy_version"):
            reg = env.registry(["primary_eu", "drift_eu", "peer_eu"]); sysm = env.system(cfgname, reg); task = "t-cache-%s-%s" % (label, trigger); ctx = sysm.e.bind(task, SC.FD, SC.NONWAIVABLE, env.floor_token(task, SC.FD), "agent-1")
            ep = "peer_eu" if trigger == "revocation" else "drift_eu"; c = SC.cand("c", ep, ("read",)); first = sysm.e.evaluate(ctx, c).outcome; h0 = sysm.e.cache.hits; sysm.e.evaluate(ctx, c); warm = sysm.e.cache.hits > h0
            if trigger == "profile_update": env.publish(reg, "drift_eu", SC.mk(transport="tls1.2"), False, 2)
            elif trigger == "revocation": reg.revoke("peer_eu", "key compromise")
            else: sysm.e.pv = "pol-2"
            after = sysm.e.evaluate(ctx, c).outcome
            # for the policy trigger the floor itself is unchanged and the profile is still good: the verdict stays ADMIT but must have been recomputed (no stale hit)
            res[trigger] = {"before": first, "warm_cache": warm, "after": after, "stale_admit": after == "ADMIT" and trigger != "policy_version", "recomputed": sysm.e.cache.hits == h0 + (1 if warm else 0) if trigger != "policy_version" else sysm.e.cache.hits == h0 + 1}
        out[label] = res
    return out


def parity(env):
    """P46-07: the same scenarios through utcp, mcp and codemode adapters give the same admitted endpoint and the same oracle verdict."""
    rows = []
    for sid, fb in (("A04", [SC.cand("tls12", "tls12_eu", ("read",)), SC.cand("peer", "peer_eu", ("read",))]), ("A03", [SC.cand("noaudit", "noaudit_eu", ("read",)), SC.cand("peer", "peer_eu", ("read",))]), ("A01", [SC.cand("mock", "mock_unaudited", ("read", "admin"))]), ("B01", [SC.cand("peer", "peer_eu", ("read",))])):
        for sysname in ("guard", "fixed-order"):
            for ad in ("utcp", "mcp", "codemode"):
                run = SC.Run(env, sysname, 0, sid); run.prefix = "par-%s-%s-%s" % (sid, sysname, ad)
                if ad == "codemode":
                    reg = env.registry(["primary_eu", "tls12_eu", "noaudit_eu", "mock_unaudited", "peer_eu"]); sysm = env.system(sysname, reg); task = "t-" + run.prefix; tok = env.floor_token(task, SC.FD)
                    ctx = sysm.e.bind(task, SC.FD, SC.NONWAIVABLE, tok, "agent-1") if isinstance(sysm, GW.Guard) else EG.Ctx(task, dict(SC.FD), frozenset(SC.NONWAIVABLE), tok, "agent-1", ("agent-1",), dict(SC.FD))
                    run.fail("primary_eu"); gw = GW.Gateway(env.world, sysm, "utcp"); order = ["primary"] + [c.id for c in fb]
                    src = "for cid in %r:\n    try:\n        call(cid)\n        break\n    except Timeout:\n        pass\n" % (order,)
                    res = gw.run_codemode(ctx, src, [SC.cand("primary", "primary_eu")] + fb, SC.PAYLOAD, "internal", run.prefix, "primary_eu")
                else: res = SC.scenario_fail_over(env, run, SC.FD, fb, adapter=ad, prof=["primary_eu", "tls12_eu", "noaudit_eu", "mock_unaudited", "peer_eu"])
                ob = SC.observe(env, run.prefix, SC.FD); rows.append({"id": sid, "system": sysname, "adapter": ad, "used": res.get("used"), "completed": bool(res.get("completed")), "violated": bool(ob["violations"])})
    keyed = {}
    for r in rows: keyed.setdefault((r["id"], r["system"]), set()).add((r["used"], r["completed"], r["violated"]))
    return {"rows": rows, "identical_across_adapters": all(len(v) == 1 for v in keyed.values()), "cells": len(keyed)}


def run(reps=SC.REPS):
    env = SC.Env()
    try:
        rows = SC.run_all(env, reps=reps); res = {"rows": rows, "summary": summarize(rows), "per_scenario": per_scenario(rows), "cache": cache_test(env), "parity": parity(env), "reps": reps, "runs": len(rows), "systems": list(SC.SYSTEMS), "scenarios": [{"id": s[0], "kind": s[1], "note": s[3]} for s in SC.SCENARIOS]}
    finally: env.close()
    for r in res["rows"]: r.pop("ms", None); r["recovery_ms"] = None if r["recovery_ms"] is None else round(r["recovery_ms"])
    return res
