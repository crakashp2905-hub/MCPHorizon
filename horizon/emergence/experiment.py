"""Corpus labeling, baselines comparison and recall/precision-versus-budget curves (P39-13/14/15). Ground truth comes from the receiver journal only."""
from __future__ import annotations
import itertools, json, math, random
from .summaries import PUB, library_summaries, digest
from .model import Endpoints, Step, search, refine, oracle_blind, apply_transform, ALL_TARGETS, direct_allowed
from . import baselines as B
from .oracle import Oracle, free_ports

TRANSFORMS = ("b64", "hash", "redact", "weak_sanitize")
SINKS = (("get", "A/ingest"), ("get", "A/redir->B"), ("get", "C/redir->B"), ("get", "C/x"), ("post", "A/ingest"), ("post", "C/x"))
BUDGETS = (5, 10, 20, 40, 80, 160, 320, 640, 1280)


def wilson(k, n, z=1.959964):
    if n == 0: return [None, None]
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)); return [round(max(0.0, (c - h) / d), 4), round(min(1.0, (c + h) / d), 4)]


def chains(sums):
    """All minimal source->transform*->sink chains (<=2 transforms), with abstract taints filled in from `sums`."""
    out = []
    for src in ("read_secret", "read_note"):
        for k in range(3):
            for ts in itertools.product(TRANSFORMS, repeat=k):
                steps, t = [Step(src, (), "", sums[src].out_taint)], sums[src].out_taint
                for j, tr in enumerate(ts):
                    t = apply_transform(sums[tr], t); steps.append(Step(tr, (j,), "", t))
                for op, tg in SINKS: out.append(steps + [Step(op, (len(steps) - 1,), tg, PUB, t)])
    return out


def name(steps): return "/".join(s.op + (":" + s.target if s.target else "") for s in steps)


def label_corpus(eps, sums, orc):
    rows = []
    for c in chains(sums):
        r = orc.execute(c)
        rows.append({"chain": name(c), "ops": sorted({s.op for s in c if s.op not in ("get", "post")}), "sink": c[-1].op, "target": c[-1].target, "leak": r["leak_to_B"], "blind": oracle_blind(c), "journal_sha256": r["journal_sha256"], "_steps": c})
    return rows


def confusion(rows, flag):
    tp = fp = fn = tn = unk = unk_leak = 0
    for r in rows:
        if r["blind"]: continue
        v = flag(r["_steps"])
        if v == "UNKNOWN": unk += 1; unk_leak += r["leak"]; continue
        a = bool(v) and v != "SAFE"
        if a and r["leak"]: tp += 1
        elif a and not r["leak"]: fp += 1
        elif not a and r["leak"]: fn += 1
        else: tn += 1
    P = tp + fn; N = fp + tn
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "unknown": unk, "unknown_that_leaked": unk_leak, "recall": round(tp / P, 4) if P else None, "recall_ci": wilson(tp, P), "fpr": round(fp / N, 4) if N else None, "fpr_ci": wilson(fp, N),
            "precision": round(tp / (tp + fp), 4) if tp + fp else None}


def compare_baselines(rows, eps, sums):
    return {"D0": confusion(rows, lambda s: B.d0(s)), "D3": confusion(rows, lambda s: B.d3(s)), "direct_taint": confusion(rows, lambda s: B.direct_taint(s, eps)),
            "emergence": confusion(rows, lambda s: B.emergence(s, eps, sums)),
            "emergence_refined": confusion(rows, lambda s: B.emergence(s, eps, refine(sums, "weak_sanitize", digest([r["journal_sha256"] for r in rows if "weak_sanitize" in r["ops"]][:1]))))}


def make_worlds(seed=1337, n=40):
    rng = random.Random(seed); ws = []
    for i in range(n):
        ops = {"read_note"} | ({"read_secret"} if rng.random() < .9 else set())
        for t in TRANSFORMS:
            if rng.random() < .6: ops.add(t)
        for s in ("get", "post"):
            if rng.random() < .8 if s == "get" else rng.random() < .7: ops.add(s)
        tg = tuple(t for t in ("A/ingest", "A/redir->B", "C/redir->B", "C/x") if rng.random() < .7)
        ws.append({"id": "W%02d" % i, "ops": sorted(ops), "targets": tg})
    return ws


def world_truth(w, rows):
    """positive iff some oracle-labelled leaking (non-blind) corpus chain lies inside the world (ops subset, target available, direct-policy allowed)."""
    return any(r["leak"] and not r["blind"] and set(r["ops"]) | {"read_secret", r["sink"]} <= set(w["ops"]) and r["target"] in w["targets"] and direct_allowed(r["target"]) and r["chain"].startswith("read_secret") for r in rows)


def run_world(w, eps, sums_full, orc, budget, *, seed=0, guided=True, refined=None):
    sums = {k: v for k, v in (refined or sums_full).items() if k in w["ops"]}
    r = search(sums, eps, budget=budget, seed=seed, guided=guided, targets=w["targets"])
    ver = dis = blind = 0
    for c in r["candidates"]:
        if oracle_blind(c.steps): blind += 1; continue
        if orc.execute(c.steps)["leak_to_B"]: ver += 1
        else: dis += 1
    return {"verified": ver, "disproved": dis, "blind": blind, "unknown": len(r["unknowns"]), "evaluated": r["evaluated"]}


def curves(eps, sums, orc, rows, worlds=None, seeds=(0, 1, 2, 3, 4)):
    worlds = worlds or make_worlds(); truth = {w["id"]: world_truth(w, rows) for w in worlds}; pos = [w for w in worlds if truth[w["id"]]]
    refined = refine(sums, "weak_sanitize", digest([r["journal_sha256"] for r in rows if "weak_sanitize" in r["ops"]][:1]))
    only_c = [w["id"] for w in pos if not any(r["leak"] and not r["blind"] and set(r["ops"]) | {"read_secret", r["sink"]} <= set(w["ops"]) and r["target"] in w["targets"] and r["target"].startswith("A/") and r["chain"].startswith("read_secret") for r in rows)]
    res = {"positive_worlds_only_via_unmodeled_C": only_c, "worlds": len(worlds), "positive_worlds": len(pos), "negative_worlds": len(worlds) - len(pos), "budgets": list(BUDGETS), "curves": {}}
    for mode, kw in (("guided", {"guided": True}), ("unguided", {"guided": False}), ("guided+refined", {"guided": True, "refined": refined})):
        pts = []
        for b in BUDGETS:
            found = 0; V = D = 0; falsepos_worlds = 0
            for w in worlds:
                sd = seeds if not kw.get("guided") else (0,)
                hits = []
                for sdv in sd:
                    r = run_world(w, eps, sums, orc, b, seed=sdv, **kw); hits.append(r)
                    V += r["verified"]; D += r["disproved"]
                if truth[w["id"]] and sum(h["verified"] > 0 for h in hits) / len(hits) >= .5: found += 1
                if not truth[w["id"]] and any(h["verified"] > 0 for h in hits): falsepos_worlds += 1       # would mean the oracle contradicts world_truth
            pts.append({"budget": b, "recall_worlds": [found, len(pos)], "recall": round(found / len(pos), 4), "recall_ci": wilson(found, len(pos)), "verified_candidates": V, "disproved_candidates": D,
                        "verified_precision": round(V / (V + D), 4) if V + D else None, "verified_precision_ci": wilson(V, V + D), "oracle_contradictions": falsepos_worlds})
        res["curves"][mode] = pts
    return res
