"""Small, dependency-free statistics for P9 (P9-20). Paired exact McNemar, Wilson CIs, template-cluster bootstrap, Holm correction, Cohen's h."""
from __future__ import annotations
import math, random
from math import comb


def wilson(k: int, n: int, z: float = 1.959964):
    if n == 0: return None
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact p for discordant counts b (A only) and c (B only)."""
    n = b + c
    if n == 0: return 1.0
    return min(1.0, 2 * sum(comb(n, i) for i in range(0, min(b, c) + 1)) / 2 ** n)


def holm(ps: list[float]) -> list[float]:
    order = sorted(range(len(ps)), key=lambda i: ps[i]); out = [0.0] * len(ps); run = 0.0
    for r, i in enumerate(order):
        run = max(run, min(1.0, (len(ps) - r) * ps[i])); out[i] = run
    return out


def cohens_h(p1: float, p2: float) -> float: return 2 * math.asin(math.sqrt(p1)) - 2 * math.asin(math.sqrt(p2))


def paired(a: dict, b: dict) -> dict:
    """a, b: {scenario_id: 0/1} over the same ids. Returns counts, risk difference (a-b) and exact McNemar p."""
    ids = sorted(set(a) & set(b)); n = len(ids)
    if not n: return {"n": 0}
    only_a = sum(a[i] and not b[i] for i in ids); only_b = sum(b[i] and not a[i] for i in ids); pa = sum(a[i] for i in ids) / n; pb = sum(b[i] for i in ids) / n
    return {"n": n, "a_rate": round(pa, 4), "b_rate": round(pb, 4), "risk_difference": round(pa - pb, 4), "cohens_h": round(cohens_h(pa, pb), 4), "discordant_a_only": only_a, "discordant_b_only": only_b, "mcnemar_exact_p": round(mcnemar_exact(only_a, only_b), 6)}


def cluster_bootstrap_rd(a: dict, b: dict, cluster: dict, *, reps: int = 4000, seed: int = 7):
    """95% CI for the risk difference, resampling TEMPLATE clusters (scenarios of one template are near-duplicates, not independent)."""
    ids = sorted(set(a) & set(b)); groups: dict = {}
    for i in ids: groups.setdefault(cluster[i], []).append(i)
    keys = sorted(groups); rnd = random.Random(seed); rds = []
    if len(keys) < 2: return None
    for _ in range(reps):
        pick = [i for k in (rnd.choice(keys) for _ in keys) for i in groups[k]]; rds.append(sum(a[i] for i in pick) / len(pick) - sum(b[i] for i in pick) / len(pick))
    rds.sort(); return [round(rds[int(0.025 * reps)], 4), round(rds[int(0.975 * reps) - 1], 4)]
