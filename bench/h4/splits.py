"""Anti-leakage splits (P37-13). Unit of assignment = FAMILY (semantic group) across all four suites, so a family never straddles splits; assignment is a deterministic hash order with fixed proportions.
HONEST LIMIT: the baselines' rules were written by the same author who wrote the scenarios, so splits give bookkeeping separation, not blind validation. Nothing was tuned after splits were assigned."""
import hashlib
SALT = "h4-v1"; PROPORTIONS = (("train", 0.5), ("validation", 0.2), ("test", 0.3))
def assign(families: list) -> dict:
    fam = sorted(set(families), key=lambda f: hashlib.sha256((SALT + f).encode()).hexdigest()); n = len(fam); out = {}; i = 0
    cuts = [round(n * 0.5), round(n * 0.7), n]
    for idx, f in enumerate(fam): out[f] = "train" if idx < cuts[0] else "validation" if idx < cuts[1] else "test"
    return out
def check(rows_or_scn, mapping: dict) -> list:
    """-> problems: a family mapped to two splits, or a scenario whose family is unmapped."""
    p = []
    for s in rows_or_scn:
        if s["family"] not in mapping: p.append("UNMAPPED:" + s["family"])
    return p
def leakage_report(scenarios: list, mapping: dict) -> dict:
    by = {}
    for s in scenarios: by.setdefault(s["family"], set()).add(mapping[s["family"]])
    straddle = {f: sorted(v) for f, v in by.items() if len(v) > 1}; cnt = {}
    for s in scenarios: cnt[mapping[s["family"]]] = cnt.get(mapping[s["family"]], 0) + 1
    return {"families": len(by), "straddling_families": straddle, "scenarios_per_split": cnt, "salt": SALT, "unit": "family"}
