"""P9 comparative study: python3 bench/p9/study.py [--out results/v2/p9_comparative.json]. Scripted agents; same worlds, tools and data for every system."""
from __future__ import annotations
import argparse, hashlib, json, shutil, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from bench.secbench import spec
from bench.secbench.runner import run_one, summarize, CODE_TEMPLATES
from bench.secbench.world import ALL_SUTS, World, Sut, NoRealNetwork
from bench.p9 import stats as S
from horizon.codemode.exec import HERE

NAMES = {"open": "B0", "name_heuristic": "B1", "b2_allowlist": "B2", "b3_read_send_pair": "B3", "b4_exact_taint": "B4"}
PRIMARY = [("full", b) for b in ("open", "name_heuristic", "b2_allowlist", "b4_exact_taint")]
EXTRA = [("full", "labels_only"), ("full", "b3_read_send_pair"), ("labels_only", "b3_read_send_pair")] + [("full", a) for a in ("full-no-boundary", "full-no-ledger", "full-no-manual-trust")]
SUBSETS = {"test_all": lambda t: t["split"] == "test", "test_v01_templates": lambda t: t["split"] == "test" and t["template_code"][0] != "S", "post_hoc_S": lambda t: t["template_code"][0] == "S", "dev": lambda t: t["split"] == "dev"}


def run_rows(seed: int, have_node: bool):
    rows = []
    with NoRealNetwork():
        for sc in spec.build(seed):
            if sc["truth"]["template_code"] in CODE_TEMPLATES and not have_node: continue
            for s in ALL_SUTS: rows.append(run_one(sc, s, seed))
    return rows


def compare(rows, subset, a, b, metric):
    sel = SUBSETS[subset]; role = "harmful" if metric == "attacker_success" else "benign"; key = (lambda r: int(r["attacker_success"])) if metric == "attacker_success" else (lambda r: int(bool(r["utility_ok"])))
    pick = lambda sysn: {r["id"]: key(r) for r in rows if r["system"] == sysn and r["role"] == role and sel(r["_t"])}
    A, B = pick(a), pick(b); cl = {r["id"]: r["template"] for r in rows if r["system"] == a}
    out = paired(A, B, cl); out.update({"a": a, "b": b, "metric": metric, "subset": subset}); return out


def paired(A, B, cl):
    r = S.paired(A, B); r["risk_difference_ci95_cluster"] = S.cluster_bootstrap_rd(A, B, cl) if r["n"] else None; r["n_template_clusters"] = len({cl[i] for i in A}) if A else 0; return r


def transport_equivalence():
    """P9-17: the same bytes through each transport. Semantic disagreements between transports are reported, not hidden."""
    out = []
    with NoRealNetwork():
        for sysn in ("labels_only", "full", "full-no-boundary"):
            for src, kind in (("s2", "secret"), ("s1", "public")):
                for via in ("utcp.post", "utcp.get", "cli.upload", "mcp.post", "ws.send"):
                    w = World(spec.SEED); sut = Sut(sysn, w); v, h = sut.read(src, "mcp"); r = sut.send(via, v, [h], "d1", None)
                    out.append({"system": sysn, "payload": kind, "transport": via, "allowed": bool(r.get("ok")), "reason": None if r.get("ok") else str(r.get("error"))[:80]})
    dis = []
    for sysn in ("labels_only", "full", "full-no-boundary"):
        for kind in ("secret", "public"):
            d = {x["transport"]: x["allowed"] for x in out if x["system"] == sysn and x["payload"] == kind}
            if len(set(d.values())) > 1: dis.append({"system": sysn, "payload": kind, "decisions": d})
    return {"matrix": out, "semantic_disagreements": dis}


def determinism(seeds=(1, 2, 3, 4, 5), have_node=False):
    """P9-19 (scripted agents): outcomes must not depend on the random token values. This is detector determinism, NOT model variance (no model is used)."""
    sigs = []
    for sd in seeds:
        with NoRealNetwork():
            rows = [run_one(sc, s, sd) for sc in spec.build(spec.SEED) if sc["truth"]["split"] == "test" and sc["truth"]["template_code"] not in CODE_TEMPLATES for s in ("labels_only", "full", "b4_exact_taint")]
        sigs.append(hashlib.sha256(json.dumps(sorted((r["id"], r["system"], r["outcome"], r["attacker_success"], bool(r["utility_ok"])) for r in rows)).encode()).hexdigest()[:16])
    return {"world_seeds": list(seeds), "outcome_signatures": sigs, "identical": len(set(sigs)) == 1, "scope": "non-Code-Mode test scenarios, systems labels_only/full/b4_exact_taint", "note": "No LLM in the loop: this says nothing about model-seed variance."}


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default=str(REPO / "results/v2/p9_comparative.json")); ap.add_argument("--seed", type=int, default=spec.SEED); a = ap.parse_args(argv)
    have_node = bool(shutil.which("node")) and (HERE / "node_modules" / "isolated-vm").exists()
    if not have_node: print("WARNING: no node runtime; Code Mode scenarios are skipped and the denominators shrink", file=sys.stderr)
    scs = {s["visible"]["id"]: s["truth"] for s in spec.build(a.seed)}; rows = run_rows(a.seed, have_node)
    for r in rows: r["_t"] = scs[r["id"]]
    summaries = {name: {sysn: v for sysn, v in summarize([r for r in rows if SUBSETS[name](r["_t"])]).items()} for name in SUBSETS}
    comps = []
    for name in ("test_all", "test_v01_templates", "post_hoc_S", "dev"):
        for (x, y) in PRIMARY + EXTRA:
            for m in ("attacker_success", "utility_ok"): comps.append(compare(rows, name, x, y, m))
    prim = [c for c in comps if c["subset"] == "test_all" and c["metric"] == "attacker_success" and (c["a"], c["b"]) in PRIMARY]
    adj = S.holm([c["mcnemar_exact_p"] for c in prim])
    for c, p in zip(prim, adj): c["holm_adjusted_p"] = round(p, 6); c["primary"] = True
    for c in prim:
        ci = c["risk_difference_ci95_cluster"]; c["supported_by_prereg_rule"] = bool(c["holm_adjusted_p"] < 0.05 and ci and ci[1] < 0 and c["risk_difference"] <= -0.25)
    per_template = {}
    for r in rows:
        if r["split"] in ("dev", "test"):
            e = per_template.setdefault(r["template"], {}).setdefault(r["system"], {"harmful_n": 0, "attacker_success": 0, "benign_n": 0, "benign_utility_ok": 0})
            if r["role"] == "harmful": e["harmful_n"] += 1; e["attacker_success"] += int(r["attacker_success"])
            else: e["benign_n"] += 1; e["benign_utility_ok"] += int(bool(r["utility_ok"]))
    for r in rows: r.pop("_t")
    res = {"benchmark": spec.VERSION, "seed": a.seed, "agents": "scripted (no LLM)", "node_runtime": have_node, "status": "CANDIDATE; exploratory (see docs/research/P9_PREREGISTRATION.md); Gate G6 NOT opened",
           "systems": {s: NAMES.get(s, s) for s in ALL_SUTS}, "summaries": summaries, "comparisons": comps, "per_template": per_template, "transport_equivalence": transport_equivalence(), "determinism": determinism(have_node=have_node),
           "denominators": "attacker_success over harmful scenarios; utility over benign scenarios; BLOCKED/REFUSED count as prevented and as utility loss; TIMEOUT/ERROR listed in outcomes and counted as neither", "rows": rows}
    Path(a.out).write_text(json.dumps(res, indent=1, sort_keys=True)); print("wrote", a.out)


if __name__ == "__main__": main()
