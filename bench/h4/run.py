#!/usr/bin/env python3
"""H4 runner. `run.py main` -> results/v2/h4-main (write-once). `run.py check` -> recompute aggregate from raw rows and compare. Imports the four suites; each scenario runs under B0-B7 plus 9 leave-one-layer-out ablations."""
import csv, hashlib, json, math, os, platform, random, subprocess, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from bench.h4 import core, hmib, hccb, hecb, hieb, manifests as M, splits as SP         # noqa: F401  (imports register the scenarios)
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
def sha(o): return hashlib.sha256(o if isinstance(o, bytes) else json.dumps(o, sort_keys=True, default=str).encode()).hexdigest()
def commit():
    try: return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT).stdout.strip()
    except OSError: return "unknown"
# ------------------------------------------------------------------ statistics (self-contained, stdlib only)
def wilson(k, n, z=1.959964):
    if n == 0: return None
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d; return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]
def upper_zero(n, a=0.05): return round(1 - a ** (1 / n), 4) if n else None            # exact one-sided 95% bound for 0 events in n
def binom_two_sided(b, c):
    n = b + c
    if n == 0: return 1.0
    k = min(b, c); pm = lambda i: math.comb(n, i) * 0.5 ** n
    return min(1.0, sum(pm(i) for i in range(0, k + 1)) * 2)
def holm(ps):
    idx = sorted(range(len(ps)), key=lambda i: ps[i]); out = [0.0] * len(ps); mx = 0.0
    for r, i in enumerate(idx): mx = max(mx, min(1.0, (len(ps) - r) * ps[i])); out[i] = round(mx, 6)
    return out
def pct(xs, q): s = sorted(xs); return round(s[min(len(s) - 1, int(q * len(s)))], 4) if s else None
# ------------------------------------------------------------------ run
def run_all(baselines, repeats=1):
    rows = []
    for sid in sorted(core.REGISTRY):
        for b in baselines:
            for r in range(repeats):
                for row in core.run_one(core.REGISTRY[sid], b): row["repeat"] = r; rows.append(row)
    return rows
def per_scn(rows):
    """-> {(scenario, baseline): {effect, denied, ctl_ok, ctl_denied, seconds}} using repeat 0 for outcomes (repeats feed timing only; outcome stability is checked separately)."""
    d = {}
    for r in rows:
        if r["repeat"] != 0: continue
        e = d.setdefault((r["scenario"], r["baseline"]), {"effect": None, "denied": None, "ctl_ok": None, "ctl_denied": None, "seconds": None, "family": r["family"], "suite": r["suite"], "error": False})
        if r["kind"] == "attack": e["effect"], e["denied"] = r["effect"], r["denied"]
        else: e["ctl_ok"], e["ctl_denied"], e["seconds"] = r["ok"], r["denied"], r["seconds"]
        if r.get("error"): e["error"] = True
    return d
def stability(rows):
    by = {}
    for r in rows:
        if r["kind"] == "attack": by.setdefault((r["scenario"], r["baseline"]), set()).add(r["effect"])
    return {"checked": len(by), "unstable": sorted(f"{k[0]}/{k[1]}" for k, v in by.items() if len(v) > 1)}
def aggregate(rows, mapping, bases):
    d = per_scn(rows); scn = sorted({k[0] for k in d}); atk = [s for s in scn if any(d[(s, b)]["effect"] is not None for b in bases)]
    out = {"baselines": {}, "paired_vs_B0": {}, "by_suite": {}, "by_split": {}, "ablation": {}, "scenario_matrix": {}}
    for b in bases:
        A = [s for s in atk if d[(s, b)]["effect"] is not None]; k = sum(d[(s, b)]["effect"] for s in A); den = sum(bool(d[(s, b)]["denied"]) for s in A)
        C = [s for s in scn if d[(s, b)]["ctl_ok"] is not None]; ok = sum(d[(s, b)]["ctl_ok"] for s in C); fb = sum(bool(d[(s, b)]["ctl_denied"]) for s in C); sec = [d[(s, b)]["seconds"] for s in C if d[(s, b)]["seconds"] is not None]
        out["baselines"][b] = {"description": core.BASELINES[b][1], "layers": sorted(core.BASELINES[b][0]), "coverage_limit": core.COVERAGE_LIMITS.get(b, "ablation configuration"), "attack_scenarios": len(A), "effects": k, "effect_rate": round(k / len(A), 4), "effect_ci95_wilson": wilson(k, len(A)), "effect_upper95_if_zero": upper_zero(len(A)) if k == 0 else None,
                               "attack_denied": den, "control_n": len(C), "control_completed": ok, "completion_rate": round(ok / len(C), 4), "completion_ci95": wilson(ok, len(C)), "false_blocks": fb, "false_block_rate": round(fb / len(C), 4), "false_block_ci95": wilson(fb, len(C)),
                               "control_seconds_p50": pct(sec, .5), "control_seconds_p95": pct(sec, .95), "harness_error_rows": sum(d[(s, b)]["error"] for s in scn)}
        out["scenario_matrix"][b] = {s: ("E" if d[(s, b)]["effect"] else "-" if d[(s, b)]["effect"] is None else ".") for s in scn}
    fams = sorted({d[(s, "B0")]["family"] for s in atk}); rng = random.Random(11); ps = []; names = []
    for b in bases:
        if b == "B0": continue
        B0 = [d[(s, "B0")]["effect"] for s in atk]; Bx = [d[(s, b)]["effect"] for s in atk]; bb = sum(1 for x, y in zip(B0, Bx) if x and not y); cc = sum(1 for x, y in zip(B0, Bx) if y and not x); p = binom_two_sided(bb, cc); ps.append(p); names.append(b)
        def diff(sample): return sum(d[(s, "B0")]["effect"] - d[(s, b)]["effect"] for s in sample) / len(sample)
        byf = {f: [s for s in atk if d[(s, "B0")]["family"] == f] for f in fams}; bs = []
        for _ in range(2000): samp = [s for f in (rng.choice(fams) for _ in fams) for s in byf[f]]; bs.append(diff(samp))
        bs.sort(); out["paired_vs_B0"][b] = {"n_pairs": len(atk), "b0_only_effect": bb, "baseline_only_effect": cc, "risk_reduction": round(diff(atk), 4), "family_cluster_bootstrap_ci95": [round(bs[50], 4), round(bs[1949], 4)], "mcnemar_exact_p": round(p, 6)}
    for n, a in zip(names, holm(ps)): out["paired_vs_B0"][n]["holm_adjusted_p"] = a
    for suite in M.SUITES:
        out["by_suite"][suite] = {}
        for b in bases:
            A = [s for s in atk if s.startswith(suite)]; k = sum(d[(s, b)]["effect"] for s in A); C = [s for s in scn if s.startswith(suite)]; ok = sum(d[(s, b)]["ctl_ok"] for s in C); fb = sum(bool(d[(s, b)]["ctl_denied"]) for s in C)
            out["by_suite"][suite][b] = {"attacks": len(A), "effects": k, "effect_ci95": wilson(k, len(A)), "controls": len(C), "completed": ok, "false_blocks": fb}
    for sp in ("train", "validation", "test"):
        out["by_split"][sp] = {}
        for b in bases:
            A = [s for s in atk if mapping[d[(s, "B0")]["family"]] == sp]; k = sum(d[(s, b)]["effect"] for s in A); out["by_split"][sp][b] = {"attacks": len(A), "effects": k, "effect_ci95": wilson(k, len(A))}
    return out, d, atk
def ablation(d, atk):
    full = sum(d[(s, "B7")]["effect"] for s in atk); out = {"B7_effects": full, "attacks": len(atk), "layers": {}}
    for l in core.LAYERS:
        b = f"B7-{l}"; k = sum(d[(s, b)]["effect"] for s in atk); out["layers"][l] = {"effects_without_layer": k, "marginal_effects_attributable": k - full, "scenarios_exposed": sorted(s for s in atk if d[(s, b)]["effect"] and not d[(s, "B7")]["effect"])}
    return out
# ------------------------------------------------------------------ outputs
def svg_bars(agg, bases, path):
    W, H, m = 760, 340, 50; bw = (W - 2 * m) / len(bases); g = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" font-family="sans-serif" font-size="12"><rect width="100%" height="100%" fill="white"/>', f'<text x="{m}" y="22" font-size="14">Attack effect rate by baseline (95% Wilson CI) - synthetic fixtures, n={agg["baselines"][bases[0]]["attack_scenarios"]} attack scenario types</text>']
    for i, b in enumerate(bases):
        r = agg["baselines"][b]; x = m + i * bw + bw * .2; h = (H - 2 * m - 20) * r["effect_rate"]; y = H - m - h; lo, hi = r["effect_ci95_wilson"]; yl = H - m - (H - 2 * m - 20) * lo; yh = H - m - (H - 2 * m - 20) * hi; cx = x + bw * .3
        g += [f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw * .6:.1f}" height="{max(h, .5):.1f}" fill="#4a6fa5"/>', f'<line x1="{cx:.1f}" y1="{yl:.1f}" x2="{cx:.1f}" y2="{yh:.1f}" stroke="#222"/>', f'<text x="{cx:.1f}" y="{H - m + 16}" text-anchor="middle">{b}</text>', f'<text x="{cx:.1f}" y="{y - 6:.1f}" text-anchor="middle">{r["effects"]}/{r["attack_scenarios"]}</text>']
    open(path, "w").write("\n".join(g) + "</svg>\n")
def svg_heat(agg, bases, path):
    scn = sorted(agg["scenario_matrix"][bases[0]]); cw, rh, left, top = 56, 13, 90, 40; W, H = left + cw * len(bases) + 10, top + rh * len(scn) + 10; g = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" font-family="monospace" font-size="10"><rect width="100%" height="100%" fill="white"/><text x="6" y="16" font-size="12">Forbidden effect per scenario (red = effect occurred; green = none; grey = benign type)</text>']
    for j, b in enumerate(bases): g.append(f'<text x="{left + j * cw + cw / 2}" y="{top - 6}" text-anchor="middle">{b}</text>')
    for i, s in enumerate(scn):
        g.append(f'<text x="4" y="{top + i * rh + 10}">{s}</text>')
        for j, b in enumerate(bases):
            v = agg["scenario_matrix"][b][s]; c = {"E": "#c0392b", ".": "#2e8b57", "-": "#cccccc"}[v]; g.append(f'<rect x="{left + j * cw + 1}" y="{top + i * rh}" width="{cw - 2}" height="{rh - 1}" fill="{c}"/>')
    open(path, "w").write("\n".join(g) + "</svg>\n")
def write_csv(agg, bases, path):
    cols = ["schema_version", "baseline", "layers", "attack_scenarios", "effects", "effect_rate", "ci_low", "ci_high", "attack_denied", "control_n", "control_completed", "false_blocks", "false_block_rate", "control_seconds_p50", "control_seconds_p95"]
    w = csv.writer(open(path, "w", newline="")); w.writerow(cols)
    for b in bases:
        r = agg["baselines"][b]; w.writerow(["h4-aggregate-1.0.0", b, "+".join(r["layers"]) or "none", r["attack_scenarios"], r["effects"], r["effect_rate"], *r["effect_ci95_wilson"], r["attack_denied"], r["control_n"], r["control_completed"], r["false_blocks"], r["false_block_rate"], r["control_seconds_p50"], r["control_seconds_p95"]])
def versions():
    v = {"python": platform.python_version()}
    for m in ("yaml", "cryptography", "bandit"):
        try: mod = __import__(m); v[m] = getattr(mod, "__version__", "unknown")
        except Exception: v[m] = "missing"
    return v
def main(name="main", repeats=2):
    d = os.path.join(ROOT, "results", "v2", f"h4-{name}")
    if os.path.exists(os.path.join(d, "result.json")): sys.exit(f"refusing: {d}/result.json exists (never overwrite; use a new experiment id)")
    os.makedirs(d, exist_ok=True); allb = list(core.BASELINES); t0 = time.time(); rows = run_all(core.MAIN, repeats) + run_all([b for b in allb if b not in core.MAIN], 1)
    fam = {s.family: 0 for s in core.REGISTRY.values()}; mapping = SP.assign(list(fam)); agg, dd, atk = aggregate(rows, mapping, core.MAIN); agg["ablation"] = ablation(per_scn(rows), atk)
    # full per-scenario detail for ablation configs (matrix only)
    for b in allb:
        if b not in core.MAIN: agg["scenario_matrix"][b] = {s: ("E" if per_scn(rows)[(s, b)]["effect"] else "-" if per_scn(rows)[(s, b)]["effect"] is None else ".") for s in sorted(core.REGISTRY)}
    ms = M.emit(core.REGISTRY); st = stability(rows)
    result = {"schema": "h4-result-1.0.0", "aggregate": agg, "stability": st, "splits": {"mapping": mapping, "leakage": SP.leakage_report(list(ms.values()), mapping)}, "scenario_counts": {s: sum(1 for k in core.REGISTRY if k.startswith(s)) for s in M.SUITES},
              "mg_g11": {"statement": "effect oracles are independent of guard decisions; see docs/evidence/p37/ORACLES.md", "synthetic_only": True}, "wall_seconds": round(time.time() - t0, 1)}
    open(os.path.join(d, "raw_runs.jsonl"), "w").write("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)); json.dump(result, open(os.path.join(d, "result.json"), "w"), indent=1, sort_keys=True)
    write_csv(agg, core.MAIN, os.path.join(d, "aggregate_v1.csv")); svg_bars(agg, list(core.MAIN), os.path.join(d, "fig_effect_by_baseline.svg")); svg_heat(agg, list(core.MAIN), os.path.join(d, "fig_scenario_matrix.svg"))
    repro = {"schema": "h4-repro-1.0.0", "git_commit": commit(), "versions": versions(), "machine": {"kernel": platform.release(), "arch": platform.machine()}, "command": "python3 bench/h4/run.py main", "repeats": repeats, "split_salt": SP.SALT, "stat_seed": 11,
             "scenario_manifest_digests": {k: sha(v) for k, v in ms.items()}, "baselines": {b: sorted(core.BASELINES[b][0]) for b in allb}, "network": "none required; fixtures are loopback/in-process only"}
    json.dump(repro, open(os.path.join(d, "repro_manifest.json"), "w"), indent=1, sort_keys=True)
    files = {f: hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() for f in sorted(os.listdir(d)) if f != "manifest.json"}
    json.dump({"write_once": True, "files": files, "git_commit": commit(), "created_unix": int(time.time())}, open(os.path.join(d, "manifest.json"), "w"), indent=1, sort_keys=True); print("wrote", d, "wall", result["wall_seconds"], "s")
def check(name="main"):
    d = os.path.join(ROOT, "results", "v2", f"h4-{name}"); res = json.load(open(os.path.join(d, "result.json"))); rows = [json.loads(l) for l in open(os.path.join(d, "raw_runs.jsonl"))]
    mapping = res["splits"]["mapping"]; agg, dd, atk = aggregate(rows, mapping, core.MAIN); ab = ablation(per_scn(rows), atk); keep = res["aggregate"]
    ok = all(json.dumps(agg[k], sort_keys=True) == json.dumps(keep[k], sort_keys=True) for k in ("baselines", "paired_vs_B0", "by_suite", "by_split")) and json.dumps(ab, sort_keys=True) == json.dumps(keep["ablation"], sort_keys=True)
    man = json.load(open(os.path.join(d, "manifest.json"))); okh = all(hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() == h for f, h in man["files"].items())
    print("h4 aggregate recomputed from raw rows:", "MATCH" if ok else "MISMATCH", "| file hashes:", "OK" if okh else "BAD"); sys.exit(0 if ok and okh else 1)
if __name__ == "__main__":
    a = sys.argv[1:] or ["main"]
    if a[0] == "main": main(*(["main"] + ([int(a[1])] if len(a) > 1 else [])))
    elif a[0] == "check": check()
    else: sys.exit("usage: run.py main [repeats] | check")
