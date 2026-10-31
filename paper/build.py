"""Builds every table and figure of the manuscript from versioned result artifacts only (P11-15). No number is typed by hand.
Usage: python3 paper/build.py [--check]. --check fails if committed outputs or the manuscript's embedded tables differ from regeneration."""
import hashlib, json, re, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]; P = REPO / "paper"; RES = json.loads((REPO / "results/v2/p9_comparative.json").read_text()); OLD = json.loads((REPO / "results/v2/p8-secbench-0.1/test.json").read_text())
LABEL = {"open": "B0 no defence", "name_heuristic": "B1 name heuristic", "b2_allowlist": "B2 endpoint allowlist", "b3_read_send_pair": "B3 read+send rule", "b4_exact_taint": "B4 exact taint", "labels_only": "labels only", "full": "full", "full-no-boundary": "full − boundary", "full-no-ledger": "full − ledger", "full-no-manual-trust": "full − manifest trust"}
ORDER = list(LABEL)
ci = lambda c: f"[{c[0]:.2f}, {c[1]:.2f}]" if c else "n/a"


def table_main():
    out = ["| system | attacker success (test) | 95% Wilson CI | benign utility (test) | attacker success (0.1 templates) | attacker success (post-hoc S) | benign utility (S) |", "|---|---|---|---|---|---|---|"]
    T, V, S = RES["summaries"]["test_all"], RES["summaries"]["test_v01_templates"], RES["summaries"]["post_hoc_S"]
    for k in ORDER[:7]:
        t, v, s = T[k], V[k], S[k]; out.append(f"| {LABEL[k]} | {t['attacker_success']}/{t['harmful_n']} | {ci(t['attacker_success_ci95'])} | {t['benign_utility_ok']}/{t['benign_n']} | {v['attacker_success']}/{v['harmful_n']} | {s['attacker_success']}/{s['harmful_n']} | {s['benign_utility_ok']}/{s['benign_n']} |")
    return "\n".join(out)


def table_ablation():
    out = ["| system | attacker success (test) | benign utility (test) | misses (templates) |", "|---|---|---|---|"]
    for k in ("full", "full-no-boundary", "full-no-ledger", "full-no-manual-trust", "labels_only"):
        t = RES["summaries"]["test_all"][k]; out.append(f"| {LABEL[k]} | {t['attacker_success']}/{t['harmful_n']} | {t['benign_utility_ok']}/{t['benign_n']} | {', '.join(t['attacker_success_templates']) or 'none'} |")
    return "\n".join(out)


def table_paired():
    out = ["| comparison (attacker success, test) | risk difference | cluster-bootstrap 95% CI | Holm-adjusted p | prereg rule |", "|---|---|---|---|---|"]
    for c in RES["comparisons"]:
        if c.get("primary"): out.append(f"| {LABEL[c['a']]} vs {LABEL[c['b']]} | {c['risk_difference']:+.2f} | {ci(c['risk_difference_ci95_cluster'])} | {c['holm_adjusted_p']:.4f} | {'met' if c['supported_by_prereg_rule'] else 'not met'} |")
    b3 = next(c for c in RES["comparisons"] if c["subset"] == "test_v01_templates" and c["a"] == "full" and c["b"] == "b3_read_send_pair" and c["metric"] == "attacker_success")
    out.append(f"| full vs B3 (0.1 templates; not pre-registered as primary) | {b3['risk_difference']:+.2f} | {ci(b3['risk_difference_ci95_cluster'])} | n/a (exact McNemar p = {b3['mcnemar_exact_p']:.2f}) | not applicable: no difference |")
    return "\n".join(out)


def table_transport():
    out = ["| system | payload | transport | allowed |", "|---|---|---|---|"]
    for x in RES["transport_equivalence"]["matrix"]:
        if x["system"] == "full": out.append(f"| {x['system']} | {x['payload']} | {x['transport']} | {'yes' if x['allowed'] else 'no'} |")
    return "\n".join(out)


def table_v01():
    d = OLD["summary"]; return "\n".join(["| system (SecBench 0.1, test, 26 harmful / 26 benign) | attacker success | benign utility |", "|---|---|---|"] + [f"| {k} | {d[k]['attacker_success']}/{d[k]['harmful_n']} | {d[k]['benign_utility_ok']}/{d[k]['benign_n']} |" for k in ("open", "name_heuristic", "labels_only", "full")])


def bar_svg(title, rows, maxv, color):
    w, bar, left = 640, 22, 190; h = 40 + len(rows) * (bar + 8)
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" role="img" aria-label="{title}"><title>{title}</title><rect width="{w}" height="{h}" fill="white"/><text x="8" y="20" font-family="sans-serif" font-size="14" font-weight="bold">{title}</text>']
    for i, (name, k, n) in enumerate(rows):
        y = 34 + i * (bar + 8); bw = (w - left - 70) * (k / n if n else 0)
        s.append(f'<text x="8" y="{y + 16}" font-family="sans-serif" font-size="12">{name}</text><rect x="{left}" y="{y}" width="{bw:.1f}" height="{bar}" fill="{color}"/><text x="{left + bw + 6:.1f}" y="{y + 16}" font-family="sans-serif" font-size="12">{k}/{n}</text>')
    return "\n".join(s) + "</svg>\n"


def figures():
    T = RES["summaries"]["test_all"]
    return {"fig1_attacker_success.svg": bar_svg("Attacker success on test split (lower is better)", [(LABEL[k], T[k]["attacker_success"], T[k]["harmful_n"]) for k in ORDER], 1, "#b3412e"),
            "fig2_benign_utility.svg": bar_svg("Benign utility on test split (higher is better)", [(LABEL[k], T[k]["benign_utility_ok"], T[k]["benign_n"]) for k in ORDER], 1, "#2e6f8e")}


def generated():
    tabs = {"table_main": table_main(), "table_ablation": table_ablation(), "table_paired": table_paired(), "table_transport": table_transport(), "table_v01": table_v01()}
    return tabs, figures()


def embed(text, tabs):
    for k, v in tabs.items():
        text, n = re.subn(rf"(<!-- BEGIN {k} -->\n).*?(<!-- END {k} -->)", lambda m: m.group(1) + v + "\n" + m.group(2), text, flags=re.S)
        if n != 1: raise SystemExit(f"manuscript lacks exactly one marker pair for {k}")
    return text


def main(check=False):
    tabs, figs = generated(); ms = (P / "MANUSCRIPT.md").read_text(); new = embed(ms, tabs); bad = []
    files = {P / "tables" / f"{k}.md": v + "\n" for k, v in tabs.items()} | {P / "figures" / k: v for k, v in figs.items()} | {P / "MANUSCRIPT.md": new}
    for f, v in files.items():
        if check:
            if not f.exists() or f.read_text() != v: bad.append(str(f.relative_to(REPO)))
        else: f.write_text(v)
    man = {"inputs": {p: hashlib.sha256((REPO / p).read_bytes()).hexdigest() for p in ("results/v2/p9_comparative.json", "results/v2/p8-secbench-0.1/test.json")}, "outputs": {str(f.relative_to(REPO)): hashlib.sha256(v.encode()).hexdigest() for f, v in sorted(files.items(), key=lambda x: str(x[0]))}}
    mp = P / "BUILD_MANIFEST.json"
    if check:
        if not mp.exists() or json.loads(mp.read_text()) != man: bad.append("paper/BUILD_MANIFEST.json")
        if bad: print("STALE:", bad); sys.exit(1)
        print("OK")
    else: mp.write_text(json.dumps(man, indent=1, sort_keys=True)); print("built")


if __name__ == "__main__": main("--check" in sys.argv)
