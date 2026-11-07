"""S2-07 probe-selection comparison on SELF-AUTHORED synthetic systems (CANDIDATE; not independent, not held-out, toy). Measures probes-to-discovery and discovery rate at a fixed budget for:
active (Spectra), random (mean over seeds), static_graph (order by declared effect count desc), expert_rule (external-facing probe kinds first). Whatever the numbers are, they are reported; nothing here claims active selection helps."""
from __future__ import annotations
import json, random, sys
from . import tomography as T

KINDS = ("net", "file", "proc", "local")
INSTR = frozenset({"fs", "net", "queue"})
SINKS = ("fs", "net", "queue", "offhost")
EXPERT_RANK = {"net": 0, "proc": 1, "file": 2, "local": 3}


def make_world(rng: random.Random, n=8):
    probes = [f"{rng.choice(KINDS)}_{i}" for i in range(n)]
    declared = {p: tuple(sorted(rng.sample(SINKS[:3], rng.choice((0, 0, 1))))) for p in probes}
    hidden = rng.random() < 0.7
    graph = {p: set(v) for p, v in declared.items()}
    target = None
    if hidden:
        target = rng.choice(probes); extra = rng.choice(("fs", "net", "queue"))
        if extra in graph[target]: extra = next(s for s in ("fs", "net", "queue") if s not in graph[target]) if len(graph[target]) < 3 else None
        if extra: graph[target].add(extra)
        else: target = None
    hyps = [{p: frozenset(v) for p, v in declared.items()}] + [{**{p: frozenset(v) for p, v in declared.items()}, p: frozenset(declared[p]) | {s}} for p in probes for s in ("fs", "net", "queue") if s not in declared[p]]
    return probes, declared, graph, hyps, target


def run(strategy, probes, declared, graph, hyps, budget, order=None, seed=0):
    system = lambda probe: [(s, f"{probe}->{s}") for s in sorted(graph.get(probe, ()))]
    v, d = T.infer(system, probes, hyps, declared, INSTR, budget=budget, strategy=strategy, seed=seed, order=order)
    return v, d.get("probes_used", budget)


def experiment(n_worlds=300, seed=2026, budgets=(2, 4, 8), n_random=20):
    rng = random.Random(seed); out = {"n_worlds": n_worlds, "seed": seed, "budgets": list(budgets), "worlds_with_discoverable_hidden_effect": 0, "strategies": {}}
    names = ("active", "random", "static_graph", "expert_rule"); acc = {n: {b: 0.0 for b in budgets} for n in names}; used = {n: 0.0 for n in names}; per = {n: [] for n in names}; disc = 0
    for _ in range(n_worlds):
        probes, declared, graph, hyps, target = make_world(rng)
        if target is None: continue
        disc += 1
        orders = {"static_graph": sorted(probes, key=lambda p: (-len(declared[p]), p)), "expert_rule": sorted(probes, key=lambda p: (EXPERT_RANK[p.split("_")[0]], p))}
        for b in budgets:
            acc["active"][b] += run("active", probes, declared, graph, hyps, b)[0] == "DISCOVERED"
            acc["random"][b] += sum(run("random", probes, declared, graph, hyps, b, seed=s)[0] == "DISCOVERED" for s in range(n_random)) / n_random
            for n in ("static_graph", "expert_rule"): acc[n][b] += run("ordered", probes, declared, graph, hyps, b, order=orders[n])[0] == "DISCOVERED"
        u = {"active": run("active", probes, declared, graph, hyps, 50)[1], "random": sum(run("random", probes, declared, graph, hyps, 50, seed=s)[1] for s in range(n_random)) / n_random}
        for n in ("static_graph", "expert_rule"): u[n] = run("ordered", probes, declared, graph, hyps, 50, order=orders[n])[1]
        for n in names: used[n] += u[n]; per[n].append(u[n])
    out["worlds_with_discoverable_hidden_effect"] = disc
    for n in names: out["strategies"][n] = {"discovery_rate_at_budget": {str(b): round(acc[n][b] / disc, 4) for b in budgets}, "mean_probes_to_discovery": round(used[n] / disc, 3)}
    brng = random.Random(seed + 1); out["paired_bootstrap_95ci_mean_probes_saved_by_active_vs"] = {}
    for n in names:
        if n == "active": continue
        diffs = [per[n][i] - per["active"][i] for i in range(disc)]; means = sorted(sum(brng.choice(diffs) for _ in diffs) / len(diffs) for _ in range(2000))
        out["paired_bootstrap_95ci_mean_probes_saved_by_active_vs"][n] = [round(means[50], 3), round(means[1949], 3)]
    out["note"] = "self-authored toy worlds; hidden effects land on instrumented sinks only; active uses the same hypothesis class that generated the worlds; NOT held-out, NOT independent"
    return out


if __name__ == "__main__":
    r = experiment(); json.dump(r, open(sys.argv[1] if len(sys.argv) > 1 else "/dev/stdout", "w"), indent=1, sort_keys=True); print(json.dumps(r["strategies"], sort_keys=True))
