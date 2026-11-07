"""HorizonSpectra toy slice (SP-06,07,11,12,15,16,17,18,20). RESEARCH, CANDIDATE, fixtures only — no real agents, no network.
A system is a black box: probe -> set of (sink, tag) effects. Only INSTRUMENTED sinks are observed (fixture-owned journals, never the system's own logs).
Hypothesis class C = finite set of channel graphs {probe: frozenset(sinks)}. Inference returns DISCOVERED (undeclared instrumented effect seen), UNIDENTIFIABLE (surviving hypotheses disagree only on
uninstrumented sinks, or on effects relevant to the claim), or BOUNDED_COVERAGE (scope = probes tried, sinks instrumented, hypothesis class)."""
from __future__ import annotations
import random


class Journal:
    """Fixture-owned sink journal. The system under test cannot write to it except by causing a real effect on that sink."""
    def __init__(self, sinks): self.sinks, self.rows = frozenset(sinks), []
    def record(self, sink, tag):
        if sink in self.sinks: self.rows.append((sink, tag))


def run_probe(system, probe, journal: Journal, budget: dict) -> frozenset:
    if budget["left"] <= 0: raise RuntimeError("PROBE_BUDGET_EXHAUSTED")
    budget["left"] -= 1; before = len(journal.rows)
    for sink, tag in system(probe): journal.record(sink, tag)
    return frozenset(s for s, _ in journal.rows[before:])


def consistent(hyps, probe, seen, instrumented): return [h for h in hyps if frozenset(h.get(probe, frozenset())) & instrumented == seen]


def infer(system, probes, hyps, declared, instrumented, *, budget=50, strategy="active", seed=0, order=None):
    """declared: {probe: sinks} the integration CLAIMS. Returns (verdict, detail)."""
    instrumented = frozenset(instrumented); j = Journal(instrumented); b = {"left": budget}; alive = list(hyps); tried = []; rng = random.Random(seed); pool = list(probes)
    while pool:
        if b["left"] <= 0: return "UNKNOWN", {"reason": "probe budget exhausted before every probe was tried", "untried": sorted(pool), "probes_used": len(tried)}
        if strategy == "active":   # pick the probe whose predicted instrumented outcome splits the surviving hypotheses most evenly (affects ORDER / time-to-discovery only: every probe is still run before a non-DISCOVERED verdict, so untried probes are never certified) (max distinct outcomes, then min largest class)
            def score(p):
                groups = {}
                for h in alive: groups.setdefault(frozenset(h.get(p, frozenset())) & instrumented, []).append(h)
                return (-len(groups), max(len(g) for g in groups.values()) if groups else 0, p)
            p = min(pool, key=score)
        elif strategy == "ordered": p = min(pool, key=lambda q: (list(order).index(q) if q in order else len(order), q))   # fixed external ordering (static-graph / expert-rule baselines)
        else: p = pool[rng.randrange(len(pool))]
        pool.remove(p); seen = run_probe(system, p, j, b); tried.append(p)
        extra = seen - frozenset(declared.get(p, ()))
        if extra: return "DISCOVERED", {"probe": p, "undeclared_sinks": sorted(extra), "probes_used": len(tried), "evidence": list(j.rows)}
        alive = consistent(alive, p, seen, instrumented)
    # what do surviving hypotheses say about effects we cannot see?
    hidden = {p: sorted({s for h in alive for s in h.get(p, ())} - instrumented) for p in probes}
    hidden = {p: s for p, s in hidden.items() if s}
    if not alive: return "UNKNOWN", {"reason": "no hypothesis in class C explains observations (model class wrong)", "probes_used": len(tried)}
    if hidden or len({frozenset((p, frozenset(h.get(p, ()))) for p in probes) for h in alive}) > 1:
        return "UNIDENTIFIABLE", {"surviving": len(alive), "uninstrumented_effects_possible": hidden, "probes_used": len(tried)}
    return "BOUNDED_COVERAGE", {"scope": {"probes": sorted(tried), "instrumented": sorted(instrumented), "hypotheses": len(hyps)}, "probes_used": len(tried), "note": "no claim outside this scope"}
