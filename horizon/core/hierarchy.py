"""Resource hierarchy DAG validation (P2-02) and static deployment certification (P2-20)."""
from __future__ import annotations
from .closure import closure


class HierarchyError(ValueError):
    pass


def validate_hierarchy(parents: dict[str, list[str]], multi_parent_ok: frozenset[str] = frozenset()) -> list[str]:
    """parents: node -> declared parent list. Returns a topological order (parents first). Rejects unknown parents, self-parent,
    duplicate parents, cycles, and ambiguous (multi-)parents unless explicitly whitelisted."""
    for n, ps in parents.items():
        if n in ps: raise HierarchyError(f"{n}: self-parent")
        if len(set(ps)) != len(ps): raise HierarchyError(f"{n}: duplicate parent")
        if len(ps) > 1 and n not in multi_parent_ok: raise HierarchyError(f"{n}: ambiguous parents {sorted(ps)}")
        for p in ps:
            if p not in parents: raise HierarchyError(f"{n}: unknown parent {p}")
    indeg = {n: len(ps) for n, ps in parents.items()}; kids: dict[str, list[str]] = {n: [] for n in parents}
    for n, ps in parents.items():
        for p in ps: kids[p].append(n)
    ready, order = sorted(n for n, d in indeg.items() if d == 0), []
    while ready:
        n = ready.pop(0); order.append(n)
        for k in sorted(kids[n]):
            indeg[k] -= 1
            if indeg[k] == 0: ready.append(k); ready.sort()
    if len(order) != len(parents): raise HierarchyError("cycle: " + ",".join(sorted(n for n, d in indeg.items() if d > 0)))
    return order


def ancestors(parents: dict[str, list[str]], node: str) -> set[str]:
    validate_hierarchy(parents, frozenset(parents)); out, st = set(), [node]
    while st:
        for p in parents[st.pop()]:
            if p not in out: out.add(p); st.append(p)
    return out


def certify(tool_caps: dict[str, list[str]], rules: list[dict], danger: list[str]) -> dict:
    """Static over-approximation: closure of the UNION of every tool's capabilities. Sound (never says 'safe' when a danger
    atom is reachable from any subset of the deployed tools) ONLY under these assumptions: (1) tool_caps is complete and
    correct for every deployed tool incl. effective runtime effects; (2) the rule set covers all dangerous compositions —
    this tool certifies absence from the *authored* horizon, not absence of danger; (3) no capability arises outside tool_caps
    (e.g. via shell access); (4) rules are the same at run time. Not complete: it may report danger for unreachable orderings."""
    union = sorted({a for caps in tool_caps.values() for a in caps})
    c = closure(union, rules); hit = sorted(set(danger) & set(c["atoms"]))
    return {"status": "NOT_CERTIFIED" if hit else "CERTIFIED_UNDER_ASSUMPTIONS", "reachable_danger": hit,
            "witnesses": {a: c["witnesses"][a] for a in hit if a in c["witnesses"]}, "closure_size": len(c["atoms"]),
            "assumptions": ["tool_caps complete", "authored horizon complete for scope", "no out-of-band capabilities", "rules unchanged at runtime"]}
