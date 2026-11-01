"""Budgeted indirect-effect reachability (P44-08, P44-13) and the HorizonEmergence adapter. Edges carry a trust level; an unmodeled node, an unattested declaration used as proof of absence, or an exhausted budget yields UNKNOWN, never 'no path'."""
from __future__ import annotations
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class Graph:
    edges: dict = field(default_factory=dict)         # node -> list of (dst, kind, trust)  trust: attested | observed | declared | unknown
    modeled: set = field(default_factory=set)         # nodes whose outgoing behaviour is modeled
    def add(self, a, b, kind="forward", trust="attested"): self.edges.setdefault(a, []).append((b, kind, trust)); self.modeled.add(a)


@dataclass
class Result:
    reached: set; unknown: bool; exhausted: bool; expanded: int; max_depth_seen: int; ms: float; reasons: list


def reachable(g: Graph, start, *, max_nodes=10_000, max_depth=8, deadline_s=2.0, accept_trust=("attested", "observed")) -> Result:
    t0 = time.perf_counter(); seen = {start}; q = deque([(start, 0)]); expanded = 0; unknown = False; exhausted = False; deepest = 0; reasons = []
    while q:
        if time.perf_counter() - t0 > deadline_s: exhausted = True; reasons.append("DEADLINE"); break
        n, d = q.popleft(); deepest = max(deepest, d)
        if n not in g.modeled: unknown = True; reasons.append("UNMODELED " + str(n)); continue
        if expanded >= max_nodes: exhausted = True; reasons.append("NODE_BUDGET"); break
        expanded += 1
        if d >= max_depth:
            if g.edges.get(n): exhausted = True; reasons.append("DEPTH_BUDGET")
            continue
        for dst, kind, trust in g.edges.get(n, []):
            if trust not in accept_trust: unknown = True; reasons.append("UNVERIFIED_EDGE %s->%s (%s)" % (n, dst, trust))
            if dst not in seen: seen.add(dst); q.append((dst, d + 1))
    return Result(seen - {start}, unknown or exhausted, exhausted, expanded, deepest, round((time.perf_counter() - t0) * 1000, 3), sorted(set(reasons))[:6])


def verdict(res: Result, forbidden: set) -> str:
    """DENY if a forbidden destination is reachable; UNKNOWN if the search could not be completed or relied on unverified edges; otherwise ALLOW (for the modeled graph only)."""
    if res.reached & forbidden: return "DENY"
    return "UNKNOWN" if res.unknown else "ALLOW"


def from_emergence(eps) -> Graph:
    """Build a reach graph from a HorizonEmergence Endpoints world: an endpoint that delegates (redirects) to a parameter-supplied URL can reach every other endpoint; an unmodeled endpoint is an unmodeled node."""
    g = Graph(); ports = eps.ports
    for role, port in ports.items():
        s = eps.by_port[port]
        if not s.modeled: continue
        g.modeled.add(role)
        if s.delegates:
            for other, p2 in ports.items():
                if other != role: g.add(role, other, "redirect", "attested")
    return g
