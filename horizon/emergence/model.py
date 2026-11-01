"""Bounded labeled transition model + effect-based violation checker + guided search (P39-03..08)."""
from __future__ import annotations
import random, urllib.parse
from dataclasses import dataclass, field
from .summaries import (PUB, ENC, SEC, RANK, join, OpSummary, EndpointSummary, library_summaries, serialize_summaries, canon, digest, ABSTRACTION_VERSION)

MAX_DEPTH, MAX_VARS, MAX_BRANCH = 4, 4, 64          # P39-04 caps


class Endpoints:
    """Concrete endpoint ports for one world plus the analyst's knowledge of them."""
    def __init__(self, a, b, c, *, known_c=False, a_redirect_known=True):
        self.ports = {"A": a, "B": b, "C": c}
        self.by_port = {a: EndpointSummary("partner", a, True, (("/redir", "to"),) if a_redirect_known else (), True),
                        b: EndpointSummary("external", b, True, (), False),
                        c: EndpointSummary("other", c, known_c, (("/redir", "to"),) if known_c else (), False)}
        # NOTE: the real receiver redirects on EVERY port for /redir. The model only knows what it was told.
    def targets(self):
        """name -> (method-agnostic url template with {v}); a template is rendered per step."""
        a, b, c = self.ports["A"], self.ports["B"], self.ports["C"]
        h = "http://127.0.0.1:%d" % 0
        return {"A/ingest": lambda v: "http://127.0.0.1:%d/ingest?d=%s" % (a, urllib.parse.quote(v, safe="")),
                "A/redir->B": lambda v: "http://127.0.0.1:%d/redir?to=http://127.0.0.1:%d/c?d=%s" % (a, b, urllib.parse.quote(v, safe="")),
                "B/c": lambda v: "http://127.0.0.1:%d/c?d=%s" % (b, urllib.parse.quote(v, safe="")),
                "C/redir->B": lambda v: "http://127.0.0.1:%d/redir?to=http://127.0.0.1:%d/c?d=%s" % (c, b, urllib.parse.quote(v, safe="")),
                "C/x": lambda v: "http://127.0.0.1:%d/x?d=%s" % (c, urllib.parse.quote(v, safe=""))}


ALL_TARGETS = ("A/ingest", "A/redir->B", "B/c", "C/redir->B", "C/x")
POLICY_ALLOWED_HOSTS = ("A", "C")      # direct-call policy: any call must address partner A or other-partner C (never B)


def direct_allowed(target: str) -> bool:
    """The direct-call policy looks only at the host the call addresses."""
    return target.split("/")[0] in POLICY_ALLOWED_HOSTS


def chain_of(url: str, eps: Endpoints):
    """Resolve delegated remote effects: list of (port, path, known) hops reached by a request to `url`. unknown=True if a hop's delegation behavior is not modeled."""
    hops, unknown, cur, seen = [], False, url, 0
    while cur and seen < 4:
        u = urllib.parse.urlsplit(cur); port = u.port; es = eps.by_port.get(port)
        hops.append((port, u.path, es.modeled if es else False))
        if es is None or not es.modeled: unknown = True; break
        nxt = None
        for pref, param in es.delegates:
            if u.path.startswith(pref):
                raw = cur.split(param + "=", 1)[1] if (param + "=") in cur else ""
                nxt = raw or None
        cur = nxt; seen += 1
    return hops, unknown


@dataclass
class Step:
    op: str; args: tuple = (); target: str = ""; out_taint: str = PUB; in_taint: str = PUB; url: str = ""; chain: tuple = (); unknown: bool = False; violation: bool = False
    def d(self): return {"op": self.op, "args": list(self.args), "target": self.target, "in_taint": self.in_taint, "out_taint": self.out_taint, "url": self.url, "chain": [list(h) for h in self.chain], "unknown": self.unknown, "violation": self.violation}


def apply_transform(summary: OpSummary, t: str) -> str:
    if summary.transform == "sanitize": return PUB
    if summary.transform == "encode": return ENC if t != PUB else PUB
    if summary.transform == "identity": return t
    return t        # 'unknown' transform: conservative, taint preserved


def step_effect(vars_taint, st: Step, eps: Endpoints, sums) -> Step:
    """Effect of a sink step: resolve the delegated chain and check it against the policy ('protected data may only reach secure sinks'). Not a function of tool names."""
    v = "X" * 4                                      # abstract value placeholder; the URL structure is what matters
    url = eps.targets()[st.target](v)
    hops, unknown = chain_of(url, eps)
    st.url, st.chain, st.unknown = url, tuple(hops), unknown
    tt = st.in_taint
    bad_known = [h for h in hops if h[2] and not eps.by_port[h[0]].secure_sink]
    st.violation = RANK[tt] > 0 and bool(bad_known)
    return st


def slice_steps(steps):
    """Backward dataflow slice from the final sink step (drops steps that do not feed it); remaps variable indices. Candidates are minimal and deduplicated by slice."""
    vid, last = [], steps[-1]; owner = {}
    n = 0
    for i, s in enumerate(steps[:-1]): owner[n] = i; n += 1
    keep, need = set(), set(last.args)
    for i in range(len(steps) - 2, -1, -1):
        pass
    want = [owner[a] for a in last.args if a in owner]; keep = set()
    while want:
        i = want.pop()
        if i in keep: continue
        keep.add(i); want += [owner[a] for a in steps[i].args if a in owner]
    order = sorted(keep); newidx = {i: k for k, i in enumerate(order)}; remap = {a: newidx[owner[a]] for a in owner if owner[a] in newidx}
    out = []
    for i in order:
        s = steps[i]; out.append(Step(s.op, tuple(remap[a] for a in s.args), s.target, s.out_taint, s.in_taint, s.url, s.chain, s.unknown, s.violation))
    l = Step(last.op, tuple(remap[a] for a in last.args if a in remap), last.target, last.out_taint, last.in_taint, last.url, last.chain, last.unknown, last.violation)
    return out + [l]


def actions(vars_taint, sums, eps, allowed_only=True, targets=None):
    acts = []
    for n in ("read_secret", "read_note"):
        if n in sums: acts.append(Step(n, (), "", sums[n].out_taint))
    for n in ("b64", "hash", "redact", "weak_sanitize"):
        if n in sums:
            for i, t in enumerate(vars_taint): acts.append(Step(n, (i,), "", apply_transform(sums[n], t), t))
    for n in ("get", "post"):
        if n in sums:
            for tg in (targets or ALL_TARGETS):
                if n == "post" and "redir" in tg: continue
                if allowed_only and not direct_allowed(tg): continue
                for i, t in enumerate(vars_taint): acts.append(Step(n, (i,), tg, PUB, t))
    return acts


@dataclass
class Candidate:
    steps: list; status: str      # VIOLATION | UNKNOWN
    def d(self): return {"status": self.status, "steps": [s.d() for s in self.steps]}
    def key(self): return digest(self.d())


def search(sums, eps, *, budget=200, seed=0, guided=True, max_depth=MAX_DEPTH, allowed_only=True, targets=None):
    """Bounded BFS over abstract states (taints of live variables). `budget` caps evaluated (state, action) transitions. Returns dict(candidates, unknowns, evaluated, truncated, states).
    Abstract state = tuple of var taints (cycle detection: a state is expanded once; MAX_VARS/MAX_DEPTH/MAX_BRANCH cap growth)."""
    rng = random.Random(seed); frontier = [((), (), [])]; seen = {frozenset()}; evaluated = 0; cands, unk, trunc = [], [], False; dk = set()
    for depth in range(max_depth):
        nxt = []
        for vt, ve, path in frontier:
            acts = actions(vt, sums, eps, allowed_only, targets)
            if guided:      # constraint-guided: tainted data first, sinks on tainted data before anything else
                acts.sort(key=lambda s: (0 if s.op in ("get", "post") and s.in_taint != PUB else 1 if s.op == "read_secret" else 2 if s.op in ("b64", "weak_sanitize", "hash", "redact") else 3, rng.random()))
            else: rng.shuffle(acts)
            for a in acts[:MAX_BRANCH]:
                if evaluated >= budget: return {"candidates": cands, "unknowns": unk, "evaluated": evaluated, "truncated": True, "states": len(seen)}
                evaluated += 1
                a = Step(**{k: getattr(a, k) for k in ("op", "args", "target", "out_taint", "in_taint")})
                if a.op in ("get", "post"):
                    step_effect(vt, a, eps, sums)
                    if a.violation: c = Candidate(slice_steps(path + [a]), "VIOLATION"); (cands.append(c) if c.key() not in dk else None); dk.add(c.key())
                    elif a.unknown and RANK[a.in_taint] > 0: c = Candidate(slice_steps(path + [a]), "UNKNOWN"); (unk.append(c) if c.key() not in dk else None); dk.add(c.key())
                    continue
                ex = a.op + "(" + ",".join(ve[i] for i in a.args) + ")"
                nv, ne = vt + (a.out_taint,), ve + (ex,)
                if len(nv) > MAX_VARS or frozenset(ne) in seen: continue
                seen.add(frozenset(ne)); nxt.append((nv, ne, path + [a]))
        frontier = nxt
        if not frontier: break
    return {"candidates": cands, "unknowns": unk, "evaluated": evaluated, "truncated": False, "states": len(seen)}


def refine(sums: dict, op: str, evidence_digest: str, scope: str = "oracle-variant-set/v1") -> dict:
    """Abstraction refinement (P39-08): an independent oracle disproved a candidate that relied on `op` preserving taint. Reclassify `op` as a sanitizer FOR THIS SCOPE and record the evidence.
    This is evidence-scoped, not a proof that the op is safe against every decoder."""
    out = dict(sums); o = out[op]
    out[op] = OpSummary(o.name, o.kind, o.out_taint, "sanitize", o.principal, 0.6, "refined:oracle:" + evidence_digest[:12] + ":" + scope)
    return out


def serialize_model(sums, eps) -> str:
    return canon({"sums": serialize_summaries(sums), "eps": sorted((p, e.modeled, e.delegates, e.secure_sink) for p, e in eps.by_port.items()), "abs": ABSTRACTION_VERSION})


def oracle_blind(steps) -> bool:
    """The receiver's variant set does not cover nested encodings, so a leak through b64(b64(x)) would read as 'no leak'. Such candidates are NOT scored (neither TP nor FP)."""
    prod = {}
    n = 0
    for s in steps:
        if s.op in ("get", "post"): break
        prod[n] = s.op; n += 1
        if s.op == "b64" and prod.get(s.args[0]) == "b64": return True
    return False
