"""World, step vocabulary and the deterministic interleaving explorer (P52-09). A scenario gives each actor a list of atomic steps; the explorer enumerates EVERY interleaving that keeps each actor's order and the declared
happens-before constraints, runs the system under test on a fresh world for each, and judges the final server-side record with the independent oracle. A dispatch step is one step when the gateway and the sink share a
transaction and two steps (check, then apply) otherwise, so a mutation can fall between check and use."""
import itertools
from ..hpolicy.authority import HorizonPolicy
from . import core as C
from .store import Store
from .net import Net
from .approver import Approver
from .oracle import judge

class World:
    def __init__(self, ex, sc):
        self.t = [1_000_000.0]; self.clock = lambda: self.t[0]; self.skew = sc.get("worker_skew", 0); self.ex = ex
        self.A = HorizonPolicy("pol-1", clock=self.clock); self.iss = self.A.register_issuer("approver", {"APPROVAL"}); self.verifier = self.A.verifier()
        self.store = Store(self.clock); self.net = Net(); self.approver = Approver(self.iss, self.store, self.net, self.clock)
        self.tokens, self.done, self.results, self.ctx, self.pending = {}, {}, [], {}, []
        self.sink_atomic, self.deferred, self.telemetry_up = sc.get("sink_atomic", True), sc.get("deferred", False), sc.get("telemetry", True)
        for i, b in C.RULES0.items(): self.store.set_rule(i, b)
        for p, sc_ in (("agentA", "export"), ("agentB", "export"), ("officer", "export"), ("officer", "restricted-export")): self.store.grant(p, sc_)
        self.store.put_object("doc1", "PUBLIC", "quarterly figures v1"); self.store.put_object("doc2", "INTERNAL", "team roster"); self.store.put_object("doc3", "PUBLIC", "press kit")
        sc["setup"](self) if sc.get("setup") else None
    def worker_clock(self): return self.t[0] + self.skew

def call(label, fn): return {"label": label, "kind": "call", "fn": fn}
def approve(actor, obj, host, key="t", ttl=60, label="approve"): return call(label, lambda w: w.tokens.__setitem__(key, w.approver.request(actor, obj, host, ttl)))
def wait(s, label="wait"): return call(label, lambda w: w.t.__setitem__(0, w.t[0] + s))
def dispatch(caller, obj, host, rid, key="t", reapprove=False, queued=False, label="dispatch"): return {"label": label, "kind": "dispatch", "caller": caller, "obj": obj, "host": host, "rid": rid, "key": key, "reapprove": reapprove, "queued": queued}
def write(caller, obj, base, content, label): return call(label, lambda w: w.ex.write(w, caller, obj, base, content))
def provider_flush(label="flush"): return call(label, lambda w: _flush(w))
def _flush(w):
    for k, host, ip, final in w.pending: w.store.apply_export(k["actor"], k["obj"], host, ip, final, k["approval"])
    w.pending.clear()

def expand(prog, ex, w):
    out = []
    for s in prog:
        if s["kind"] != "dispatch": out.append(s); continue
        n = ex.phases(w)
        def p1(w, s=s):
            act = {"op": "export", "obj": s["obj"], "host": s["host"], "queued": s["queued"]}; ctx = ex.begin(w, w.tokens.get(s["key"]), s["caller"], act, s["rid"])
            if s["reapprove"] and "final" in ctx and ctx["final"]["status"] == "DENIED" and ctx["final"]["reason"] not in ("NO_TOKEN",):
                w.results.pop(); w.tokens[s["key"]] = w.approver.request(s["caller"], s["obj"], s["host"]); w.reapprovals = getattr(w, "reapprovals", 0) + 1; ctx = ex.begin(w, w.tokens.get(s["key"]), s["caller"], act, s["rid"])
            w.ctx[s["label"] + s["rid"]] = ctx
        def p2(w, s=s): ex.finish(w, w.ctx[s["label"] + s["rid"]])
        out.append({"label": s["label"] + "#1", "kind": "call", "fn": p1})
        if n == 2: out.append({"label": s["label"] + "#2", "kind": "call", "fn": p2})
    return out

def interleavings(actors, before):
    names = list(actors); out = []
    def rec(pos, done, path):
        if all(pos[n] == len(actors[n]) for n in names): out.append(list(path)); return
        for n in names:
            if pos[n] < len(actors[n]):
                lab = actors[n][pos[n]]["label"]
                if any(b == lab and a not in done for a, b in before): continue
                pos[n] += 1; path.append((n, lab)); done.add(lab); rec(pos, done, path); done.discard(lab); path.pop(); pos[n] -= 1
    rec({n: 0 for n in names}, set(), []); return out

def run_order(sc, ex, order):
    w = World(ex, sc); progs = {n: expand(p, ex, w) for n, p in sc["actors"].items()}; idx = {n: 0 for n in progs}
    for n, lab in order:
        st = progs[n][idx[n]]; assert st["label"] == lab; st["fn"](w); idx[n] += 1
    return w

def explore(sc, ex):
    w0 = World(ex, sc); progs = {n: expand(p, ex, w0) for n, p in sc["actors"].items()}; orders = interleavings(progs, sc.get("before", [])); res = []
    for o in orders:
        w = run_order(sc, ex, o); j = judge(w.store); eff = w.store.effects()
        done = all(any(e["actor"] == x["actor"] and e["obj"] == x["obj"] and e["host"] == x["host"] for e in eff) for x in sc.get("expect", [])) and all((w.store.obj(k) or {"version": -1})["version"] == v for k, v in sc.get("versions", {}).items())
        if sc.get("single", False): done = done and len(eff) == len(sc.get("expect", []))
        res.append({"order": [l for _, l in o], "violations": j, "harm": any(x["harm"] for x in j), "completed": done, "unknown": any(r["status"] == "UNKNOWN" for r in w.results), "denials": [r["reason"] for r in w.results if r["status"] == "DENIED"], "effects": len(eff), "reapprovals": getattr(w, "reapprovals", 0), "lookups": w.net.lookups})
    return res
