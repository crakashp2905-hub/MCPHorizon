"""Execution adapters and the systems that decide fallbacks (P46-07, P46-13).

Systems (all see the same candidate list, in the planner's preference order):
  guard            HorizonDowngrade engine: floor-bound, attested-profile, partial-order admission; REVIEW/BLOCK never executes.
  fixed-order      first candidate that responds (the 'preferred tool ordering' baseline).
  static-allowlist first candidate whose endpoint is on a design-time allowlist.
  tool-name-only   first candidate whose TOOL NAME was permitted, whichever server provides it.
  scripted-suggest first candidate by a similarity score fixed by the scenario author (a deterministic stand-in for 'generic LLM fallback suggestions'; no model is called).
Adapters: utcp (plain HTTP(S) call), mcp (JSON-RPC tools/call envelope), codemode (generated code runs in a namespace whose only network capability is `call`, which re-checks EVERY call, including fallbacks the code chooses by itself).
"""
import json, time, types
from . import engine as EG


class Timeout(Exception): pass


class System:
    name = "?"
    def pick(self, ctx, remaining, original): raise NotImplementedError
    def headers(self, world, ctx, cand): return {}


class Guard(System):
    name = "guard"
    def __init__(self, engine, broker, label="guard"): self.e, self.b, self.name = engine, broker, label
    def pick(self, ctx, remaining, original):
        ch = self.e.choose(ctx, remaining); d = ch["decision"]
        return {"action": ch["action"], "candidate": d.candidate if d else None, "decision": d, "evals": ch["evaluations"]}
    def headers(self, world, ctx, cand):
        h = {"Authorization": "Bearer " + self.b.issue(ctx, cand)}
        if self.e.reg.status(cand.endpoint) == "ATTESTED" and self.e.reg.vector(cand.endpoint).get("authn") == "api_key": h["X-Api-Key"] = world.api_key
        return h


class Naive(System):
    def __init__(self, name, broker, allow_endpoints=None, allow_tools=None, similarity=None): self.name, self.b, self.ae, self.at, self.sim = name, broker, allow_endpoints, allow_tools, similarity or {}
    def pick(self, ctx, remaining, original):
        c = remaining
        if self.ae is not None: c = [x for x in c if x.endpoint in self.ae]
        if self.at is not None: c = [x for x in c if x.tool in self.at]
        if self.sim: c = sorted(c, key=lambda x: -self.sim.get(x.id, 0))
        return {"action": "USE" if c else "BLOCK", "candidate": c[0] if c else None, "decision": None, "evals": []}
    def headers(self, world, ctx, cand):
        return {"Authorization": "Bearer " + self.b.issue(ctx, cand), "X-Api-Key": world.api_key}          # ordinary client: sends every credential it holds, scope as the agent asked


def wire(adapter, cand, payload):
    if adapter == "mcp": return json.dumps({"jsonrpc": "2.0", "id": cand.id, "method": "tools/call", "params": {"name": cand.tool, "arguments": {"op": cand.op, "payload": payload}}}).encode()
    return json.dumps({"op": cand.op, "payload": payload}).encode()


class Gateway:
    def __init__(self, world, system, adapter="utcp", timeout=0.5): self.w, self.s, self.adapter, self.timeout = world, system, adapter, timeout; self.attempts = []; self.sent = []
    def attempt(self, ctx, cand, payload, req_id, data_class):
        if cand.endpoint == "local_spool":
            self.attempts.append({"cand": cand.id, "status": 200, "local": True}); return 200
        h = {**self.s.headers(self.w, ctx, cand), "X-Req-Id": req_id, "X-Data-Class": data_class}; t0 = time.perf_counter()
        st, _ = self.w.request(cand.endpoint, wire(self.adapter, cand, payload), h, timeout=self.timeout); self.sent.append({"req_id": req_id, "endpoint": cand.endpoint})
        self.attempts.append({"cand": cand.id, "endpoint": cand.endpoint, "status": st, "ms": round((time.perf_counter() - t0) * 1000, 1)}); return st
    def run(self, ctx, primary, fallbacks, payload, data_class, req_prefix, approvals=None, original=None):
        """Try the primary; on failure consult the system for each next fallback. -> result dict (never raises)."""
        t0 = time.perf_counter(); res = {"completed": False, "used": None, "review": None, "blocked": 0, "decisions": [], "attempts": self.attempts}; n = 0
        st = self.attempt(ctx, primary, payload, "%s-%d" % (req_prefix, n), data_class); n += 1
        if st == 200: res.update(completed=True, used=primary.endpoint, ms=round((time.perf_counter() - t0) * 1000, 1), failed_over=False); return res
        remaining = list(fallbacks); t_fail = time.perf_counter()
        while remaining:
            p = self.s.pick(ctx, remaining, original or primary.endpoint); res["decisions"].append({"action": p["action"], "cand": p["candidate"].id if p["candidate"] else None, "evals": [e.d() for e in p["evals"]]})
            if p["action"] == "BLOCK": res["blocked"] += 1; break
            if p["action"] == "REVIEW":
                dec = p["decision"]; req = self.s.e.approval_request(ctx, dec, original or primary.endpoint); res["review"] = req; tok = (approvals or {}).get(dec.candidate.id)
                if tok is None: break
                ok, why = self.s.e.check_approval(tok, req, ctx.principal); res["approval"] = [ok, why]
                if not ok: break
            cand = p["candidate"]; st = self.attempt(ctx, cand, payload, "%s-%d" % (req_prefix, n), data_class); n += 1
            if st == 200: res.update(completed=True, used=cand.endpoint, ms=round((time.perf_counter() - t0) * 1000, 1), recovery_ms=round((time.perf_counter() - t_fail) * 1000, 1), failed_over=True); return res
            remaining = [c for c in remaining if c.id != cand.id]
        res["ms"] = round((time.perf_counter() - t0) * 1000, 1); return res

    # ---- Code Mode: generated code may choose fallbacks itself; every call is checked -----------------------------------------------------------------------------
    def run_codemode(self, ctx, source, cands, payload, data_class, req_prefix, original):
        by = {c.id: c for c in cands}; state = {"n": 0, "used": None, "calls": [], "denied": []}
        def call(cid):
            c = by[cid]; p = self.s.pick(ctx, [c], original); state["calls"].append({"cand": cid, "action": p["action"]})
            if p["action"] != "USE": state["denied"].append(cid); raise Timeout("denied by policy: %s" % p["action"])
            st = self.attempt(ctx, c, payload, "%s-%d" % (req_prefix, state["n"]), data_class); state["n"] += 1
            if st != 200: raise Timeout("endpoint failure")
            state["used"] = c.endpoint; return {"ok": True}
        ns = {"call": call, "Timeout": Timeout, "__builtins__": {"Exception": Exception}}; exec(compile(source, "<generated>", "exec"), ns)
        return {"completed": state["used"] is not None, "used": state["used"], "calls": state["calls"], "denied": state["denied"], "attempts": self.attempts}
