"""Enforcement at the charged sinks (P50-08) and the compared accounting strategies (P50-13).
Four carriers (MCP, UTCP, Code Mode, OS/effect broker) are normalized by `decode` into the same (context, tool, args); the cost is then derived from the tool registry and charged to ONE ledger, so switching carrier or spawning an agent cannot create a new allowance.
These are carrier-level codecs, not hooks in the real MCP/UTCP/Code Mode adapters (the same boundary P45 documents)."""
import base64, json, threading, time
from . import units as U

HEADER, META = "X-Horizon-Budget", "horizon/budget"
CARRIERS = ("mcp", "utcp", "codemode", "os")


def encode(carrier, ctx, tool, args):
    if carrier == "mcp": return {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": tool, "arguments": args, "_meta": {META: ctx}}}
    if carrier == "utcp": return {"call_template": {"name": tool, "headers": {HEADER: base64.b64encode(json.dumps(ctx, sort_keys=True).encode()).decode()}, "body": args}}
    if carrier == "codemode": return {"binding": {"__budget": ctx}, "call": [tool, args]}
    if carrier == "os": return {"effect": {"tool": tool, "args": args}, "ctx": ctx}
    raise ValueError("unknown carrier")
def decode(carrier, msg):
    try:
        if carrier == "mcp": p = msg["params"]; return p["_meta"][META], p["name"], p["arguments"]
        if carrier == "utcp": t = msg["call_template"]; return json.loads(base64.b64decode(t["headers"][HEADER])), t["name"], t["body"]
        if carrier == "codemode": return msg["binding"]["__budget"], msg["call"][0], msg["call"][1]
        if carrier == "os": return msg["ctx"], msg["effect"]["tool"], msg["effect"]["args"]
    except (KeyError, TypeError, ValueError, IndexError): return None
    return None


def naive_cost(tool, args, policy=U.POLICY):
    """What the weaker accounting strategies use: no validation, so a negative amount lowers the counter."""
    t = policy["tools"].get(tool)
    if t is None: return None, 0
    cls, key = t
    try: return cls, (1 if key is None else int(args.get(key)))
    except (TypeError, ValueError): return cls, 0


class Broker:
    def __init__(self, kind, receiver, clock, ledger=None, caps=None, *, sink_cap=True, reconcile_charge=True, sync_every=5, gap=0.0, ttl=30.0, policy=U.POLICY):
        self.kind, self.rc, self.clock, self.led, self.caps, self.sink_cap, self.reconcile_charge, self.sync_every, self.gap, self.ttl, self.policy = kind, receiver, clock, ledger, caps or {}, sink_cap, reconcile_charge, sync_every, gap, ttl, policy
        self.cnt = {}; self.view = {}; self.delta = {}; self.n = 0; self.alerts = []; self._lk = threading.Lock(); self.log = []
    def _cap(self, task, cls): return self.caps.get(task, {}).get(cls, 0)
    def call(self, principal, msg, carrier):
        d = decode(carrier, msg)
        if d is None or not isinstance(d[0], dict): return {"status": "denied", "reason": "MALFORMED_CONTEXT"}
        ctx, tool, args = d; task, scope, rid = ctx.get("task"), ctx.get("scope"), ctx.get("rid")
        out = getattr(self, "_" + self.kind.replace("-", "_"))(principal, carrier, task, scope, rid, tool, args)
        self.log.append({"principal": principal, "carrier": carrier, "tool": tool, "status": out["status"], "reason": out.get("reason")}); return out
    def _run(self, tool, args, rid, task, max_units=None):
        cls, key = self.policy["tools"][tool]
        try: return self.rc.apply(tool, args, rid, task, cls, key, max_units)
        except TimeoutError: return None
    # ---- strategies ------------------------------------------------------------------------------------------------------------------------------------------------
    def _none(self, principal, carrier, task, scope, rid, tool, args):
        if tool not in self.policy["tools"]: return {"status": "denied", "reason": "UNKNOWN_TOOL"}
        r = self._run(tool, args, rid, task); return {"status": "timeout"} if r is None else {"status": "ok", "observed": r["observed"]}
    def _gated(self, key, principal, carrier, task, rid, tool, args, post=False):
        cls, n = naive_cost(tool, args, self.policy)
        if cls is None: return {"status": "denied", "reason": "UNKNOWN_TOOL"}
        if not post:
            with self._lk:                                                                                     # atomic check-and-increment: this strategy's weakness is its SCOPE, not a race
                cur = self.cnt.get(key + (cls,), 0)
                if cur + n > self._cap(task, cls): return {"status": "denied", "reason": "BUDGET_EXCEEDED"}
                self.cnt[key + (cls,)] = cur + n
            r = self._run(tool, args, rid, task); return {"status": "timeout"} if r is None else {"status": "ok", "observed": r["observed"]}
        r = self._run(tool, args, rid, task)
        with self._lk: self.cnt[key + (cls,)] = self.cnt.get(key + (cls,), 0) + n
        if post and self.cnt[key + (cls,)] > self._cap(task, cls): self.alerts.append((task, cls, self.cnt[key + (cls,)]))
        return {"status": "timeout"} if r is None else {"status": "ok", "observed": r["observed"]}
    def _per_agent(self, principal, carrier, task, scope, rid, tool, args): return self._gated((principal, task), principal, carrier, task, rid, tool, args)
    def _per_protocol(self, principal, carrier, task, scope, rid, tool, args): return self._gated((carrier, task), principal, carrier, task, rid, tool, args)
    def _per_tool(self, principal, carrier, task, scope, rid, tool, args): return self._gated((tool, task), principal, carrier, task, rid, tool, args)
    def _posthoc(self, principal, carrier, task, scope, rid, tool, args): return self._gated(("all", task), principal, carrier, task, rid, tool, args, post=True)
    def _eventual(self, principal, carrier, task, scope, rid, tool, args):
        """Replicated counter: admission reads a view refreshed every `sync_every` calls; effects are merged on refresh."""
        cls, n = naive_cost(tool, args, self.policy)
        if cls is None: return {"status": "denied", "reason": "UNKNOWN_TOOL"}
        with self._lk:
            self.n += 1
            if self.n % self.sync_every == 1:
                for k, v in self.delta.items(): self.view[k] = self.view.get(k, 0) + v
                self.delta = {}
            seen = self.view.get((task, cls), 0)
        if seen + n > self._cap(task, cls): return {"status": "denied", "reason": "BUDGET_EXCEEDED"}
        r = self._run(tool, args, rid, task)
        with self._lk: self.delta[(task, cls)] = self.delta.get((task, cls), 0) + n
        return {"status": "timeout"} if r is None else {"status": "ok", "observed": r["observed"]}
    def _budget(self, principal, carrier, task, scope, rid, tool, args):
        try: cost = U.cost_of(tool, args, self.policy)
        except U.CostError as e: return {"status": "denied", "reason": str(e)}
        if not isinstance(rid, str) or not rid: return {"status": "denied", "reason": "NO_REQUEST_ID"}
        q = U.digest([tool, args]); res = self.led.reserve(scope, principal, rid, q, cost, self.ttl)
        if not res["ok"]: return {"status": "denied", "reason": res["reason"]}
        if res.get("replayed") and res["state"] == "COMMITTED": return {"status": "ok", "replayed": True, "observed": self.led.info(rid)["observed"]}
        if res["state"] == "RESERVED":
            s = self.led.start(rid)
            if not s["ok"]: return {"status": "denied", "reason": s["reason"]}
        r = self._run(tool, args, rid, task, max_units=cost if self.sink_cap else None)
        if r is None: return {"status": "timeout", "rid": rid}                                              # stays STARTED -> UNKNOWN after ttl: still charged
        c = self.led.commit(rid, r["observed"] if self.reconcile_charge else cost)
        return {"status": "ok", "observed": r["observed"], "overrun": c.get("overrun")}
    def reconcile(self, rid):
        """Ask the independent receiver what happened to a request that timed out; unreachable telemetry leaves the reservation charged."""
        return self.led.reconcile(rid, self.rc.observe(rid))
    def spawn(self, parent_scope, parent_principal, child_scope, child_principal, caps, mode="attenuate"):
        if self.kind == "budget":
            ps = self.led._scope(parent_scope)
            if ps is None or (self.led.bind_principal and ps["principal"] != parent_principal): return {"ok": False, "reason": "NOT_SCOPE_PRINCIPAL"}
            return self.led.delegate(parent_scope, child_scope, child_principal, caps, mode)
        return {"ok": True, "cap": caps}
