"""Experiment harness (P50-09..13): the same world for every system. Budgets are assigned through the owner role of the shared HorizonPolicy authority; the oracle reads only the receiver's own counters."""
import os, shutil, tempfile, threading
from dataclasses import dataclass, field
from ..hpolicy.authority import HorizonPolicy, EvidenceError
from . import units as U, broker as B
from .ledger import Ledger
from .sinks import Receiver

BASE = 1_000_000.0
class Clock:
    def __init__(self): self.t = BASE
    def __call__(self): return self.t
    def advance(self, s): self.t += s


@dataclass(frozen=True)
class Sys:
    name: str; kind: str; led: tuple = (); brk: tuple = (); rc: tuple = ()
def systems():
    S = [Sys("none", "none"), Sys("per-agent-cap", "per_agent"), Sys("eventual-counter", "eventual"), Sys("post-hoc-alert", "posthoc"), Sys("single-protocol-limiter", "per_protocol"), Sys("per-tool-cap", "per_tool"), Sys("budget", "budget")]
    A = {"atomic": (("atomic", False), ("gap", 0.03)), "attenuation": (("attenuate", False),), "ancestors": (("ancestors", False),), "idempotency": (("idempotent", False),), "conservative": (("conservative", False),), "signature": (("signed", False),), "principal-binding": (("bind_principal", False),)}
    for n, kw in A.items(): S.append(Sys("budget-no-" + n, "budget", kw, rc=(("idempotent", False),) if n == "idempotency" else ()))
    S.append(Sys("budget-no-sink-cap", "budget", brk=(("sink_cap", False),))); S.append(Sys("budget-no-reconcile", "budget", brk=(("sink_cap", False), ("reconcile_charge", False))))
    return S


class Env:
    def __init__(self, sysm: Sys):
        self.sys, self.clock, self.dir = sysm, Clock(), tempfile.mkdtemp(prefix="p50-"); self.auth = HorizonPolicy("pol-1", clock=self.clock); self.owner = self.auth.register_issuer("owner", {"ATTESTATION"}); self.rogue = self.auth.register_issuer("ci", {"ATTESTATION"})
        self.rc = Receiver(**dict(sysm.rc)); self.limits = {}; self.attempts = []; self.ver = {}
        self.led = Ledger(os.path.join(self.dir, "l.db"), self.auth.verifier(), self.clock, **dict(sysm.led)) if sysm.kind == "budget" else None
        self.broker = B.Broker(sysm.kind, self.rc, self.clock, self.led, caps={}, **dict(sysm.brk))
    def close(self):
        if self.led: self.led.close()
        shutil.rmtree(self.dir, ignore_errors=True)
    def token(self, task, limits, principal, rev=3, ver=1, issuer=None):
        c = {"type": "budget", "task": task, "limits": limits, "rev": rev}
        return (issuer or self.owner).issue("ATTESTATION", principal=principal, artifact=task, args_digest=U.digest(c), object_version=ver, claim=c, ttl=10 ** 7, now=int(self.clock.t))
    def open(self, task, limits, principal, **kw):
        """Legitimate budget assignment: recorded as the declared cap the oracle checks effects against."""
        self.limits[task] = dict(limits); self.broker.caps[task] = dict(limits)
        if self.led: self.led.open_task(self.token(task, limits, principal, **kw))
        return Agent(self, principal, task, task)
    def try_open(self, token):
        if not self.led: return False
        try: self.led.open_task(token); return True
        except EvidenceError: return False
    def over(self):
        """Oracle: effects the receiver really performed above the declared caps (a task with no legitimate budget has cap 0)."""
        tasks = {e["task"] for e in self.rc.effects} | set(self.limits); out = []
        for t in sorted(tasks):
            for c in U.CLASSES:
                tot = self.rc.total(t, c); cap = self.limits.get(t, {}).get(c, 0)
                if tot > cap: out.append({"task": t, "cls": c, "total": tot, "cap": cap})
        return out


class Agent:
    def __init__(self, env, principal, task, scope): self.env, self.p, self.task, self.scope = env, principal, task, scope; self.n = 0
    def call(self, carrier, tool, args, rid=None, expect=False, scope=None, task=None):
        self.n += 1; rid = rid or "%s-%s-%d" % (self.task, self.p, self.n)
        msg = B.encode(carrier, {"task": task or self.task, "scope": scope or self.scope, "agent": self.p, "rid": rid}, tool, args); out = self.env.broker.call(self.p, msg, carrier)
        self.env.attempts.append({"agent": self.p, "carrier": carrier, "tool": tool, "status": out["status"], "reason": out.get("reason"), "expect": expect, "rid": rid}); out["rid"] = rid; return out
    def spawn(self, name, caps, mode="attenuate"):
        r = self.env.broker.spawn(self.scope, self.p, name, name, caps, mode)
        return Agent(self.env, name, self.task, name) if r.get("ok") else None
