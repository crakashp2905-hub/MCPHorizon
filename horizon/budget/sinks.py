"""Synthetic budgeted receiver with independently verifiable effect counters (P50-09). It is the ground truth for what really happened: the agent and the broker cannot write to it, and the oracle reads only it.
Behaviours that matter for budgets: idempotency keys (a repeated request id applies once), a hard per-request unit cap supplied by the broker (`max_units`), effects that complete although the response is lost (`crash_after`), silent telemetry (`silent`), and a tool whose real effect can exceed what its arguments declare (`expand`)."""
import threading


class Receiver:
    def __init__(self, idempotent=True):
        self.idempotent, self._lk = idempotent, threading.Lock(); self.effects = []; self.by_rid = {}; self.silent = False; self.crash_after = set(); self.drop_before = set(); self.calls = 0
    def apply(self, tool, args, rid, task, cls, key, max_units=None):
        """-> {'observed': {cls: n}} or raises TimeoutError. The units applied are what the service really did."""
        with self._lk:
            self.calls += 1
            if rid in self.drop_before: self.drop_before.discard(rid); raise TimeoutError("request lost before reaching the service")
            if self.idempotent and rid in self.by_rid: return {"observed": dict(self.by_rid[rid]), "replayed": True}
            n = args.get(key) if key else 1
            n = n if isinstance(n, int) and not isinstance(n, bool) and n > 0 else 0                           # a negative or malformed amount does nothing at the service
            if args.get("expand"): n *= 50                                                                  # hidden fan-out: real effect exceeds the declared argument
            if max_units is not None: n = min(n, max_units.get(cls, 0))
            if n: self.effects.append({"rid": rid, "task": task, "cls": cls, "n": n, "tool": tool})
            self.by_rid[rid] = {cls: n}
            if rid in self.crash_after: self.crash_after.discard(rid); raise TimeoutError("response lost after the effect")
            return {"observed": {cls: n}}
    def observe(self, rid):
        """Independent per-request observation used for reconciliation; None when telemetry is unavailable."""
        with self._lk: return None if self.silent else dict(self.by_rid.get(rid, {}))
    def total(self, task, cls): return sum(e["n"] for e in self.effects if e["task"] == task and e["cls"] == cls)
