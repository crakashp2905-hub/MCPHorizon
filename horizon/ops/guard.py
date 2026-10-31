"""Bounded memory/CPU and event-rate protection (P10-10) and fail-closed decision wrapper with emergency mode (P10-11)."""
from __future__ import annotations
import json, resource, threading, time
from horizon.service.limits import RateLimiter


class Overload(Exception):
    def __init__(self, code, msg): super().__init__(msg); self.code = code


class ResourceGuard:
    def __init__(self, *, rate=50.0, burst=100, max_event_bytes=64_000, max_inflight=32, max_tenants=1000, clock=time.time):
        self.rl, self.max_bytes, self.max_inflight, self.max_tenants, self.inflight, self.l = RateLimiter(rate, burst, clock), max_event_bytes, max_inflight, max_tenants, 0, threading.Lock(); self.tenants = set()

    def admit(self, tenant: str, event) -> None:
        raw = event if isinstance(event, (bytes, str)) else json.dumps(event)
        if len(raw) > self.max_bytes: raise Overload("TOO_LARGE", "event exceeds size limit")
        if tenant not in self.tenants:
            if len(self.tenants) >= self.max_tenants: raise Overload("TENANT_LIMIT", "too many tenants (state bound)")
            self.tenants.add(tenant)
        if not self.rl.allow(tenant): raise Overload("RATE_LIMITED", "per-tenant event rate exceeded")

    def __enter__(self):
        with self.l:
            if self.inflight >= self.max_inflight: raise Overload("BUSY", "too many in-flight evaluations")
            self.inflight += 1
        return self

    def __exit__(self, *a):
        with self.l: self.inflight -= 1


def limit_process(*, cpu_s: int = 10, mem_mb: int = 512, files: int = 256):
    """Apply to a worker process (call in the child, e.g. preexec_fn)."""
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s)); resource.setrlimit(resource.RLIMIT_AS, (mem_mb << 20, mem_mb << 20)); resource.setrlimit(resource.RLIMIT_NOFILE, (files, files))


class FailClosed:
    """Wrap a gate's `decide`. Any exception, timeout, malformed answer or engaged emergency mode => DENY for protected effects. Only explicitly allowlisted read-only operations may pass in emergency mode."""
    PROTECTED = {"write", "modify", "delete", "execute", "send", "admin"}

    def __init__(self, decide, *, timeout_s: float = 2.0, emergency_read_allow: set | None = None):
        self.decide, self.timeout, self.emergency = decide, timeout_s, False; self.read_allow = set(emergency_read_allow or ()); self.stats = {"failclosed": 0, "ok": 0}

    def engage(self): self.emergency = True
    def release(self): self.emergency = False

    def __call__(self, body: dict) -> dict:
        eff, op = body.get("effect"), body.get("tool_id") or body.get("native_operation")
        if self.emergency and not (eff == "read" and op in self.read_allow): return self._deny("EMERGENCY_MODE")
        box = {}
        def run():
            try: box["r"] = self.decide(body)
            except BaseException as e: box["e"] = type(e).__name__
        t = threading.Thread(target=run, daemon=True); t.start(); t.join(self.timeout)
        if t.is_alive(): return self._deny("POLICY_SERVICE_TIMEOUT")
        if "e" in box: return self._deny("POLICY_SERVICE_ERROR")
        r = box["r"]
        if not isinstance(r, dict) or r.get("verdict") not in ("ALLOW", "DENY", "REVIEW", "UNKNOWN"): return self._deny("POLICY_SERVICE_MALFORMED")
        self.stats["ok"] += 1; return r

    def _deny(self, code):
        self.stats["failclosed"] += 1; return {"verdict": "DENY", "reason_codes": [code], "failed_closed": True}
