"""Token-bucket rate limiter and circuit breaker (P3-12)."""
from __future__ import annotations
import threading


class RateLimiter:
    def __init__(self, rate: float, burst: int, clock):
        self.rate, self.burst, self.clock, self.b, self.l = rate, burst, clock, {}, threading.Lock()

    def allow(self, key: str) -> bool:
        with self.l:
            now = self.clock(); tokens, last = self.b.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1: self.b[key] = (tokens, now); return False
            self.b[key] = (tokens - 1, now); return True


class Breaker:
    """Opens after `threshold` consecutive failures; while open, callers must fail closed for protected effects."""
    def __init__(self, threshold: int, cooldown: float, clock):
        self.t, self.cd, self.clock, self.fails, self.opened_at, self.l = threshold, cooldown, clock, 0, None, threading.Lock()

    def is_open(self) -> bool:
        with self.l:
            if self.opened_at is None: return False
            if self.clock() - self.opened_at >= self.cd: self.opened_at, self.fails = None, 0; return False   # half-open: allow a probe
            return True

    def record(self, ok: bool) -> None:
        with self.l:
            if ok: self.fails = 0; return
            self.fails += 1
            if self.fails >= self.t: self.opened_at = self.clock()
