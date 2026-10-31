"""Ground-truth oracle (P7-13, P7-15). MEASUREMENT ONLY. Plants synthetic canary secrets and reports whether canary BYTES (raw or re-encoded) appear in
what actually left. It is never imported by gates or the detector; fixtures' truth annotations are stripped before anything deployable sees them."""
from __future__ import annotations
import hashlib, secrets
from .detect import variants

TRUTH_KEYS = {"_truth", "malicious", "expected", "poison", "suppressor", "oracle", "canary_id"}


def canary(kind: str = "api") -> str: return f"CANARY-{kind}-" + secrets.token_hex(12)


def strip_truth(o):
    """Remove every fixture-truth annotation before a fixture is handed to the system under test."""
    if isinstance(o, dict): return {k: strip_truth(v) for k, v in o.items() if k not in TRUTH_KEYS}
    if isinstance(o, list): return [strip_truth(v) for v in o]
    return o


class Oracle:
    def __init__(self): self.canaries: dict[str, str] = {}; self.sent: list[dict] = []
    def plant(self, name: str, kind: str = "api") -> str: v = canary(kind); self.canaries[name] = v; return v
    def observe(self, channel: str, payload: bytes) -> list[str]:
        """Record bytes that left the system boundary and return which canaries they contain."""
        hit = sorted(n for n, v in self.canaries.items() if any(v.encode() in x for x in variants(payload)))
        self.sent.append({"channel": channel, "sha": hashlib.sha256(payload).hexdigest()[:16], "leaked": hit}); return hit
    def leaked(self) -> set: return {n for s in self.sent for n in s["leaked"]}
