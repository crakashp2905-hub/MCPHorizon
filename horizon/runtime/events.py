"""Security event rate controls, alert deduplication and redaction auditing (P30-13). A flood of identical attempts must not (a) drown the log, (b) hide the first occurrence, or (c) leak a secret
through an event field. Suppressed events are COUNTED, never silently dropped."""
from __future__ import annotations
import hashlib, json, time
from horizon.runtime import schema as SC


class EventSink:
    def __init__(self, *, rate_per_s=20.0, burst=40, dedup_window_s=30.0, clock=time.monotonic):
        self.rate, self.burst, self.win, self.clock = rate_per_s, burst, dedup_window_s, clock
        self.buckets, self.seen, self.out, self.stats = {}, {}, [], {"accepted": 0, "deduped": 0, "rate_limited": 0, "redactions": 0, "redaction_rejects": 0}
    @staticmethod
    def fingerprint(e: dict) -> str:
        core = {k: e.get(k) for k in ("kind", "layer", "origin")} | {"principal": e.get("authority", {}).get("principal"), "status": e.get("enforcement_result", {}).get("status"), "decision": e.get("policy_decision", {}).get("decision")}
        return hashlib.sha256(json.dumps(core, sort_keys=True, default=str).encode()).hexdigest()[:16]
    def _scrub(self, e: dict) -> dict | None:
        txt = json.dumps(e, default=str); clean, hits = SC.redact(txt)
        if hits:
            self.stats["redactions"] += len(hits)
            try: e = json.loads(clean)
            except ValueError: self.stats["redaction_rejects"] += 1; return None
            e.setdefault("redaction_audit", []).extend(sorted(set(hits)))
        return e
    def emit(self, e: dict) -> str:
        e = self._scrub(dict(e))
        if e is None: return "REJECTED"
        now = self.clock(); fp = self.fingerprint(e); seen = self.seen.get(fp)
        if seen and now - seen["t0"] < self.win:
            seen["n"] += 1; self.stats["deduped"] += 1; return "DEDUPED"
        key = (e.get("authority", {}).get("principal"), e.get("kind")); b = self.buckets.setdefault(key, {"tok": float(self.burst), "t": now})
        b["tok"] = min(self.burst, b["tok"] + (now - b["t"]) * self.rate); b["t"] = now
        if b["tok"] < 1: self.stats["rate_limited"] += 1; self.seen[fp] = seen or {"t0": now, "n": 0}; return "RATE_LIMITED"
        b["tok"] -= 1; self.seen[fp] = {"t0": now, "n": 1}; self.out.append(e); self.stats["accepted"] += 1; return "ACCEPTED"
    def summary(self) -> dict:
        """Totals always reconcile: accepted + deduped + rate_limited + rejected == emitted."""
        suppressed = sum(v["n"] - 1 for v in self.seen.values() if v["n"] > 1)
        return {**self.stats, "suppressed_repeats_recorded": suppressed}
