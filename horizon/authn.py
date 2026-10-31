"""HMAC event signing with bounded replay window and per-run sequence enforcement (P1-19)."""
from __future__ import annotations
import hashlib, hmac, json, time
from collections import OrderedDict


def canonical_bytes(event: dict) -> bytes:
    e = {k: v for k, v in event.items() if k != "sig"}
    return json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sign_event(key: bytes, key_id: str, event: dict) -> dict:
    mac = hmac.new(key, key_id.encode() + b"\x1f" + canonical_bytes(event), hashlib.sha256).hexdigest()
    return {**event, "sig": {"key_id": key_id, "mac": mac}}


class ReplayGuard:
    """Rejects bad MACs, stale/future timestamps, duplicate event ids and non-increasing seq per run.
    State is in-memory and bounded (LRU); a restart forgets history, so persist it in a protected store for production."""

    def __init__(self, keys: dict[str, bytes], max_skew_s: float = 30.0, max_ids: int = 100_000):
        self.keys, self.skew, self.max_ids = keys, max_skew_s, max_ids
        self.ids: OrderedDict[str, None] = OrderedDict(); self.seq: dict[str, int] = {}

    def verify(self, signed: dict, now: float | None = None, parse_time=None) -> str | None:
        """Return None if accepted, else a reason string. Accepting records the event (single use)."""
        now = time.time() if now is None else now
        sig = signed.get("sig")
        if not isinstance(sig, dict) or sig.get("key_id") not in self.keys: return "unknown or missing key_id"
        want = hmac.new(self.keys[sig["key_id"]], sig["key_id"].encode() + b"\x1f" + canonical_bytes(signed), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(sig.get("mac", "")), want): return "bad MAC"
        import calendar, re
        m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z", signed.get("wall_time", ""))
        if not m: return "bad wall_time"
        t = calendar.timegm(tuple(int(x) for x in m.groups()) + (0, 0, 0))
        if abs(now - t) > self.skew: return "timestamp outside replay window"
        eid, run, seq = signed["event_id"], signed["run_id"], signed["monotonic_seq"]
        if eid in self.ids: return "replayed event_id"
        if seq <= self.seq.get(run, -1): return "non-monotonic sequence for run"
        self.ids[eid] = None; self.seq[run] = seq
        while len(self.ids) > self.max_ids: self.ids.popitem(last=False)
        return None
