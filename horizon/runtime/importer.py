"""Offline importer for incident traces (P23-04/05/06/17). Trace text is untrusted INERT data: it is parsed, bounded, sanitized and mapped to events. Nothing from a trace is ever executed or fetched."""
from __future__ import annotations
import hashlib, hmac, json, re
from horizon.runtime import schema as SC

MAX_BYTES, MAX_RECORDS, MAX_FIELD = 8 << 20, 20000, 65536
URL = re.compile(r"(?i)\b(?:https?|wss?|ftp)://[^\s'\"<>)\]]+")
IP4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IP6 = re.compile(r"(?i)\[(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\]|\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b")
HOST = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|cloud|ai|co|xyz|app|info|sh|ru|cn)\b")
KINDS = [("network", re.compile(r"(?i)\b(curl|wget|nc|ncat|socat|ssh|scp|requests\.|urllib|http\.client|socket\.|telnet|ftp)\b|/dev/(tcp|udp)/|IO::Socket|\bAF_INET6?\b|asyncio\.open_connection")), ("metadata", re.compile(r"169\.254|metadata|latest/meta-data|instance-identity")), ("credential_read", re.compile(r"(?i)\.ssh|id_rsa|\.aws|credentials|keychain|ssh-agent|\.kube|\.netrc|\.env\b")),
         ("namespace", re.compile(r"(?i)\bunshare\b|\bnsenter\b|\bsetns\b|mount\s+-t|CLONE_NEW")), ("recon", re.compile(r"(?i)resolv\.conf|\benv\b|printenv|/proc/self/environ|\bifconfig\b|\bip\s+(a|addr|route)")), ("process", re.compile(r"(?i)\b(bash|sh|python3?|perl|ruby|node)\b\s+-c\b|\bsubprocess\b|os\.system"))]


class ImportError_(ValueError):
    def __init__(self, code, detail=""): super().__init__(f"{code}: {detail}"); self.code = code


class Sanitizer:
    """Replaces every live-looking destination with a stable local alias. Correspondence keeps a keyed digest of the source token, not the token, so the map can be audited but not used to recover the original."""
    def __init__(self, corpus_digest: str): self.key = hashlib.sha256(b"hz-corr|" + corpus_digest.encode()).digest(); self.alias, self.map = {}, []
    def _alias(self, kind, tok):
        d = hmac.new(self.key, tok.lower().encode(), hashlib.sha256).hexdigest()[:16]
        if d not in self.alias:
            a = f"sink-{len(self.alias) + 1:03d}.{ 'test' if kind != 'ip' else 'invalid'}"; self.alias[d] = a; self.map.append({"kind": kind, "alias": a, "source_hmac16": d, "source_len": len(tok)})
        return self.alias[d]
    def text(self, s: str) -> str:
        s = s[:MAX_FIELD]; s = "".join(c for c in s if c == "\n" or c == "\t" or ord(c) >= 32)
        s = URL.sub(lambda m: "http://" + self._alias("url", m.group(0).split("://", 1)[1].split("/")[0].split(":")[0]) + "/", s)
        s = IP6.sub(lambda m: self._alias("ip", m.group(0)), s); s = IP4.sub(lambda m: self._alias("ip", m.group(0)), s); s = HOST.sub(lambda m: self._alias("host", m.group(0)), s)
        return SC.redact(s)[0]


def load(path_or_bytes, *, preflight) -> tuple[list, str]:
    """Reads JSONL ONLY after an ok preflight token (P23-15). Returns (records, corpus_digest). Bounded and strict."""
    if not getattr(preflight, "ok", False): raise ImportError_("PREFLIGHT_REQUIRED", getattr(preflight, "reason", "no preflight"))
    raw = open(path_or_bytes, "rb").read(MAX_BYTES + 1) if isinstance(path_or_bytes, str) else bytes(path_or_bytes)
    if len(raw) > MAX_BYTES: raise ImportError_("TOO_LARGE")
    try: text = raw.decode("utf-8")
    except UnicodeDecodeError: raise ImportError_("NOT_UTF8")
    recs = []
    for i, line in enumerate(text.splitlines()):
        if not line.strip(): continue
        if len(recs) >= MAX_RECORDS: raise ImportError_("TOO_MANY_RECORDS")
        try: o = json.loads(line, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
        except ValueError: raise ImportError_("BAD_JSON", f"line {i + 1}")
        if not isinstance(o, dict): raise ImportError_("BAD_RECORD", f"line {i + 1}")
        recs.append(o)
    return recs, hashlib.sha256(raw).hexdigest()


def classify_command(s: str) -> list: return [k for k, rx in KINDS if rx.search(s)] or ["other"]


def to_events(records, corpus_digest, *, run_id, policy_digest, principal="replay"):
    """L1 replay: each trace 'command' record becomes an ATTEMPTED/UNKNOWN event describing what the trace claims. origin is trace_replay — NOT prefix completion, NOT spontaneous. Never executes anything."""
    san = Sanitizer(corpus_digest); evs = []
    for n, r in enumerate(records):
        if r.get("type") != "command": continue
        raw = str(r.get("content", "")); kinds = classify_command(raw[:MAX_FIELD]); cmd = san.text(raw)     # classify the inert text BEFORE aliasing (aliases erase metadata IPs); never executed
        evs.append(SC.make_event(run_id, len(evs), "+".join(kinds), layer="L1", origin="trace_replay", process={"pid": 0, "ppid": 0, "source": "host"}, principal=principal, decision="unknown", policy_digest=policy_digest, status="UNKNOWN",
                                 oracle={"receiver_bytes": None, "note": "replay only; nothing executed"}, trace_step=r.get("step", n), sanitized_command=cmd))
    return evs, san.map
