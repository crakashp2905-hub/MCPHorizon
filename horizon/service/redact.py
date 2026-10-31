"""Redaction of outcome/trace payloads (P3-03, P3-16). Fail-safe: unknown structure => dropped, not passed through."""
from __future__ import annotations
import re

SECRET_KEY = re.compile(r"(authorization|password|passwd|secret|token|api[_-]?key|cookie|credential|private[_-]?key|session)", re.I)
SECRET_VAL = re.compile(r"(bearer\s+[A-Za-z0-9._~+/=-]{8,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}|gh[pousr]_[A-Za-z0-9]{20,})", re.I)
MAX_STR, MAX_DEPTH, MAX_ITEMS = 512, 4, 50


def redact(v, depth=0):
    if depth > MAX_DEPTH: return "[TRUNCATED_DEPTH]"
    if isinstance(v, dict):
        return {str(k)[:64]: ("[REDACTED]" if SECRET_KEY.search(str(k)) else redact(x, depth + 1)) for k, x in list(v.items())[:MAX_ITEMS]}
    if isinstance(v, list): return [redact(x, depth + 1) for x in v[:MAX_ITEMS]]
    if isinstance(v, str): return "[REDACTED]" if SECRET_VAL.search(v) else (v[:MAX_STR] + ("…" if len(v) > MAX_STR else ""))
    if v is None or isinstance(v, (bool, int, float)): return v
    return "[DROPPED_UNKNOWN_TYPE]"
