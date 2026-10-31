"""Privacy-safe OpenTelemetry-shaped export (P10-14): OTLP/JSON span + metric documents built from local spans. Only allowlisted attribute keys survive; identifiers are salted-hashed; no network export here."""
from __future__ import annotations
import hashlib, json

ALLOWED = {"verdict", "protocol", "effect", "reason_code", "status", "route", "tenant_h", "principal_h", "latency_ms", "experiment_id", "rule"}


def _h(salt: bytes, v: str) -> str: return hashlib.sha256(salt + str(v).encode()).hexdigest()[:12]


def clean_attrs(attrs: dict, salt: bytes) -> dict:
    out = {}
    for k, v in attrs.items():
        if k in ("tenant", "principal"): out[k + "_h"] = _h(salt, v)
        elif k in ALLOWED and isinstance(v, (str, int, float, bool)) and len(str(v)) <= 64: out[k] = v
    return out


def to_otlp_spans(spans: list[dict], salt: bytes, service: str = "mcphorizon") -> dict:
    kv = lambda d: [{"key": k, "value": {"stringValue": str(v)}} for k, v in sorted(d.items())]
    sp = [{"traceId": (s["trace_id"] or "0" * 32).replace("-", "")[:32].ljust(32, "0"), "spanId": hashlib.sha256(f"{s['name']}{s['start']}".encode()).hexdigest()[:16], "name": s["name"],
           "startTimeUnixNano": str(int(s["start"] * 1e9)), "endTimeUnixNano": str(int(s["end"] * 1e9)), "attributes": kv(clean_attrs(s.get("attrs", {}), salt))} for s in spans]
    return {"resourceSpans": [{"resource": {"attributes": kv({"service.name": service})}, "scopeSpans": [{"scope": {"name": "mcphorizon.ops"}, "spans": sp}]}]}


def to_otlp_metrics(metrics: dict, now: float) -> dict:
    pts = [{"name": "mcphorizon.requests", "sum": {"dataPoints": [{"asInt": str(int(metrics.get("requests", 0))), "timeUnixNano": str(int(now * 1e9))}]}}, {"name": "mcphorizon.errors", "sum": {"dataPoints": [{"asInt": str(int(metrics.get("errors", 0))), "timeUnixNano": str(int(now * 1e9))}]}}]
    for v, n in sorted(metrics.get("decisions", {}).items()): pts.append({"name": "mcphorizon.decisions", "sum": {"dataPoints": [{"asInt": str(int(n)), "attributes": [{"key": "verdict", "value": {"stringValue": str(v)[:16]}}], "timeUnixNano": str(int(now * 1e9))}]}})
    return {"resourceMetrics": [{"scopeMetrics": [{"scope": {"name": "mcphorizon.ops"}, "metrics": pts}]}]}
