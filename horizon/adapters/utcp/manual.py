"""Approved manual registry (P5-02..P5-04). The registry is operator-controlled state, never read from a model-writable file.
A manual is pinned by (source, digest). Any change to digest or to any tool endpoint requires explicit re-approval; calls are blocked meanwhile."""
from __future__ import annotations
import hashlib, json
from urllib.parse import urlsplit

MAX_MANUAL_BYTES, MAX_TOOLS, MAX_DEPTH = 256_000, 500, 20


class ManualError(Exception):
    def __init__(self, code, msg): super().__init__(msg); self.code = code


def _digest(o) -> str: return "sha256:" + hashlib.sha256(json.dumps(o, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _depth(o, d=0):
    if d > MAX_DEPTH: return d
    if isinstance(o, dict): return max([d] + [_depth(v, d + 1) for v in o.values()])
    if isinstance(o, list): return max([d] + [_depth(v, d + 1) for v in o])
    return d


def parse_manual(raw: bytes, source: str) -> dict:
    """Bounded parse BEFORE any SDK/zod parsing (the pinned @utcp/sdk is exposed to a zod memory-exhaustion advisory)."""
    if len(raw) > MAX_MANUAL_BYTES: raise ManualError("TOO_LARGE", "manual exceeds size limit")
    try: doc = json.loads(raw, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    except ValueError as e: raise ManualError("BAD_JSON", str(e)[:100])
    if not isinstance(doc, dict) or not isinstance(doc.get("tools"), list): raise ManualError("BAD_SHAPE", "manual must be an object with a tools array")
    if len(doc["tools"]) > MAX_TOOLS or _depth(doc) > MAX_DEPTH: raise ManualError("TOO_COMPLEX", "manual too large or deep")
    tools = {}
    for t in doc["tools"]:
        if not isinstance(t, dict) or not isinstance(t.get("name"), str) or not t["name"]: raise ManualError("BAD_TOOL", "tool without a name")
        if t["name"] in tools: raise ManualError("DUPLICATE_TOOL", f"duplicate tool {t['name']!r}")
        ct = t.get("tool_call_template")
        if not isinstance(ct, dict) or ct.get("call_template_type") not in ("http", "cli"): raise ManualError("UNSUPPORTED_TRANSPORT", f"{t['name']}: only http and cli templates are understood")
        tools[t["name"]] = {"template": ct, "inputs": t.get("inputs", {}), "description": str(t.get("description", ""))[:2000]}
    return {"source": source, "digest": _digest(doc), "tools": tools, "endpoints": {n: _endpoint(v["template"]) for n, v in tools.items()}}


def _endpoint(ct: dict) -> str:
    if ct["call_template_type"] == "http":
        u = ct.get("url"); 
        if not isinstance(u, str): raise ManualError("BAD_TOOL", "http template without url")
        s = urlsplit(u); return f"{(ct.get('http_method') or 'GET').upper()} {s.scheme}://{(s.hostname or '').lower()}:{s.port or ''}{s.path}"
    return "cli " + json.dumps(ct.get("commands", ct.get("command", "")), sort_keys=True)


class ManualRegistry:
    """Held in memory by the trusted host. approve() is host-only; nothing a manual or tool says can call it."""
    def __init__(self): self.approved: dict[str, dict] = {}; self.seen: dict[str, dict] = {}
    def observe(self, manual_id: str, m: dict) -> dict:
        prev = self.approved.get(manual_id); self.seen[manual_id] = m
        if prev is None: return {"status": "NEW", "changed_tools": []}
        if prev["digest"] == m["digest"]: return {"status": "UNCHANGED", "changed_tools": []}
        ch = sorted(n for n in set(prev["endpoints"]) | set(m["endpoints"]) if prev["endpoints"].get(n) != m["endpoints"].get(n))
        return {"status": "CHANGED", "changed_tools": ch, "endpoint_swap": [n for n in ch if n in prev["endpoints"] and n in m["endpoints"]]}
    def approve(self, manual_id: str, approver: str) -> None:
        if not approver: raise ManualError("NO_APPROVER", "approval needs an identified approver")
        if manual_id not in self.seen: raise ManualError("UNKNOWN_MANUAL", manual_id)
        self.approved[manual_id] = {**self.seen[manual_id], "approver": approver}
    def resolve(self, manual_id: str, tool: str) -> dict:
        ap = self.approved.get(manual_id)
        if ap is None: raise ManualError("NOT_APPROVED", "manual has not been approved")
        cur = self.seen.get(manual_id)
        if cur is not None and cur["digest"] != ap["digest"]: raise ManualError("MANUAL_CHANGED", "manual changed after approval; re-approval required")
        t = ap["tools"].get(tool)
        if t is None: raise ManualError("UNKNOWN_TOOL", tool)
        return {"template": t["template"], "endpoint": ap["endpoints"][tool], "digest": ap["digest"]}
