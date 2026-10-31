"""Translators that run the REAL gates (P14-03/04/05). Each protocol path ends in the same Rig-owned receiver, so observed effects are compared, not labels alone."""
from __future__ import annotations
import json
from urllib.parse import urlsplit
from horizon import normalize as N
from horizon.adapters.mcp import wire as W
from horizon.adapters.mcp.gate import McpGate, ToolPolicy, ToolRegistry
from horizon.adapters.mcp.manifest import ManifestTracker
from horizon.adapters.utcp import creds as CR, egress as EG, manual as MN
from horizon.adapters.utcp.gate import UtcpGate
from . import effects as F

HOSTS = {"api.example.com": ["93.184.216.34"], "other.example.org": ["93.184.216.41"]}
ENDPOINTS = {"notes": "https://api.example.com/v1/notes", "alerts": "https://api.example.com/v1/alerts", "other": "https://other.example.org/v1/notes"}
SCHEMA = {"type": "object", "properties": {"url": {"type": "string"}, "text": {"type": "string"}}, "required": ["url"], "additionalProperties": False}
METHOD_OF = {"read": "GET", "send": "POST", "delete": "DELETE"}


class Rig:
    """decide(body) -> decision dict. `captured` records every decision body the gates built (for coverage reports)."""
    def __init__(self, decide, *, tenant="T1", mcp_codec="modern"):
        self.tenant, self.codec, self.captured, self.observed, self.n = tenant, mcp_codec, [], [], 0
        self._decide = decide
        def rec(body): self.captured.append(body); return decide(body)
        self.reg = ToolRegistry()
        for name, eff in (("publish", "send"), ("fetch", "read"), ("remove", "delete")): self.reg.add("s1", name, ToolPolicy(f"eq.{name}", eff, target_arg="url", target_kind="url", sink_zone="partner" if eff == "send" else None))
        self.reg.install(); self.tr = ManifestTracker(); self.tools = [{"name": n, "description": n, "inputSchema": SCHEMA} for n in ("publish", "fetch", "remove")]; self.tr.observe("s1", self.tools); self.tr.approve("s1", ["publish", "fetch", "remove"], "op")
        self.mcp = McpGate(decide=rec, forward=self._mcp_forward, registry=self.reg, tracker=self.tr, tenant=tenant)
        tl = []
        for ep, url in ENDPOINTS.items():
            tl += [{"name": f"post_{ep}", "tool_call_template": {"call_template_type": "http", "url": url, "http_method": "POST", "body_arg": "text"}}, {"name": f"get_{ep}", "tool_call_template": {"call_template_type": "http", "url": url, "http_method": "GET"}},
                   {"name": f"del_{ep}", "tool_call_template": {"call_template_type": "http", "url": url, "http_method": "DELETE"}}]
        self.mreg = MN.ManualRegistry(); self.mreg.observe("m", MN.parse_manual(json.dumps({"tools": tl}).encode(), "src")); self.mreg.approve("m", "op")
        self.trail = []
        def send(r): self.observed.append({"via": "utcp", "method": r["method"], "url": r["url"], "body": r.get("body") or b""}); return EG.Response(200, {}, b"{}")
        self.utcp = UtcpGate(decide=rec, registry=self.mreg, broker=CR.CredentialBroker(), resolver=lambda h: HOSTS.get(h, []), send=send, tenant=tenant, sink_zones={"m": "partner"})

    def _mcp_forward(self, server, req, extra):
        a = req.params.get("arguments", {}); eff = self.reg.get(server, req.name).effect
        self.observed.append({"via": "mcp", "method": METHOD_OF[eff], "url": N.canonical_url(a["url"]), "body": (a.get("text") or "").encode()})
        return {"jsonrpc": "2.0", "id": req.id, "result": {"content": [{"type": "text", "text": "ok"}]}}

    # ---- protocol entry points: each returns (ok: bool, verdict: str|None)
    def mcp_call(self, principal, tool, args):
        self.n += 1
        if self.codec == "modern":
            req = W.decode_modern({"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": W.MODERN, "Mcp-Method": "tools/call", "Mcp-Name": tool},
                                  json.dumps({"jsonrpc": "2.0", "id": self.n, "method": "tools/call", "params": {"_meta": {W.META_VER: W.MODERN}, "name": tool, "arguments": args}}).encode(), principal)
        else: req = self._legacy(principal, tool, args)
        m = self.mcp.handle("s1", req); return "result" in m, ((m.get("error") or {}).get("data") or {}).get("verdict")

    def _legacy(self, principal, tool, args):
        if not hasattr(self, "_st"): self._st, self._sids = W.SessionTable(), {}
        sid = self._sids.get(principal) or self._sids.setdefault(principal, self._st.open(principal, W.LEGACY))
        return W.decode_legacy({"Accept": "application/json, text/event-stream", "Mcp-Session-Id": sid, "MCP-Protocol-Version": W.LEGACY},
                               json.dumps({"jsonrpc": "2.0", "id": self.n, "method": "tools/call", "params": {"name": tool, "arguments": args}}).encode(), principal, self._st)

    def utcp_call(self, principal, tool, args):
        self.n += 1; r = self.utcp.call(principal, f"c{self.n}", "m", tool, args); return bool(r.get("ok")), r.get("verdict")

    # ---- translation of what was observed into Effects
    def effects(self, principal, tenant, protocol, since: int, parent=None):
        out = []
        for o in self.observed[since:]:
            kind = F.SUPPORTED_HTTP.get(o["method"]); 
            if kind is None: raise F.Unsupported("UNSUPPORTED_METHOD", o["method"])
            out.append(F.make(kind, "url", o["url"], principal=principal, tenant=tenant, payload=o["body"], parent=parent, protocol=protocol))
        return out


# ---- Code Mode path (P14-05): nested calls from a sandboxed program are normalized into the same decision shape
CM_TOOLS = ["cm_get", "cm_post", "cm_delete"]
_CM_NATIVE = {"cm_get": ("fetch:GET", "read"), "cm_post": ("fetch:POST", "send"), "cm_delete": ("fetch:DELETE", "delete")}


def _cm_run(self, principal, calls):
    """calls: list of (tool, url, text|None). Returns list of (ok, verdict) in order."""
    from horizon.codemode.exec import Executor
    outs = []
    def med(c):
        t, a = c["tool"], c["args"]; native, eff = _CM_NATIVE[t]; self.n += 1
        try: logical = N.logical_operation("code_mode", native) if native in ("fetch:GET", "fetch:POST") else "http.delete"
        except N.Unmapped: return {"ok": False, "error": "UNMAPPED"}
        body = {"protocol": "code_mode", "native_operation": native, "tool_id": f"code_mode/{t}", "effect": eff, "args_digest": None,
                "target": {"kind": "url", "raw": a["url"]}, "sink_zone": "partner" if eff == "send" else None, "purpose": None, "input_artifacts": [],
                "idempotency_key": f"cm-{self.n}", "event_id": f"{principal}-{self.n}", "logical_operation": logical}
        self.captured.append(body); dec = self._decide(body)
        if dec.get("verdict") not in ("ALLOW", "ALLOW_WITH_OBLIGATIONS"): outs.append((False, dec.get("verdict"))); return {"ok": False, "error": "DENIED"}
        self.observed.append({"via": "code_mode", "method": native.split(":")[1], "url": N.canonical_url(a["url"]), "body": (a.get("text") or "").encode()}); outs.append((True, None))
        return {"ok": True, "result": "ok"}
    prog = "\n".join(f"await tools.{t}({{url: {json.dumps(u)}, text: {json.dumps(x)}}});" for t, u, x in calls) + "\nreturn 'done';"
    Executor(med).run(prog, CM_TOOLS, principal=principal, timeout_s=30.0); return outs


Rig.cm_run = _cm_run
