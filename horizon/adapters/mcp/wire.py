"""MCP wire decoding (P4-01..P4-04). Two SEPARATE codecs: 2026-07-28 (stateless, mirrored headers) and 2025-11-25 (sessions).
Rules common to both: the authenticated principal comes from the trusted transport, never from the body or `_meta`; the operation
comes from the BODY; headers are only cross-checked (modern) or ignored-and-flagged (legacy). Fail closed on anything ambiguous."""
from __future__ import annotations
import json, secrets, time
from dataclasses import dataclass, field
from typing import Mapping, Sequence
from ...jsonschema_lite import check_bounds

MODERN, LEGACY = "2026-07-28", "2025-11-25"
META_VER = "io.modelcontextprotocol/protocolVersion"
NAME_KEY = {"tools/call": "name", "resources/read": "uri", "prompts/get": "name"}
MAX_BODY = 1 << 20
E_PARSE, E_INVALID, E_NOMETHOD, E_HEADER = -32700, -32600, -32601, -32020


class WireError(Exception):
    def __init__(self, status: int, code: int, name: str, msg: str):
        super().__init__(msg); self.status, self.code, self.name, self.msg = status, code, name, msg

    def jsonrpc(self, req_id=None) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": self.code, "message": self.msg, "data": {"name": self.name}}}


@dataclass(frozen=True)
class Request:
    version: str
    kind: str                       # request | notification | response
    method: str | None
    id: object
    params: dict
    principal: str
    name: str | None = None         # params.name / params.uri for name-bearing methods
    session_id: str | None = None
    ignored_headers: tuple = field(default_factory=tuple)
    suspicious: bool = False        # headers contradicted the body, or modern/legacy markers were mixed


def _headers(h: Mapping | Sequence) -> dict[str, str]:
    pairs = list(h.items()) if isinstance(h, Mapping) else list(h)
    out: dict[str, str] = {}
    for k, v in pairs:
        k = str(k).lower()
        if k in out: raise WireError(400, E_HEADER, "HeaderMismatch", f"duplicate header {k}")          # duplicates are ambiguous => reject
        if not isinstance(v, str) or any(c in v for c in "\r\n\x00") or not v.isascii(): raise WireError(400, E_HEADER, "HeaderMismatch", f"invalid characters in header {k}")
        out[k] = v.strip()
    return out


def _parse(body: bytes) -> dict:
    if not isinstance(body, (bytes, bytearray)) or len(body) > MAX_BODY: raise WireError(413, E_INVALID, "InvalidRequest", "body missing or too large")
    def bad_const(c): raise ValueError(c)
    try: doc = json.loads(body.decode("utf-8"), parse_constant=bad_const)
    except (ValueError, UnicodeDecodeError, RecursionError) as e: raise WireError(400, E_PARSE, "ParseError", "invalid JSON") from e
    if isinstance(doc, list): raise WireError(400, E_INVALID, "InvalidRequest", "JSON-RPC batches are not supported")
    if not isinstance(doc, dict): raise WireError(400, E_INVALID, "InvalidRequest", "body must be a JSON object")
    bad = check_bounds(doc)
    if bad: raise WireError(400, E_INVALID, "InvalidRequest", bad)
    if doc.get("jsonrpc") != "2.0": raise WireError(400, E_INVALID, "InvalidRequest", "jsonrpc must be '2.0'")
    return doc


def _classify(doc: dict, allow_response: bool) -> tuple[str, str | None, object, dict]:
    rid = doc.get("id")
    if rid is not None and (isinstance(rid, bool) or not isinstance(rid, (str, int))): raise WireError(400, E_INVALID, "InvalidRequest", "bad id type")
    if "method" not in doc:
        if ("result" in doc) != ("error" in doc) and rid is not None:
            if not allow_response: raise WireError(400, E_INVALID, "InvalidRequest", "clients must not send JSON-RPC responses in this protocol version")
            return "response", None, rid, {}
        raise WireError(400, E_INVALID, "InvalidRequest", "missing method")
    m = doc["method"]
    if not isinstance(m, str) or not m or len(m) > 128 or not m.isascii(): raise WireError(400, E_INVALID, "InvalidRequest", "bad method")
    p = doc.get("params", {})
    if not isinstance(p, dict): raise WireError(400, E_INVALID, "InvalidRequest", "params must be an object")
    return ("request" if rid is not None else "notification"), m, rid, p


def _name(method: str, params: dict) -> str | None:
    k = NAME_KEY.get(method)
    if not k: return None
    v = params.get(k)
    if not isinstance(v, str) or not v or len(v) > 2048: raise WireError(400, E_INVALID, "InvalidParams", f"{method} requires string params.{k}")
    return v


def _need_principal(principal) -> str:
    if not isinstance(principal, str) or not principal: raise WireError(401, E_INVALID, "MissingPrincipal", "no authenticated principal from the transport")
    return principal


def decode_modern(headers, body: bytes, principal: str | None) -> Request:
    """2026-07-28. Every request must carry protocol version in BOTH header and body._meta, and Mcp-Method/Mcp-Name that equal the body."""
    principal = _need_principal(principal); h = _headers(headers)
    acc = h.get("accept", "")
    if "application/json" not in acc or "text/event-stream" not in acc: raise WireError(406, E_INVALID, "NotAcceptable", "Accept must list application/json and text/event-stream")
    doc = _parse(body); kind, method, rid, params = _classify(doc, allow_response=False)
    meta = params.get("_meta")
    if not isinstance(meta, dict) or META_VER not in meta: raise WireError(400, E_INVALID, "InvalidRequest", "missing protocol version in _meta")
    if meta[META_VER] != MODERN: raise WireError(400, E_INVALID, "UnsupportedProtocolVersionError", f"unsupported protocol version {meta[META_VER]!r}")
    if h.get("mcp-protocol-version") != MODERN: raise WireError(400, E_HEADER, "HeaderMismatch", "MCP-Protocol-Version header missing or differs from body")
    if h.get("mcp-method") != method: raise WireError(400, E_HEADER, "HeaderMismatch", "Mcp-Method header missing or differs from body method")
    name = _name(method, params)
    if name is not None and h.get("mcp-name") != name: raise WireError(400, E_HEADER, "HeaderMismatch", "Mcp-Name header missing or differs from body")
    ignored = tuple(sorted(k for k in h if k in ("mcp-session-id", "last-event-id") or k.startswith("mcp-param-")))
    return Request(MODERN, kind, method, rid, params, principal, name, None, ignored, suspicious=bool({"mcp-session-id", "last-event-id"} & set(h)))


class SessionTable:
    """Legacy (2025-11-25) sessions. Bound to the principal that created them so an id alone is not a bearer credential."""
    def __init__(self, ttl_s: float = 3600, max_sessions: int = 10_000, clock=time.time):
        self.ttl, self.max, self.clock, self.s = ttl_s, max_sessions, clock, {}

    def open(self, principal: str, version: str = LEGACY) -> str:
        if len(self.s) >= self.max: raise WireError(503, E_INVALID, "TooManySessions", "session table full")
        sid = secrets.token_urlsafe(32); self.s[sid] = {"principal": principal, "version": version, "exp": self.clock() + self.ttl, "pending": set()}; return sid

    def get(self, sid: str, principal: str) -> dict:
        r = self.s.get(sid)
        if r is None or self.clock() >= r["exp"]: self.s.pop(sid, None); raise WireError(404, E_INVALID, "SessionNotFound", "unknown or expired session")
        if r["principal"] != principal: raise WireError(403, E_INVALID, "SessionPrincipalMismatch", "session belongs to another principal")
        return r

    def terminate(self, sid: str, principal: str) -> None: self.get(sid, principal); del self.s[sid]


def decode_legacy(headers, body: bytes, principal: str | None, sessions: SessionTable) -> Request:
    """2025-11-25. Operation from the body only; Mcp-Method/Mcp-Name do not exist in this version, so if present they are IGNORED and flagged."""
    principal = _need_principal(principal); h = _headers(headers)
    doc = _parse(body); kind, method, rid, params = _classify(doc, allow_response=True)
    meta = params.get("_meta") if isinstance(params, dict) else None
    if isinstance(meta, dict) and META_VER in meta: raise WireError(400, E_INVALID, "VersionMixing", "2026 protocol marker in a 2025 session request")
    ignored = tuple(sorted(k for k in h if k in ("mcp-method", "mcp-name") or k.startswith("mcp-param-")))
    sid = h.get("mcp-session-id")
    if method == "initialize":
        if sid: raise WireError(400, E_INVALID, "InvalidRequest", "initialize must not carry a session id")
        if params.get("protocolVersion") != LEGACY: raise WireError(400, E_INVALID, "UnsupportedProtocolVersionError", f"unsupported protocol version {params.get('protocolVersion')!r}")
        return Request(LEGACY, kind, method, rid, params, principal, None, None, ignored, suspicious=bool(ignored))
    if not sid: raise WireError(400, E_INVALID, "MissingSession", "session id required")
    sess = sessions.get(sid, principal)
    if h.get("mcp-protocol-version") != sess["version"]: raise WireError(400, E_INVALID, "UnsupportedProtocolVersionError", "MCP-Protocol-Version missing or differs from negotiated version")
    if kind == "response":
        if rid not in sess["pending"]: raise WireError(400, E_INVALID, "InvalidRequest", "response to a server request that was never issued")
        sess["pending"].discard(rid)
    name = _name(method, params) if method else None
    susp = bool(ignored) and any(h.get(k) not in (None, method if k == "mcp-method" else name) for k in ("mcp-method", "mcp-name"))
    return Request(LEGACY, kind, method, rid, params, principal, name, sid, ignored, suspicious=susp)
