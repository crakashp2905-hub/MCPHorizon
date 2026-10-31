"""Logical operation IDs and canonical target normalization (P1-17, P1-18)."""
from __future__ import annotations
import hashlib, ipaddress, posixpath, re, socket
from urllib.parse import quote, unquote, urlsplit

# Explicit, reviewed mapping. Anything absent is UNMAPPED -> caller must treat as unknown (fail closed).
LOGICAL = {
    ("mcp", "resources/read"): "resource.read", ("mcp", "resources/list"): "resource.list",
    ("mcp", "prompts/get"): "prompt.get", ("mcp", "prompts/list"): "prompt.list", ("mcp", "tools/list"): "tool.list",
    ("utcp", "http:GET"): "http.read", ("utcp", "http:POST"): "http.send", ("utcp", "http:PUT"): "http.write",
    ("utcp", "http:DELETE"): "http.delete", ("utcp", "cli:exec"): "process.execute",
    ("code_mode", "fs.readFile"): "file.read", ("code_mode", "fs.writeFile"): "file.write",
    ("code_mode", "fetch:POST"): "http.send", ("code_mode", "fetch:GET"): "http.read",
}
# tools/call carries no operation meaning by itself: the tool registry must supply the logical op.
TOOL_REGISTRY: dict[str, str] = {}


class Unmapped(ValueError):
    pass


def logical_operation(protocol: str, native: str, tool_id: str | None = None) -> str:
    if (protocol, native) == ("mcp", "tools/call"):
        if tool_id and tool_id in TOOL_REGISTRY: return TOOL_REGISTRY[tool_id]
        raise Unmapped(f"mcp tools/call for {tool_id!r} has no registry-declared logical operation")
    try: return LOGICAL[(protocol, native)]
    except KeyError: raise Unmapped(f"no logical operation for {protocol}:{native}") from None


def _host(h: str) -> str:
    h = h.strip("[]").rstrip(".").lower()
    try: return str(ipaddress.ip_address(h))
    except ValueError: pass
    if re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", h):  # decimal/hex/octal-obfuscated IPv4
        try: return socket.inet_ntoa(socket.inet_aton(h))
        except OSError: raise ValueError(f"malformed numeric host {h!r}")
    if not h or not re.fullmatch(r"[a-z0-9.-]+", h.encode("idna").decode()):
        raise ValueError(f"unacceptable host {h!r}")
    return h.encode("idna").decode()


def canonical_url(raw: str) -> str:
    s = urlsplit(raw.strip())
    if s.scheme.lower() not in ("http", "https", "ws", "wss"): raise ValueError(f"unsupported scheme {s.scheme!r}")
    if s.username or s.password: raise ValueError("credentials in URL are not allowed")
    if not s.hostname: raise ValueError("missing host")
    scheme, host = s.scheme.lower(), _host(s.hostname)
    port = s.port
    if port in (None, {"http": 80, "ws": 80, "https": 443, "wss": 443}[scheme]): port = None
    path = unquote(s.path or "/")
    if "\x00" in path or "\\" in path: raise ValueError("illegal path characters")
    path = posixpath.normpath(path) if path != "/" else "/"
    if s.path.endswith("/") and not path.endswith("/"): path += "/"
    if path.startswith("//"): path = "/" + path.lstrip("/")
    hostpart = f"[{host}]" if ":" in host else host
    q = f"?{s.query}" if s.query else ""
    return f"{scheme}://{hostpart}{':' + str(port) if port else ''}{quote(path, safe='/:@!$&()*+,;=-._~')}{q}"


def canonical_file(raw: str, base: str = "/") -> str:
    if "\x00" in raw or "\\" in raw: raise ValueError("illegal path characters")
    p = posixpath.normpath(raw if raw.startswith("/") else posixpath.join(base, raw))
    b = posixpath.normpath(base)
    if not (p == b or p.startswith(b.rstrip("/") + "/")): raise ValueError("path escapes base directory")
    return p


def canonical_target(kind: str, raw: str, base: str = "/") -> dict:
    if kind == "url": cid = canonical_url(raw)
    elif kind == "file": cid = canonical_file(raw, base)
    elif kind in ("resource", "agent", "process"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}", raw): raise ValueError("illegal identifier")
        cid = raw
    else: raise ValueError(f"unknown target kind {kind}")
    return {"kind": kind, "canonical_id": cid}


def target_digest(target: dict) -> str:
    """Identity derived from (kind, canonical_id) ONLY — never from agent-supplied display names."""
    return "sha256:" + hashlib.sha256(f"{target['kind']}\x1f{target['canonical_id']}".encode()).hexdigest()
