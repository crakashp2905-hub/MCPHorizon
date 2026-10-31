"""Outbound HTTP policy (P5-05..P5-10). Pure policy + a redirect-following driver over an injected `send`; no network code here.
`resolver(host)->[ip]` and `send(req)->resp` are supplied by the host so the checks are testable and the DNS answer that was validated is the one connected to."""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urljoin
from ... import normalize

METADATA_IPS = {"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"}
METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data"}
AUTH_HEADERS = {"authorization", "proxy-authorization", "cookie", "x-api-key"}


class EgressError(Exception):
    def __init__(self, code, msg): super().__init__(msg); self.code = code


def ip_forbidden(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped: a = a.ipv4_mapped
    if str(a) in METADATA_IPS: return True
    return bool(a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified or (isinstance(a, ipaddress.IPv4Address) and a in ipaddress.ip_network("100.64.0.0/10")))


def canonical_target(method: str, url: str, *, allow_http=False) -> dict:
    s = urlsplit(url)
    if s.scheme not in ("https",) + (("http",) if allow_http else ()): raise EgressError("SCHEME", "https required")
    if s.username or s.password: raise EgressError("USERINFO", "credentials in URL")
    host = (s.hostname or "").rstrip(".").lower()
    if not host: raise EgressError("NO_HOST", "no host")
    if host in METADATA_HOSTS or host == "localhost" or host.endswith((".local", ".internal", ".localhost")): raise EgressError("INTERNAL_HOST", host)
    try: ip = ipaddress.ip_address(host)
    except ValueError:
        if all(p.isdigit() or p.lower().startswith("0x") for p in host.split(".")): raise EgressError("OBFUSCATED_IP", host)      # 2130706433, 0x7f.0.0.1, 017700000001
        ip = None
    if ip is not None and ip_forbidden(str(ip)): raise EgressError("FORBIDDEN_ADDRESS", host)
    port = s.port or (443 if s.scheme == "https" else 80)
    return {"method": method.upper(), "scheme": s.scheme, "host": host, "port": port, "path": urlsplit(normalize.canonical_url(url)).path or "/", "url": normalize.canonical_url(url), "literal_ip": str(ip) if ip else None}


def resolve_checked(host: str, resolver, literal_ip=None) -> list[str]:
    ips = [literal_ip] if literal_ip else list(resolver(host))
    if not ips: raise EgressError("NO_ADDRESS", host)
    bad = [i for i in ips if ip_forbidden(i)]
    if bad: raise EgressError("FORBIDDEN_ADDRESS", f"{host} resolves to a forbidden address")      # ANY forbidden answer rejects (defeats mixed A records / rebinding to a second answer)
    return ips


@dataclass
class Budget:
    max_redirects: int = 3
    max_body_bytes: int = 1_000_000
    max_decompressed_bytes: int = 2_000_000
    max_ratio: float = 50.0


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes = b""
    tls_ok: bool = True
    wire_bytes: int | None = None


def fetch(method: str, url: str, headers: dict, *, resolver, send, budget: Budget = Budget(), allowed_hosts: set | None = None, allow_http=False) -> tuple[Response, list[dict]]:
    """Follow redirects manually. EVERY hop is re-canonicalised, re-resolved and re-checked; credentials are stripped on any host/port/scheme change.
    `send({"url","ip","method","headers"})` must connect to `ip` (the validated address) with SNI/Host = hostname and certificate verification ON."""
    trail, cur, m, h = [], url, method.upper(), {k: v for k, v in headers.items()}
    for hop in range(budget.max_redirects + 1):
        t = canonical_target(m, cur, allow_http=allow_http)
        if allowed_hosts is not None and t["host"] not in allowed_hosts: raise EgressError("HOST_NOT_ALLOWED", t["host"])
        ips = resolve_checked(t["host"], resolver, t["literal_ip"])
        resp = send({"url": t["url"], "ip": ips[0], "method": m, "headers": dict(h)}); trail.append({"url": t["url"], "ip": ips[0], "status": resp.status})
        if not resp.tls_ok: raise EgressError("TLS", "certificate validation failed")
        if resp.status in (301, 302, 303, 307, 308):
            loc = next((v for k, v in resp.headers.items() if k.lower() == "location"), None)
            if not loc: raise EgressError("BAD_REDIRECT", "redirect without location")
            nxt = urljoin(t["url"], loc); nt = canonical_target(m, nxt, allow_http=allow_http)
            if (nt["scheme"], nt["host"], nt["port"]) != (t["scheme"], t["host"], t["port"]): h = {k: v for k, v in h.items() if k.lower() not in AUTH_HEADERS}
            if resp.status in (301, 302, 303) and m not in ("GET", "HEAD"): m = "GET"
            cur = nxt; continue
        n = len(resp.body)
        if n > budget.max_body_bytes or n > budget.max_decompressed_bytes: raise EgressError("BODY_TOO_LARGE", f"{n} bytes")
        if resp.wire_bytes and n / max(resp.wire_bytes, 1) > budget.max_ratio: raise EgressError("DECOMPRESSION_RATIO", "suspicious compression ratio")
        return resp, trail
    raise EgressError("TOO_MANY_REDIRECTS", "redirect limit exceeded")
