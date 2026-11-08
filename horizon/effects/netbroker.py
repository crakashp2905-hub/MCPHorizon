"""Network broker policy + client (HTTP/HTTPS with DNS pinning, no redirects). CANDIDATE, stdlib only, imports nothing from this repo.
What it enforces, in this process, for requests made THROUGH it:
  * only (scheme, host, port) triples named in the policy; no userinfo; no IP-literal hosts unless that exact IP is the allowed host; hostnames normalised to lowercase IDNA;
  * DNS is resolved ONCE by this module (injectable resolver); every returned address must be public unless the policy entry says allow_private; the connection goes to the pinned address
    (so a second, different DNS answer cannot redirect it - no rebinding window); HTTPS verifies the certificate against the ORIGINAL hostname (SNI + hostname check) with certificate verification mandatory;
  * redirects are never followed (a 3xx is returned as a refusal), no proxy variables are read, request/response size and total time are capped, method and header names are restricted.
What it does NOT enforce: anything an agent does without calling the broker. Bypass resistance needs an OS-level boundary (no direct sockets for the agent process), which this module cannot provide and which
is NOT implemented or tested here. Public-ness uses `ipaddress` flags and is only as good as that module; IPv4-mapped IPv6 is unwrapped before the check."""
from __future__ import annotations
import http.client, ipaddress, socket, ssl, time
from dataclasses import dataclass
from urllib.parse import urlsplit

METHODS = frozenset({"GET", "POST", "PUT", "DELETE"})
FORBIDDEN_HEADERS = frozenset({"host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection", "upgrade"})


class NetBrokerError(Exception):
    def __init__(self, code, msg=""): super().__init__(f"{code}: {msg}" if msg else code); self.code = code


@dataclass(frozen=True)
class Allow:
    scheme: str; host: str; port: int; allow_private: bool = False; ca_file: str | None = None   # ca_file: extra trust anchor for THIS entry only (tests / private PKI)


def _norm_host(h: str) -> str:
    try: return h.encode("idna").decode("ascii").lower()
    except UnicodeError: raise NetBrokerError("BAD_HOST", "not IDNA-encodable")


def _ip(addr: str):
    ip = ipaddress.ip_address(addr)
    return ip.ipv4_mapped if getattr(ip, "ipv4_mapped", None) else ip


def is_public(addr: str) -> bool:
    ip = _ip(addr)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified or getattr(ip, "is_site_local", False)) and ip.is_global


class NetBroker:
    def __init__(self, allow, *, resolver=None, timeout=5.0, max_request=1 << 20, max_response=1 << 20):
        self.allow = tuple(allow); self.timeout, self.max_request, self.max_response = float(timeout), int(max_request), int(max_response)
        self.resolver = resolver or (lambda host, port: [a[4][0] for a in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)])
        for a in self.allow:
            if a.scheme not in ("http", "https"): raise ValueError("scheme must be http or https")

    def check(self, method, url, headers=None, body=b""):
        """Pure policy decision (no network except the pinned resolution). Returns (Allow, host, port, path, pinned_ip) or raises NetBrokerError."""
        if method not in METHODS: raise NetBrokerError("BAD_METHOD")
        if not isinstance(url, str) or any(c in url for c in "\x00\r\n \\") : raise NetBrokerError("BAD_URL", "illegal characters")
        if len(body) > self.max_request: raise NetBrokerError("REQUEST_TOO_LARGE")
        for k in (headers or {}):
            if not isinstance(k, str) or k.lower() in FORBIDDEN_HEADERS or any(c in k for c in "\r\n:") : raise NetBrokerError("BAD_HEADER", str(k))
            if any(c in str((headers or {})[k]) for c in "\r\n"): raise NetBrokerError("BAD_HEADER", "value")
        s = urlsplit(url)
        if s.username is not None or s.password is not None: raise NetBrokerError("USERINFO_NOT_ALLOWED")
        if s.scheme not in ("http", "https") or not s.hostname or not s.path.startswith("/"): raise NetBrokerError("BAD_URL")
        port = s.port or (443 if s.scheme == "https" else 80); host = _norm_host(s.hostname)
        entry = next((a for a in self.allow if (a.scheme, _norm_host(a.host), a.port) == (s.scheme, host, port)), None)
        if entry is None: raise NetBrokerError("OUTSIDE_ALLOWED_TARGETS", f"{s.scheme}://{host}:{port}")
        try: _ip(host); literal = True
        except ValueError: literal = False
        addrs = [host] if literal else list(self.resolver(host, port))
        if not addrs: raise NetBrokerError("DNS_NO_ANSWER")
        for a in addrs:
            try: pub = is_public(a)
            except ValueError: raise NetBrokerError("DNS_BAD_ADDRESS", str(a))
            if not pub and not entry.allow_private: raise NetBrokerError("PRIVATE_ADDRESS", str(a))
        return entry, host, port, s.path + ("?" + s.query if s.query else ""), addrs[0]

    def request(self, method, url, headers=None, body=b""):
        entry, host, port, path, ip = self.check(method, url, headers, body); deadline = time.monotonic() + self.timeout
        if entry.scheme == "https":
            ctx = ssl.create_default_context(cafile=entry.ca_file) if entry.ca_file else ssl.create_default_context()
            ctx.check_hostname = True; ctx.verify_mode = ssl.CERT_REQUIRED; ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            conn = _PinnedHTTPS(host, port, ip, ctx, self.timeout)
        else: conn = _PinnedHTTP(host, port, ip, self.timeout)
        try:
            hdrs = {"Host": host if port in (80, 443) else f"{host}:{port}", "Connection": "close", **(headers or {})}
            conn.request(method, path, body=body or None, headers=hdrs); r = conn.getresponse()
            data = r.read(self.max_response + 1)
            if len(data) > self.max_response: raise NetBrokerError("RESPONSE_TOO_LARGE")
            if time.monotonic() > deadline: raise NetBrokerError("TIMEOUT")
            if 300 <= r.status < 400: raise NetBrokerError("REDIRECT_REFUSED", str(r.status))
            return r.status, data
        except NetBrokerError: raise
        except ssl.SSLCertVerificationError as e: raise NetBrokerError("TLS_VERIFY_FAILED", e.verify_message)
        except ssl.SSLError as e: raise NetBrokerError("TLS_ERROR", str(e))
        except (socket.timeout, TimeoutError): raise NetBrokerError("TIMEOUT")
        except OSError as e: raise NetBrokerError("CONNECT_FAILED", type(e).__name__)
        finally: conn.close()


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout): super().__init__(host, port, timeout=timeout); self._ip = ip
    def connect(self): self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, ctx, timeout): super().__init__(host, port, timeout=timeout, context=ctx); self._ip = ip
    def connect(self):
        raw = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)       # SNI + hostname verification use the ORIGINAL name, the TCP peer is the pinned address
