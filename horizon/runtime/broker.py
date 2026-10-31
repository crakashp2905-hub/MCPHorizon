"""Default-deny egress broker (P25). The sandbox has NO network; every effect is one JSON request over an inherited unix socket. The broker (trusted, outside the sandbox) binds the request to the
launch's principal, authorizes it against an explicit allowlist, resolves via the approved resolver, validates the FINAL connect IP, pins the connection to that IP, re-applies policy on every redirect hop,
and caps size/time/rate. Unsupported transports are denied, not approximated."""
from __future__ import annotations
import hashlib, hmac, ipaddress, json, secrets, socket, struct, time
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from horizon import normalize as N

UNSUPPORTED = {"udp": "blocked in sandbox (socket family) and unavailable via broker", "quic": "udp-based; unavailable", "websocket": "Upgrade denied (UNSUPPORTED_TRANSPORT)", "grpc": "http/2 not implemented; denied", "connect_proxy": "CONNECT denied", "https": "TLS interception not implemented; https denied in this research build", "ftp": "unsupported", "raw_ip": "no raw sockets"}
METADATA_IPS = {"169.254.169.254", "100.100.100.200", "fd00:ec2::254", "169.254.170.2"}


def classify_ip(ip_s: str) -> str:
    """IPv4/IPv6 destination class. IPv4-mapped IPv6 is unwrapped; alternate numeric syntaxes are normalized by the caller (normalize._host)."""
    ip = ipaddress.ip_address(ip_s)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped: ip = ip.ipv4_mapped
    s = str(ip)
    if s in METADATA_IPS: return "METADATA"
    if ip.is_loopback: return "LOOPBACK"
    if ip.is_link_local: return "LINK_LOCAL"
    if ip.is_multicast: return "MULTICAST"
    if ip.is_unspecified: return "UNSPECIFIED"
    if ip in ipaddress.ip_network("100.64.0.0/10"): return "CGNAT"
    if ip.is_private: return "PRIVATE"
    if ip.is_reserved: return "RESERVED"
    return "PUBLIC"


@dataclass(frozen=True)
class Rule:
    host: str; ports: tuple = (80,); methods: tuple = ("GET", "POST"); path_prefix: str = "/"; max_body: int = 4096; max_resp: int = 65536; allow_labels: tuple = ("PUBLIC",)
    # a rule is for ONE principal: Broker.rules[principal] = [Rule,...]


class Resolver:
    """Approved resolver path (P25-05). Fixture-backed; `script` lets a name answer differently on successive calls (rebinding fixture). The sandbox cannot reach any resolver."""
    def __init__(self, table: dict, script: dict | None = None): self.t, self.script, self.calls = table, script or {}, {}
    def resolve(self, host: str) -> list:
        n = self.calls[host] = self.calls.get(host, 0) + 1
        if host in self.script: seq = self.script[host]; return seq[min(n - 1, len(seq) - 1)]
        return list(self.t.get(host, []))


class Broker:
    def __init__(self, rules: dict, resolver: Resolver, *, test_sinks: set, policy_ok=lambda: True, key: bytes | None = None, rate_per_min: int = 60, canaries: tuple = (b"TEST_CANARY_NOT_SECRET",), max_hops=3, timeout_s=3.0):
        self.rules, self.res, self.sinks, self.policy_ok, self.key, self.rate, self.canaries, self.max_hops, self.timeout, self.used, self.log, self.hits = rules, resolver, set(test_sinks), policy_ok, key or secrets.token_bytes(32), rate_per_min, canaries, max_hops, timeout_s, set(), [], {}

    # ---- authorization: decide ONCE for exact args, return an unforgeable permit (P25-03, P25-14)
    def _canon(self, principal, method, url, body: bytes, labels):
        return json.dumps({"p": principal, "m": method, "u": N.canonical_url(url), "b": hashlib.sha256(body).hexdigest(), "l": sorted(labels)}, sort_keys=True)
    def authorize(self, principal, method, url, body: bytes = b"", labels=(), exp_s=10) -> dict:
        try: dec = self._decide(principal, method, url, body, labels)
        except Exception as e: dec = {"ok": False, "code": "POLICY_ERROR", "detail": type(e).__name__}
        if not dec["ok"]: self.log.append({"principal": principal, "url": url, "decision": "DENY", "code": dec["code"]}); return dec
        c = self._canon(principal, method, url, body, labels); nonce = secrets.token_hex(8); exp = int(time.time()) + exp_s
        mac = hmac.new(self.key, f"{c}|{nonce}|{exp}".encode(), hashlib.sha256).hexdigest(); return {"ok": True, "permit": {"nonce": nonce, "exp": exp, "mac": mac}, "ip": dec["ip"], "port": dec["port"]}
    def _decide(self, principal, method, url, body, labels) -> dict:
        if not self.policy_ok(): return {"ok": False, "code": "POLICY_UNAVAILABLE"}                                  # fail closed on authority/policy outage (P25-17)
        s = urlsplit(url)
        if s.scheme != "http": return {"ok": False, "code": "UNSUPPORTED_TRANSPORT", "detail": s.scheme}
        try: cu = N.canonical_url(url)
        except ValueError as e: return {"ok": False, "code": "BAD_URL", "detail": str(e)}
        s = urlsplit(cu); host, port = s.hostname, s.port or 80
        now = time.time(); h = self.hits.setdefault(principal, []); h[:] = [t for t in h if now - t < 60]
        if len(h) >= self.rate: return {"ok": False, "code": "RATE_LIMIT"}
        rules = [r for r in self.rules.get(principal, []) if r.host == host]
        if not rules: return {"ok": False, "code": "DESTINATION_NOT_APPROVED"}
        r = next((r for r in rules if port in r.ports), None)
        if r is None: return {"ok": False, "code": "PORT_NOT_APPROVED"}
        if method not in r.methods: return {"ok": False, "code": "METHOD_NOT_APPROVED"}
        if not (s.path or "/").startswith(r.path_prefix): return {"ok": False, "code": "PATH_NOT_APPROVED"}
        if len(body) > r.max_body: return {"ok": False, "code": "BODY_TOO_LARGE"}
        if not set(labels) <= set(r.allow_labels): return {"ok": False, "code": "PAYLOAD_LABEL_NOT_ALLOWED"}
        if any(c in body for c in self.canaries) and "TEST_CANARY" not in r.allow_labels: return {"ok": False, "code": "CANARY_IN_PAYLOAD"}
        ips = self.res.resolve(host)
        if not ips: return {"ok": False, "code": "NO_RESOLUTION"}
        classes = [(ip, classify_ip(ip)) for ip in ips]
        if any((c in ("METADATA", "LINK_LOCAL", "MULTICAST", "UNSPECIFIED") or (c in ("LOOPBACK", "PRIVATE", "CGNAT", "RESERVED") and (ip, port) not in self.sinks)) for ip, c in classes): return {"ok": False, "code": "DESTINATION_CLASS_DENIED", "detail": [c for _, c in classes]}
        if len({ip for ip, _ in classes}) != 1: return {"ok": False, "code": "AMBIGUOUS_RESOLUTION"}      # multi-answer names must not let the connect pick a different address than the one validated
        h.append(now); return {"ok": True, "ip": classes[0][0], "port": port}
    def execute(self, principal, method, url, body: bytes, labels, auth: dict) -> dict:
        p = auth["permit"]; c = self._canon(principal, method, url, body, labels)
        want = hmac.new(self.key, f"{c}|{p['nonce']}|{p['exp']}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, p["mac"]): return {"ok": False, "code": "PERMIT_MISMATCH"}                    # arguments changed after authorization
        if time.time() > p["exp"]: return {"ok": False, "code": "PERMIT_EXPIRED"}
        if p["nonce"] in self.used: return {"ok": False, "code": "PERMIT_REPLAY"}
        self.used.add(p["nonce"]); return self._send(principal, method, url, body, labels, auth["ip"], auth["port"], hops=0)
    def _send(self, principal, method, url, body, labels, ip, port, hops) -> dict:
        s = urlsplit(N.canonical_url(url)); rule = next(r for r in self.rules[principal] if r.host == s.hostname and port in r.ports)
        try:
            sk = socket.create_connection((ip, port), timeout=self.timeout)          # connect to the VALIDATED, PINNED ip — never re-resolve the name
            if sk.getpeername()[0] != ip: sk.close(); return {"ok": False, "code": "PEER_MISMATCH"}
            path = (s.path or "/") + (f"?{s.query}" if s.query else ""); req = f"{method} {path} HTTP/1.1\r\nHost: {s.hostname}\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
            sk.sendall(req); data = b""; end = time.time() + self.timeout
            while len(data) <= rule.max_resp and time.time() < end:
                d = sk.recv(8192)
                if not d: break
                data += d
            sk.close()
        except OSError as e: return {"ok": False, "code": "CONNECT_FAILED", "detail": e.strerror}
        head = data.split(b"\r\n\r\n", 1)[0].decode(errors="replace"); status = int(head.split(" ", 2)[1]) if head.startswith("HTTP/") else 0
        if status in (301, 302, 303, 307, 308):                                       # policy applied AT EVERY HOP (P25-07)
            if hops >= self.max_hops: return {"ok": False, "code": "TOO_MANY_REDIRECTS"}
            loc = next((l.split(":", 1)[1].strip() for l in head.split("\r\n") if l.lower().startswith("location:")), None)
            if not loc: return {"ok": False, "code": "BAD_REDIRECT"}
            a = self.authorize(principal, "GET", loc, b"", ())
            if not a["ok"]: self.log.append({"principal": principal, "url": loc, "decision": "DENY_AT_REDIRECT", "code": a["code"]}); return {"ok": False, "code": "REDIRECT_" + a["code"]}
            self.used.add(a["permit"]["nonce"]); return self._send(principal, "GET", loc, b"", (), a["ip"], a["port"], hops + 1)
        self.log.append({"principal": principal, "url": url, "decision": "ALLOW", "status": status}); return {"ok": True, "status": status, "body": data.split(b"\r\n\r\n", 1)[-1][:rule.max_resp].decode(errors="replace")}
    def fetch(self, principal, method, url, body=b"", labels=()) -> dict:
        a = self.authorize(principal, method, url, body, labels)
        return a if not a["ok"] else self.execute(principal, method, url, body, labels, a)

    def session(self, principal) -> "Session": return Session(self, principal)


class Session:
    """What the sandbox talks to. The principal is fixed at launch; the request cannot name another one."""
    def __init__(self, broker, principal): self.b, self.p = broker, principal
    def serve_once(self, sock, run_id, reqs):
        hdr = sock.recv(4)
        if len(hdr) < 4: return
        n = struct.unpack(">I", hdr)[0]
        if n > 1 << 20: sock.sendall(self._frame({"ok": False, "code": "FRAME_TOO_LARGE"})); return
        buf = b""
        while len(buf) < n: buf += sock.recv(n - len(buf))
        try: m = json.loads(buf)
        except ValueError: sock.sendall(self._frame({"ok": False, "code": "BAD_JSON"})); return
        body = m.get("body", "").encode()
        r = self.b.fetch(self.p, str(m.get("method", "")).upper(), str(m.get("url", "")), body, tuple(m.get("labels", ())))
        reqs.append({"run_id": run_id, "principal": self.p, "method": m.get("method"), "url": m.get("url"), "ok": r["ok"], "code": r.get("code"), "bytes": len(body)}); sock.sendall(self._frame({k: v for k, v in r.items() if k not in ("permit", "ip")}))
    @staticmethod
    def _frame(o): d = json.dumps(o).encode(); return struct.pack(">I", len(d)) + d


CLIENT = '''
import socket, struct, json
def hz_fetch(method, url, body="", labels=()):
    s = socket.socket(fileno=3); d = json.dumps({"method": method, "url": url, "body": body, "labels": list(labels)}).encode()
    s.sendall(struct.pack(">I", len(d)) + d); h = s.recv(4); n = struct.unpack(">I", h)[0]; b = b""
    while len(b) < n: b += s.recv(n - len(b))
    s.detach(); return json.loads(b)
'''


def run_record(result, receiver_rows, broker_log) -> dict:
    """Single per-run record joining sandbox result, broker decisions and independent receiver observations (P25-18). `firewall_drops` is NOT available: seccomp/netns/Landlock denials are silent; the only kernel
    denial evidence is what the in-sandbox probe itself saw (errno) and the verified /proc profile."""
    allowed = [r for r in result.broker_requests if r["ok"]]
    return {"run_id": result.run_id, "policy_digest": result.policy_digest, "profile": result.profile, "broker_requests": result.broker_requests, "broker_log": [l for l in broker_log],
            "receiver_rows": receiver_rows, "receiver_bytes_total": sum(r["bytes"] for r in receiver_rows), "firewall_drops": None,
            "consistent": len(allowed) <= len(receiver_rows) + sum(1 for l in broker_log if l["decision"] == "ALLOW" and l.get("status", 0) >= 300)}
