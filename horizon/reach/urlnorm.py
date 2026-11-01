"""URL / authority / host / address-family normalization that does not trust raw strings (P44-03). Fail closed: anything ambiguous raises Unresolvable and becomes UNKNOWN upstream.
Handles: userinfo tricks, backslashes, control chars, percent-encoded hosts, case, trailing dot, IDNA, IPv4 in decimal/hex/octal/short forms, IPv6 incl. IPv4-mapped, default ports, dot-segments."""
from __future__ import annotations
import ipaddress, re
from dataclasses import dataclass


class Unresolvable(ValueError):
    def __init__(self, why): super().__init__(why); self.why = why


@dataclass(frozen=True)
class Canon:
    scheme: str; host: str; kind: str; port: int; path: str; query: str; userinfo: bool = False
    @property
    def authority(self): return (self.host, self.port)
    def url(self): return "%s://%s%s%s%s" % (self.scheme, ("[%s]" % self.host) if self.kind == "ipv6" else self.host, "" if self.port == {"http": 80, "https": 443}[self.scheme] else ":%d" % self.port, self.path, ("?" + self.query) if self.query else "")


def _ipv4_aton(h: str):
    """inet_aton-style forms: a, a.b, a.b.c, a.b.c.d with decimal / 0x hex / 0 octal parts. Returns dotted quad or None when h is not numeric."""
    parts = h.split(".")
    if not 1 <= len(parts) <= 4 or any(p == "" for p in parts): return None
    vals = []
    for p in parts:
        try:
            if re.fullmatch(r"0[xX][0-9a-fA-F]+", p): vals.append(int(p, 16))
            elif re.fullmatch(r"0[0-7]+", p): vals.append(int(p, 8))
            elif re.fullmatch(r"[0-9]+", p): vals.append(int(p, 10))
            else: return None
        except ValueError: raise Unresolvable("bad numeric host part")
    n = len(vals)
    if any(v < 0 for v in vals): raise Unresolvable("negative")
    for v in vals[:-1]:
        if v > 255: raise Unresolvable("numeric host part out of range")
    if vals[-1] >= 256 ** (5 - n): raise Unresolvable("numeric host tail out of range")
    ip = 0
    for v in vals[:-1]: ip = (ip << 8) | v
    ip = (ip << (8 * (5 - n))) | vals[-1]
    return str(ipaddress.IPv4Address(ip))


def _pct_decode(s: str) -> str:
    def f(m): return chr(int(m.group(1), 16))
    return re.sub(r"%([0-9a-fA-F]{2})", f, s)


def _path(p: str) -> str:
    out = []
    for seg in p.split("/"):
        s = _pct_decode(seg) if re.fullmatch(r"(?:[A-Za-z0-9._~-]|%2[eE])+", seg) else seg           # only unreserved characters are decoded
        if s == ".": continue
        if s == "..":
            if len(out) > 1: out.pop()
            continue
        out.append(seg if s != seg and not re.fullmatch(r"[.]+", s) else s)
    r = "/".join(out)
    return r if r.startswith("/") else "/" + r


def canonicalize(url: str) -> Canon:
    if not isinstance(url, str) or not url or len(url) > 2048: raise Unresolvable("empty or oversized")
    if re.search(r"[\x00-\x20\x7f\\]", url): raise Unresolvable("control character, whitespace or backslash")
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#.*)?$", url)
    if not m: raise Unresolvable("not an absolute URL")
    scheme, auth, path, query = m.group(1).lower(), m.group(2), m.group(3), m.group(4) or ""
    if scheme not in ("http", "https"): raise Unresolvable("scheme not allowed")
    userinfo = "@" in auth
    host_port = auth.rsplit("@", 1)[-1]
    if host_port == "": raise Unresolvable("empty host")
    if host_port.startswith("["):
        mm = re.fullmatch(r"\[([0-9a-fA-F:.]+)\](?::([0-9]*))?", host_port)
        if not mm: raise Unresolvable("bad IPv6 literal")
        try: ip = ipaddress.IPv6Address(mm.group(1))
        except ValueError: raise Unresolvable("bad IPv6")
        port_s = mm.group(2)
        if ip.ipv4_mapped is not None: host, kind = str(ip.ipv4_mapped), "ipv4"           # an IPv4-mapped address IS that IPv4 address
        else: host, kind = str(ip), "ipv6"
    else:
        mm = re.fullmatch(r"([^:]*)(?::([0-9]*))?", host_port)
        if not mm: raise Unresolvable("bad authority")
        raw, port_s = mm.group(1), mm.group(2)
        host = _pct_decode(raw)
        if host.endswith("."): host = host[:-1]
        if not host or ".." in host: raise Unresolvable("empty label")
        v4 = _ipv4_aton(host.lower())
        if v4 is not None: host, kind = v4, "ipv4"
        elif re.fullmatch(r"(0[xX][0-9a-fA-F]*|[0-9]+)", host.lower().rsplit(".", 1)[-1]): raise Unresolvable("numeric-looking final label that is not a valid IPv4 address")
        else:
            try: host = host.lower().encode("idna").decode("ascii")
            except UnicodeError: raise Unresolvable("bad IDNA")
            if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*", host): raise Unresolvable("illegal host characters")
            kind = "name"
    default = {"http": 80, "https": 443}[scheme]
    if port_s is None or port_s == "": port = default
    else:
        port = int(port_s)
        if not 1 <= port <= 65535: raise Unresolvable("port out of range")
    return Canon(scheme, host, kind, port, _path(path or "/"), query, userinfo)
