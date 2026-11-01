"""Baselines (P44-14): strict domain allowlist, URL-pattern filter, and trust-in-declarations (tool-description analysis). All three follow redirects automatically and resolve names again at connect time, like ordinary HTTP clients."""
from __future__ import annotations
import ipaddress, json, re, urllib.parse
from . import network as N, urlnorm as U


class Naive:
    def __init__(self, mock, resolver, store, kind, allow_hosts=(), deny_re=None, declared=None):
        self.mock, self.res, self.store, self.kind, self.allow, self.deny, self.declared = mock, resolver, store, kind, set(allow_hosts), re.compile(deny_re) if deny_re else None, declared or {}
    def _decide(self, urls, service=None):
        if self.kind == "pattern": return "DENY" if any(self.deny.search(u) for u in urls if u) else "ALLOW"
        for u in urls:
            if not u: continue
            h = (urllib.parse.urlsplit(u).hostname or "")
            if h not in self.allow: return "DENY"
            try:
                ip = self.res.resolve(h)                           # SSRF-style check resolves once...
                if ip not in {self.res.t.get(a) for a in self.allow if a in self.res.t}: return "DENY"
            except KeyError: return "DENY"
        if self.kind == "declaration" and service:               # ...and trusts the service's self-description
            fw = self.declared.get(service, [])
            if any(urllib.parse.urlsplit(f).hostname not in self.allow for f in fw): return "DENY"
        return "ALLOW"
    def _addr(self, host):
        """What the OS resolver does at connect time: numeric forms (decimal, hex, octal, IPv4-mapped IPv6) are addresses, names go to DNS again."""
        try: v4 = U._ipv4_aton(host.lower())
        except U.Unresolvable: v4 = None
        if v4: return v4
        try:
            ip = ipaddress.ip_address(host)
            return str(ip.ipv4_mapped or ip)
        except ValueError: return self.res.resolve(host)
    def _get(self, url, method, body, headers):
        for _ in range(6):
            u = urllib.parse.urlsplit(url); ip = self._addr(u.hostname)        # ...and again at connect time
            s, h, d = N.vhttp((u.hostname, (u.path or "/") + ("?" + u.query if u.query else "")), ip, u.port or 80, method, body, headers)
            if s in (301, 302, 303, 307, 308) and "Location" in h: url = urllib.parse.urljoin(url, h["Location"]); method = "GET" if s in (301, 302, 303) else method; continue
            return s, h, d
        return 0, {}, b""
    def run(self, principal, op, target, artifact=None, claimed_label=None, src=None, to=None):
        payload = self.store.get(artifact)["value"] if artifact else ""; urls = [target] + ([src] if src else []) + ([to] if to else [])
        name = (urllib.parse.urlsplit(target).hostname or "") if op != "send" else None; v = self._decide(urls, name)
        out = {"decision": {"verdict": v, "action": "EXECUTE" if v == "ALLOW" else "BLOCK", "reasons": [], "label": None, "effects": []}, "executed": False, "status": None, "receipt": None, "post_verdict": v, "trace": []}
        if v != "ALLOW": return out
        url, body, method = target, None, "GET"
        embedded = bool(artifact and "{d}" in url)
        if embedded: url = url.replace("{d}", urllib.parse.quote(payload, safe=""))
        elif op == "send": method, body = "POST", payload.encode()
        if op == "convert": method, body = "POST", json.dumps({"doc": payload, "src": src}).encode()
        if op == "relay": method, body = "POST", payload.encode(); url = target + ("&" if "?" in target else "?") + "to=" + urllib.parse.quote(to or "", safe="")
        try: s, h, d = self._get(url, method, body, {})
        except (KeyError, OSError): s, h, d = 0, {}, b""
        out.update(executed=True, status=s, body=(d or b"")[:200].decode("latin1")); return out
