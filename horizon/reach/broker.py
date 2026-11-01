"""Egress broker and policy (P44-04, 05, 06, 07) plus the baselines it is compared with (P44-14). Every connection decision uses the RESOLVED, pinned address, never the raw string. Verdicts: ALLOW | DENY | UNKNOWN; UNKNOWN never executes sensitive data."""
from __future__ import annotations
import base64, hashlib, json, re, threading, urllib.parse, uuid
from dataclasses import dataclass, field, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from . import urlnorm as U, model as M, network as N

MAX_HOPS = 3


@dataclass(frozen=True)
class Config:
    canonicalize: bool = True; pin: bool = True; revalidate_redirects: bool = True; bind_labels: bool = True; require_attestation: bool = True; fabric: bool = True; require_receipts: bool = True; unknown_blocks: bool = True


@dataclass
class Policy:
    """clearance[host] = highest label that may be sent to that destination. Resolved to addresses at load time with the trusted resolver, so a numeric or rebinding form of the same host is judged by the address it actually reaches."""
    clearance: dict; grants: dict; service_clearance: dict
    def __post_init__(self): self.ip_clear = {}
    def bind(self, resolver):
        for h, lab in {**self.clearance, **self.service_clearance}.items():
            try: self.ip_clear[resolver.resolve(h)] = lab
            except KeyError: pass
        return self
    def allowed_for(self, principal, host): return host in self.grants.get(principal, set())


def default_policy(resolver) -> Policy:
    return Policy({"public.test": "PUBLIC", "evil.test": "PUBLIC", "store.test": "PUBLIC", "partner.test": "SECRET", "partner2.test": "SECRET"},
                  {"analyst": {"public.test", "evil.test", "store.test", "partner.test", "partner2.test", "converter.test", "relay.test", "ext-converter.test"}, "intern": {"public.test"}},
                  {"converter.test": "SECRET", "relay.test": "SECRET", "ext-converter.test": "SECRET"}).bind(resolver)


@dataclass
class Decision:
    verdict: str; action: str; reasons: list; effects: list = field(default_factory=list); label: str = "PUBLIC"; first: dict | None = None
    def d(self): return {"verdict": self.verdict, "action": self.action, "reasons": self.reasons, "label": self.label, "effects": [(e.destination, e.effect, e.trust) for e in self.effects]}


class Fabric:
    """Controlled-network fabric: the only route for controlled services' outbound requests. Enforces a per-call label and the service's attested egress list. Unknown call context = SECRET (most restrictive)."""
    def __init__(self, broker): self.b, self.ctx, self.denied, self.allowed, self.lock = broker, {}, [], [], threading.Lock(); self._start()
    def _start(self):
        fab = self
        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"
            def log_message(self, *a): pass
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0); j = json.loads(self.rfile.read(n)); code, body = fab.egress(j); self.send_response(code); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H); self.srv.daemon_threads = True; self.port = self.srv.server_address[1]; threading.Thread(target=self.srv.serve_forever, daemon=True).start()
    def stop(self): self.srv.shutdown(); self.srv.server_close()
    def register(self, call, service, label, fetch_ok=()):
        with self.lock: self.ctx[call] = (service, label, frozenset(fetch_ok))
    def egress(self, j):
        with self.lock: svc, lab, fetch_ok = self.ctx.get(j.get("call", ""), (None, "SECRET", frozenset()))
        if svc is None or svc != j.get("service"): lab, fetch_ok = "SECRET", frozenset()      # unknown call id, or a call id borrowed by another service: most restrictive
        pure_fetch = j.get("method", "GET") == "GET" and not j.get("body_b64") and self.b.canon_url(j["url"]) in fetch_ok
        man = self.b.registry.manifest(j.get("service", ""))
        r = self.b.check_destination(j["url"], "PUBLIC" if pure_fetch else lab, egress_of=man)             # the exact URL the caller authorized to be fetched carries no payload
        if r["verdict"] != "ALLOW": self.denied.append({"service": j.get("service"), "url": j["url"], "why": r["reasons"], "label": lab}); return 403, json.dumps({"denied": r["reasons"]}).encode()
        self.allowed.append({"service": j.get("service"), "url": j["url"], "label": lab})
        s, h, d, trace = self.b.fetch_pinned(j["url"], j.get("method", "GET"), base64.b64decode(j.get("body_b64", "")) or None, lab, {}); return (s if s else 502), (d or b"")


class Broker:
    def __init__(self, mock, resolver, policy, registry, store, cfg=Config(), clock=None):
        self.mock, self.res, self.pol, self.registry, self.store, self.cfg = mock, resolver, policy, registry, store, cfg; self.port = mock.port; self.fabric = Fabric(self) if cfg.fabric else None; self.log = []
    def close(self):
        if self.fabric: self.fabric.stop()

    # ---- destination check -----------------------------------------------------------------------------------------------------------------------------------------------------------------
    def check_destination(self, url, label, egress_of=None, principal=None) -> dict:
        """-> {verdict, reasons, canon, ip}. Decides on the canonical authority and the resolved, pinned address."""
        try:
            c = U.canonicalize(url) if self.cfg.canonicalize else self._raw(url)
        except U.Unresolvable as e: return {"verdict": "UNKNOWN", "reasons": ["UNRESOLVABLE_DESTINATION: " + e.why], "canon": None, "ip": None}
        if c.userinfo: return {"verdict": "UNKNOWN", "reasons": ["USERINFO_IN_AUTHORITY"], "canon": c, "ip": None}
        try: ip = c.host if c.kind != "name" else self.res.resolve(c.host)
        except KeyError: return {"verdict": "UNKNOWN", "reasons": ["UNRESOLVED_HOST " + c.host], "canon": c, "ip": None}
        clear = self.pol.ip_clear.get(ip)
        if egress_of is not None and c.host not in egress_of["egress"] and ip not in {self.res.t.get(h) for h in egress_of["egress"]}: return {"verdict": "DENY", "reasons": ["NOT_IN_SERVICE_EGRESS_LIST " + c.host], "canon": c, "ip": ip}
        if clear is None: return {"verdict": "DENY" if M.RANK[label] > 0 else "ALLOW", "reasons": ["DESTINATION_NOT_IN_POLICY " + ip] if M.RANK[label] > 0 else ["PUBLIC_DATA_TO_UNLISTED_DESTINATION"], "canon": c, "ip": ip}
        if M.RANK[label] > M.RANK[clear]: return {"verdict": "DENY", "reasons": ["LABEL_%s_EXCEEDS_CLEARANCE_%s at %s" % (label, clear, ip)], "canon": c, "ip": ip}
        return {"verdict": "ALLOW", "reasons": [], "canon": c, "ip": ip}
    def canon_url(self, url):
        try: return U.canonicalize(url).url()
        except U.Unresolvable: return None
    def _raw(self, url):
        u = urllib.parse.urlsplit(url); h = (u.hostname or "").lower()
        return U.Canon(u.scheme, h, "name", u.port or 80, u.path or "/", u.query, False)

    # ---- pinned fetch ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    def fetch_pinned(self, url, method, body, label, headers, principal=None, first=None):
        """Resolve once, check the address, connect to THAT address, never auto-follow: each redirect hop is re-canonicalized and re-checked. Returns (status, headers, body, trace)."""
        trace = []; hops = 0
        while True:
            r = first if (first is not None and hops == 0) else self.check_destination(url, label)          # hop 0: the address already validated by evaluate() is reused (pinned)
            trace.append({"url": url, "verdict": r["verdict"], "ip": r["ip"], "why": r["reasons"]})
            if r["verdict"] != "ALLOW" and hops > 0 and self.cfg.revalidate_redirects: return 0, {}, None, trace
            if r["verdict"] != "ALLOW" and hops == 0: return 0, {}, None, trace
            c = r["canon"]
            if r is first:                                     # the request actually sent may add path/query to the string that was evaluated, but never change the authority
                try: c = U.canonicalize(url) if self.cfg.canonicalize else self._raw(url)
                except U.Unresolvable: return 0, {}, None, trace
                if c.authority != first["canon"].authority: trace[-1]["why"] = ["AUTHORITY_CHANGED_AFTER_CHECK"]; return 0, {}, None, trace
            ip = r["ip"] if self.cfg.pin else self.res.resolve(c.host) if c.kind == "name" else c.host
            s, h, d = N.vhttp((c.host, c.path + ("?" + c.query if c.query else "")), ip, c.port, method, body, headers)
            trace[-1]["status"] = s
            if s in (301, 302, 303, 307, 308) and "Location" in h and hops < MAX_HOPS:
                loc = urllib.parse.urljoin(c.url(), h["Location"])
                if not self.cfg.revalidate_redirects: url, hops = loc, hops + 1; method = "GET" if s in (301, 302, 303) else method; body = None if s in (301, 302, 303) else body; continue
                url, hops = loc, hops + 1; method = "GET" if s in (301, 302, 303) else method; body = None if s in (301, 302, 303) else body; continue
            return s, h, d, trace

    # ---- the policy decision ---------------------------------------------------------------------------------------------------------------------------------------------------------------
    def label_of(self, artifact, claimed=None):
        if artifact is None: return "PUBLIC"
        return self.store.get(artifact)["label"] if self.cfg.bind_labels else (claimed or "PUBLIC")
    def service_trust(self, host):
        st = self.registry.status(host)
        if st == "ATTESTED": return "attested"
        return "unverified-declaration"
    def evaluate(self, principal, op, target, artifact=None, claimed_label=None, src=None, to=None) -> Decision:
        label = self.label_of(artifact, claimed_label); reasons, effs, verdicts = [], [], []
        r = self.check_destination(target, label)
        if op == "send":
            verdicts.append(r["verdict"]); reasons += r["reasons"]; effs.append(M.EffectiveEffect(principal, None, r["canon"].authority if r["canon"] else ("?", 0), "send", label, "direct"))
        else:                                                   # call of an intermediary service
            c = r["canon"]; name = self._service_name(c, r["ip"]) if c else ""
            trust = self.service_trust(name) if c else "unverified-declaration"
            if r["canon"] is None: verdicts.append(r["verdict"]); reasons += r["reasons"]
            elif not self.pol.allowed_for(principal, name): verdicts.append("DENY"); reasons.append("PRINCIPAL_HAS_NO_GRANT_FOR_SERVICE " + name)
            elif self.registry.status(name) == "REVOKED": verdicts.append("DENY"); reasons.append("SERVICE_REVOKED " + name)
            elif trust != "attested" and self.cfg.require_attestation:
                if M.RANK[label] > 0: verdicts.append("UNKNOWN"); reasons.append("REMOTE_EFFECTS_UNVERIFIED " + name)
                else: verdicts.append("ALLOW"); reasons.append("PUBLIC_DATA_UNVERIFIED_SERVICE")
            else:
                clr = self.pol.service_clearance.get(name, "PUBLIC") if trust == "attested" else "PUBLIC"
                if not self.cfg.require_attestation: clr = self.pol.service_clearance.get(name, "PUBLIC")
                if M.RANK[label] > M.RANK[clr]: verdicts.append("DENY"); reasons.append("LABEL_%s_EXCEEDS_SERVICE_CLEARANCE_%s" % (label, clr))
                else: verdicts.append("ALLOW")
                effs.append(M.EffectiveEffect(principal, name, c.authority, "call", label, trust))
                man = self.registry.manifest(name)
                for kind, arg in (("fetch", src), ("relay", to)):
                    if not arg: continue
                    if man is not None and kind not in man["ops"] and trust == "attested": verdicts.append("DENY"); reasons.append("OP_NOT_IN_MANIFEST " + kind); continue
                    rr = self.check_destination(arg, "PUBLIC" if kind == "fetch" else label)          # a fetch sends only the URL; a relay forwards the payload
                    effs.append(M.EffectiveEffect(principal, name, rr["canon"].authority if rr["canon"] else ("?", 0), kind, label, trust)); verdicts.append(rr["verdict"]); reasons += rr["reasons"]
                if man is not None and not man["controlled"] and trust == "attested" and self.cfg.require_receipts: reasons.append("EXTERNAL_SERVICE_RESIDUAL_EFFECTS_BOUND_ONLY_BY_RECEIPT")
        v = "DENY" if "DENY" in verdicts else "UNKNOWN" if "UNKNOWN" in verdicts else "ALLOW"
        act = "EXECUTE" if v == "ALLOW" or (v == "UNKNOWN" and not self.cfg.unknown_blocks) else "BLOCK"
        return Decision(v, act, reasons, effs, label, r)
    def _service_name(self, c, ip):
        """Identity of a service is the address it resolves to, so numeric or alias forms of the same service map to one registry entry."""
        for n, a in self.res.t.items():
            if a == ip: return n
        return c.host

    def run(self, principal, op, target, artifact=None, claimed_label=None, src=None, to=None) -> dict:
        embedded = bool(artifact and "{d}" in target)
        if embedded: target = target.replace("{d}", urllib.parse.quote(self.store.get(artifact)["value"], safe=""))          # one final string is checked AND used
        d = self.evaluate(principal, op, target, artifact, claimed_label, src, to); out = {"decision": d.d(), "executed": False, "status": None, "receipt": None, "post_verdict": d.verdict, "trace": [], "call": None}
        if d.action != "EXECUTE": return out
        call = uuid.uuid4().hex[:12]; out["call"] = call; payload = self.store.get(artifact)["value"] if artifact else ""; hd = {"X-Horizon-Label": d.label, "X-Horizon-Call": call}
        url, body, method = target, None, "GET"
        if op == "send" and not embedded: method, body = "POST", payload.encode()
        if op == "convert": method, body = "POST", json.dumps({"doc": payload, "src": src}).encode(); hd["Content-Type"] = "application/json"
        if op == "relay": method, body = "POST", payload.encode(); url = target + ("&" if "?" in target else "?") + "to=" + urllib.parse.quote(to or "", safe="")
        name = None
        if op != "send":
            c = U.canonicalize(target) if self.cfg.canonicalize else self._raw(target); name = self._service_name(c, c.host if c.kind != "name" else self.res.resolve(c.host)); man = self.registry.manifest(name)
            if self.fabric and man and man["controlled"] and self.registry.status(name) == "ATTESTED": self.fabric.register(call, name, d.label, [self.canon_url(src)] if src else [])
        s, h, data, trace = self.fetch_pinned(url, method, body, d.label, hd, principal, d.first); out.update(executed=bool(trace and trace[0].get("status") is not None), status=s or None, trace=trace)
        out["body"] = (data or b"")[:200].decode("latin1")
        if op != "send" and name and self.registry.status(name) == "ATTESTED" and self.cfg.require_receipts:
            man = self.registry.manifest(name)
            if not man["controlled"]:
                rc = M.verify_receipt(h.get("X-Reach-Receipt") if h else None, man, call); out["receipt"] = rc["state"]
                if rc["state"] != "OK": out["post_verdict"] = "UNKNOWN"
                else:
                    fetch_ok = {self.canon_url(src)} if src else set()
                    bad = [e["url"] for e in rc["effects"] if not (e["method"] == "GET" and self.canon_url(e["url"]) in fetch_ok) and self.check_destination(e["url"], d.label)["verdict"] == "DENY"]
                    if bad: out["receipt"] = "REVEALS_UNAUTHORIZED_EFFECT"; out["post_verdict"] = "DENY"; self.registry.revoke(name, "receipt reveals " + bad[0])
        return out
