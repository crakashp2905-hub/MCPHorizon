"""HorizonInfraGuard (P36): authenticated AI-service posture, LOCAL ONLY.
Boundary decision (P36-01): we do NOT build a general cloud posture scanner. We (a) lint declarative IaC offline for a narrow set of AI-service exposure rules, (b) probe SYNTHETIC services this repository starts on loopback, and (c) emit signed evidence
that a runtime risk view can consume. Mature scanners (checkov, trivy, ...) are the right tool for breadth; incremental coverage vs them is measured, not assumed (docs/evidence/p36/COMPARISON.md).
Third-party scanning is forbidden by default: `scan_allowed()` only admits loopback and reserved test names."""
from __future__ import annotations
import hashlib, http.server, ipaddress, json, re, socket, threading, time, urllib.error, urllib.request
import yaml
from horizon.authz.keys import Signer
from horizon.runtime import artifacts as A

def canon(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str).encode()
def sha(o) -> str: return hashlib.sha256(o if isinstance(o, bytes) else canon(o)).hexdigest()

# ------------------------------------------------------------------ local-only guard (P36-04, P36-16)
class ScanForbidden(Exception): pass
def scan_allowed(host: str) -> bool:
    """Default-deny: only loopback addresses and reserved test names may be probed. No DNS lookup is performed."""
    h = host.strip("[]").lower()
    try: ip = ipaddress.ip_address(h); return ip.is_loopback
    except ValueError: return h == "localhost" or bool(re.search(r"\.(test|invalid|example|localhost)$", h))
def require_local(host: str):
    if not scan_allowed(host): raise ScanForbidden(f"refusing to probe {host!r}: third-party scanning is forbidden by default")

# ------------------------------------------------------------------ IaC lint (P36-05, P36-10, P36-11, P36-12, P36-13)
SECRET_ENV = re.compile(r"(?i)(pass(word)?|secret|token|api[_-]?key|private[_-]?key)")
SECRET_VAL = re.compile(r"^(?!\s*$)(?!\$\{)(?!<)(?!changeme$)(?!.*\{\{).{6,}$")
DEFAULT_CREDS = {("postgres", "postgres"), ("admin", "admin"), ("root", "root"), ("admin", "password"), ("elastic", "changeme"), ("neo4j", "neo4j"), ("admin", "changeme")}
PUBLIC_HOSTS = {"0.0.0.0", "::", "[::]", "*", ""}
RULES = {
 "IG001": "database or model-service port is published on a non-loopback interface", "IG002": "service accepts connections without authentication", "IG003": "default or empty credentials", "IG004": "admin or metrics endpoint exposed without allowlist entry",
 "IG005": "secret value present in plaintext environment / image layer", "IG006": "log or trace UI without authentication or tenant isolation", "IG007": "telemetry retention exceeds policy maximum or deletion is not access-controlled",
 "IG008": "service account is over-privileged (superuser / ALL PRIVILEGES / wildcard)", "IG009": "non-loopback listener without TLS",
}
def _port_binding(p) -> tuple:
    """-> (host, container_port, published_port). Compose short syntax: 'host:ip:hp:cp' | 'hp:cp' | 'cp'."""
    if isinstance(p, dict): return p.get("host_ip", ""), p.get("target"), p.get("published")
    parts = str(p).split(":"); 
    if len(parts) == 3: return parts[0], parts[2].split("/")[0], parts[1]
    if len(parts) == 2: return "", parts[1].split("/")[0], parts[0]
    return "", parts[0].split("/")[0], None
def lint(doc: dict, path: str = "<memory>", *, retention_max_days: int = 30, admin_allowlist=()) -> list:
    """Compose-like structure: services: {name: {image, ports, environment, command, x-auth, x-admin, x-tls, x-retention-days, x-deletion, x-roles, x-log-ui}}. Each finding: rule, exact message, source path and JSON-pointer-like location."""
    out = []; F = lambda rule, ptr, **k: out.append({"rule": rule, "message": RULES[rule], "source": path, "location": ptr, **k})
    for name, svc in (doc.get("services") or {}).items():
        base = f"/services/{name}"; env = svc.get("environment") or {}
        if isinstance(env, list): env = dict(e.split("=", 1) if "=" in e else (e, "") for e in env)
        for i, p in enumerate(svc.get("ports") or []):
            host, cport, pport = _port_binding(p)
            if host in PUBLIC_HOSTS: F("IG001", f"{base}/ports/{i}", detail=f"{host or 'all-interfaces'}:{pport or cport}")
        auth = svc.get("x-auth", {})
        if auth.get("mode", "none") in ("none", "", None, "anonymous"): F("IG002", f"{base}/x-auth")
        u, pw = env.get("POSTGRES_USER") or env.get("DB_USER") or auth.get("user"), env.get("POSTGRES_PASSWORD") or env.get("DB_PASSWORD") or auth.get("password")
        if (u and (pw in ("", None) or (str(u), str(pw)) in DEFAULT_CREDS)) or (pw in ("",) and "POSTGRES_PASSWORD" in env): F("IG003", f"{base}/environment")
        for k, v in env.items():
            if SECRET_ENV.search(k) and isinstance(v, str) and SECRET_VAL.match(v) and not v.startswith(("secret://", "env://", "file://")): F("IG005", f"{base}/environment/{k}", detail="value redacted")
        for ep in svc.get("x-admin", {}).get("endpoints", []):
            if ep not in set(admin_allowlist): F("IG004", f"{base}/x-admin/endpoints", detail=ep)
        lu = svc.get("x-log-ui")
        if lu and (lu.get("auth", "none") in ("none", "") or not lu.get("tenant_isolation", False)): F("IG006", f"{base}/x-log-ui")
        if "x-retention-days" in svc and (svc["x-retention-days"] > retention_max_days or svc.get("x-deletion", {}).get("requires_role") not in ("admin", "operator")): F("IG007", f"{base}/x-retention-days", detail=f"{svc['x-retention-days']}d > {retention_max_days}d" if svc["x-retention-days"] > retention_max_days else "deletion not role-gated")
        for r in svc.get("x-roles", []):
            if r.get("superuser") or any(g.upper() in ("ALL", "ALL PRIVILEGES", "*") for g in r.get("grants", [])): F("IG008", f"{base}/x-roles", detail=r.get("name"))
        pub = [p for p in (svc.get("ports") or []) if _port_binding(p)[0] in PUBLIC_HOSTS]
        if pub and not svc.get("x-tls", False): F("IG009", f"{base}/x-tls")
    return out
def lint_text(text: str, path: str, **kw) -> list:
    try: doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as e: return [{"rule": "IG000", "message": "unparsable IaC: cannot establish posture (UNKNOWN, not pass)", "source": path, "location": "/", "detail": str(e)[:80]}]
    return lint(doc, path, **kw)
def image_secret_scan(layers: dict) -> list:
    """Secrets baked into a (test-only) image: layers = {path: bytes}. Planted synthetic canaries are reported separately and never echoed in raw form."""
    hits = A.scan_secrets(layers); return [{"rule": "IG005", "message": RULES["IG005"], "source": "image", "location": h.get("where") or h.get("file"), "detail": "value redacted", "kind": h.get("kind")} for h in hits]
def deployment_report(findings: list, *, name="deploy") -> dict:
    """Deployment-blocking: any finding blocks. Reports cite source path + exact rule; UNKNOWN (unparsable) also blocks."""
    return {"decision": "BLOCK" if findings else "ALLOW", "findings": findings, "blocking_rules": sorted({f["rule"] for f in findings}), "digest": sha(findings)}

# ------------------------------------------------------------------ synthetic local services (P36-02, P36-06, P36-08, P36-09, P36-11)
class _H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self): self.server.svc.handle(self, "GET")
    def do_POST(self): self.server.svc.handle(self, "POST")
    def do_DELETE(self): self.server.svc.handle(self, "DELETE")
class SyntheticService:
    """A tiny local 'database + admin API + log UI' bound to 127.0.0.1 only (P36-04: binding is enforced in code, not by caller). Config selects secure vs defective behaviour."""
    def __init__(self, *, require_auth=True, admin_endpoints=("/admin/config",), metrics_public=False, logui_auth=True, logui_tenant_isolation=True, tokens=None, retention_s=3600):
        self.cfg = dict(require_auth=require_auth, admin=list(admin_endpoints), metrics_public=metrics_public, logui_auth=logui_auth, iso=logui_tenant_isolation); self.tokens = tokens or {"tok-t1": ("t1", "user"), "tok-t2": ("t2", "user"), "tok-admin": ("t1", "admin")}
        self.rows = {"t1": [{"id": 1, "v": "alpha"}], "t2": [{"id": 2, "v": "beta"}]}; self.logs = {"t1": [], "t2": []}; self.retention_s = retention_s; self.srv = None; self.port = None; self.requests = 0
    def start(self):
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H); self.srv.svc = self; self.port = self.srv.server_address[1]; assert self.srv.server_address[0] == "127.0.0.1"; threading.Thread(target=self.srv.serve_forever, daemon=True).start(); return self
    def stop(self):
        if self.srv: self.srv.shutdown(); self.srv.server_close()
    def __enter__(self): return self.start()
    def __exit__(self, *a): self.stop()
    def add_log(self, tenant, line, t=None): self.logs[tenant].append({"t": time.time() if t is None else t, "line": line})
    def _who(self, h):
        tok = (h.headers.get("Authorization") or "").replace("Bearer ", ""); return self.tokens.get(tok)
    def handle(self, h, method):
        self.requests += 1; path = h.path.split("?")[0]; who = self._who(h)
        if path == "/query":
            if self.cfg["require_auth"] and not who: return h._send(401, {"error": "auth required"})
            tenant = who[0] if who else "t1"; return h._send(200, {"rows": self.rows[tenant]})
        if path in self.cfg["admin"] or path.startswith("/admin"):
            if path not in self.cfg["admin"]: return h._send(404, {})
            if self.cfg["require_auth"] and not (who and who[1] == "admin"): return h._send(401 if not who else 403, {"error": "admin only"})
            return h._send(200, {"config": "redacted"})
        if path == "/metrics":
            if not self.cfg["metrics_public"] and not who: return h._send(401, {})
            return h._send(200, {"metrics": {"requests": self.requests}})
        if path.startswith("/logs/"):
            want = path.split("/")[2]
            if self.cfg["logui_auth"] and not who: return h._send(401, {})
            if self.cfg["iso"] and who and who[0] != want: return h._send(403, {"error": "tenant isolation"})
            return h._send(200, {"lines": [l["line"] for l in self.logs.get(want, [])]})
        if path == "/telemetry" and method == "DELETE":
            if not (who and who[1] == "admin"): return h._send(403, {"error": "deletion requires admin"})
            cutoff = time.time() - self.retention_s; n = 0
            for t in self.logs: before = len(self.logs[t]); self.logs[t] = [l for l in self.logs[t] if l["t"] >= cutoff]; n += before - len(self.logs[t])
            return h._send(200, {"deleted": n})
        return h._send(404, {})
def http_call(host, port, path, *, method="GET", token=None, timeout=3):
    require_local(host); req = urllib.request.Request(f"http://{host}:{port}{path}", method=method)
    if token: req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r: return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")
    except (urllib.error.URLError, OSError) as e: return 0, {"error": str(e)}

# ------------------------------------------------------------------ dynamic probes with independent oracles
def probe_auth(host, port, *, user_token) -> dict:
    """Benign authenticated query and unauthorized anonymous query are SEPARATE fixtures/results (P36-06). Oracle = rows actually returned, not the status code alone."""
    a_code, a_body = http_call(host, port, "/query"); b_code, b_body = http_call(host, port, "/query", token=user_token)
    return {"anonymous": {"status": a_code, "rows_returned": len(a_body.get("rows", []))}, "authenticated": {"status": b_code, "rows_returned": len(b_body.get("rows", []))}, "anonymous_data_exposed": bool(a_body.get("rows")), "benign_ok": b_code == 200 and bool(b_body.get("rows"))}
def probe_endpoints(host, port, *, inventory: list, allowlist: list, candidates=("/query", "/admin/config", "/admin/debug", "/metrics", "/logs/t1", "/telemetry", "/debug/pprof")) -> dict:
    """Compare what actually answers (anonymously) against the declared inventory and allowlist. Unknown responders are findings (P36-09)."""
    live = [p for p in candidates if http_call(host, port, p)[0] not in (404, 0)]; anon_ok = [p for p in candidates if http_call(host, port, p)[0] == 200]
    return {"responding": live, "undeclared": [p for p in live if p not in inventory], "anonymously_readable": anon_ok, "unallowlisted_anonymous": [p for p in anon_ok if p not in allowlist]}
def canary_scan_logs(host, port, *, token, tenant, canary_prefix="TEST_CANARY_NOT_SECRET") -> dict:
    """Looks for planted log canaries; the report carries a hash and count, NEVER the raw canary value (P36-07)."""
    code, body = http_call(host, port, f"/logs/{tenant}", token=token); lines = body.get("lines", []) if code == 200 else []
    found = [l for l in lines if canary_prefix in l]; return {"status": code, "canaries_found": len(found), "evidence_sha256": [hashlib.sha256(l.encode()).hexdigest()[:16] for l in found]}
def check_log_ui(host, port) -> dict:
    anon = http_call(host, port, "/logs/t1")[0]; cross = http_call(host, port, "/logs/t2", token="tok-t1")[0]; own = http_call(host, port, "/logs/t1", token="tok-t1")[0]
    return {"anonymous_status": anon, "cross_tenant_status": cross, "own_tenant_status": own, "auth_ok": anon in (401, 403), "isolation_ok": cross in (401, 403), "benign_ok": own == 200}
def check_retention(host, port, *, token_user, token_admin, expired_present: bool) -> dict:
    user_del = http_call(host, port, "/telemetry", method="DELETE", token=token_user)[0]; admin_del = http_call(host, port, "/telemetry", method="DELETE", token=token_admin); return {"user_delete_status": user_del, "admin_delete": admin_del, "access_controlled": user_del in (401, 403), "expired_removed": admin_del[0] == 200 and admin_del[1].get("deleted", 0) > 0 if expired_present else None}

# ------------------------------------------------------------------ signed evidence into a runtime risk view without granting admin (P36-14)
def sign_evidence(signer: Signer, report: dict, *, subject: str, now=None) -> dict:
    b = {"kind": "posture-evidence", "subject": subject, "decision": report["decision"], "blocking_rules": report["blocking_rules"], "report_digest": report["digest"], "ts": time.time() if now is None else now, "kid": signer.kid}; return {**b, "sig": signer.sign(canon(b)).hex()}
class RiskView:
    """Read-only for agents: only evidence signed by the registered posture key can be ingested; the view exposes decisions and has NO method that changes infrastructure."""
    def __init__(self, posture_pub: bytes, clock=time.time, max_age_s=3600): self.pub, self.clock, self.max_age, self._ev = posture_pub, clock, max_age_s, {}
    def ingest(self, ev: dict) -> bool:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try: Ed25519PublicKey.from_public_bytes(self.pub).verify(bytes.fromhex(ev["sig"]), canon({k: v for k, v in ev.items() if k != "sig"}))
        except Exception: return False
        self._ev[ev["subject"]] = ev; return True
    def risk(self, subject: str) -> dict:
        e = self._ev.get(subject)
        if not e: return {"subject": subject, "state": "UNKNOWN", "why": "no trusted posture evidence"}
        if self.clock() - e["ts"] > self.max_age: return {"subject": subject, "state": "UNKNOWN", "why": "evidence stale"}
        return {"subject": subject, "state": "BLOCKED" if e["decision"] == "BLOCK" else "OK", "rules": e["blocking_rules"]}
