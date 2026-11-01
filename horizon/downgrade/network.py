"""Local endpoint fixtures and independent journals (P46-08/09). One separate process hosts several HTTP(S) endpoints on loopback aliases with DIFFERENT real properties: TLS version (plaintext / 1.2-only / 1.3-only), enforced authentication (none / api key / signed bearer with required scope), whether the endpoint posts to the audit sink, whether it copies request bodies to a side sink (a hidden egress), and the region (127.0.2.x = eu, 127.0.3.x = us). Every request is journalled by the endpoint process; the audit and side sinks are journalled by their own handlers. The gateway never writes these files, so they are the oracle's evidence. The harness may flip an endpoint's failure mode through a control port.
Loopback only; the canary payload is synthetic."""
from __future__ import annotations
import base64, datetime, hashlib, http.client, json, os, socket, ssl, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CANARY = "TEST_CANARY_NOT_SECRET"


def make_cert(dirpath):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import ipaddress
    key = ec.generate_private_key(ec.SECP256R1()); name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "horizon-downgrade-fixture")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=2)) \
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.2.1")), x509.IPAddress(ipaddress.ip_address("127.0.3.1")), x509.DNSName("localhost")]), False).sign(key, hashes.SHA256())
    cp, kp = os.path.join(dirpath, "cert.pem"), os.path.join(dirpath, "key.pem")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM)); open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); return cp, kp


def _b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_bearer(tok, pub_hex, aud, now):
    """-> (claims | None, reason). Signed by the credential broker; checked by the endpoint itself."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        b, s = tok.split("."); Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(_b64d(s), b.encode()); c = json.loads(_b64d(b))
    except Exception: return None, "bad_signature"
    if c.get("aud") != aud: return None, "wrong_audience"
    if c.get("exp", 0) < now: return None, "expired"
    return c, ""


def serve(cfgfile):
    cfg = json.load(open(cfgfile)); wd = cfg["workdir"]; jl = threading.Lock(); modes = {e["name"]: "ok" for e in cfg["endpoints"]}
    def jw(name, row):
        with jl, open(os.path.join(wd, name), "a") as f: f.write(json.dumps(row) + "\n")
    def post(port, path, obj, ip="127.0.9.1"):
        try:
            c = http.client.HTTPConnection(ip, port, timeout=2); c.request("POST", path, json.dumps(obj).encode(), {"Content-Length": str(len(json.dumps(obj).encode()))}); c.getresponse().read(); c.close()
        except Exception: pass
    class Sink(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0); body = self.rfile.read(n); self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
            j = json.loads(body or b"{}"); j["t"] = time.time(); jw(self.server.journal, j)
    def sink(port, journal, ip="127.0.9.1"):
        s = ThreadingHTTPServer((ip, port), Sink); s.journal = journal; s.daemon_threads = True; threading.Thread(target=s.serve_forever, daemon=True).start(); return s
    sink(cfg["audit_port"], "audit.jsonl"); sink(cfg["side_port"], "side.jsonl")

    def handler_for(e):
        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"
            def log_message(self, *a): pass
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0); body = self.rfile.read(n); mode = modes[e["name"]]; rid = self.headers.get("X-Req-Id", ""); probe = self.headers.get("X-Probe") == "1"
                if mode == "timeout": time.sleep(3.0)
                if mode == "drop": self.connection.close(); return
                tlsv = self.connection.version() if isinstance(self.connection, ssl.SSLSocket) else None
                tok = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip(); key = self.headers.get("X-Api-Key"); presented = "oauth" if tok else "api_key" if key else "none"; claims = None; why = ""
                status = 200
                if e["authn"] == "api_key" and key != cfg["api_key"]: status = 401
                elif e["authn"] == "oauth":
                    claims, why = verify_bearer(tok, cfg["broker_pub"], e["name"], time.time()) if tok else (None, "missing")
                    if claims is None: status = 401
                    elif not set(e.get("requires_scope", [])) <= set(claims.get("scope", [])): status = 403; why = "insufficient_scope"
                if mode == "5xx" and status == 200: status = 503
                row = {"t": time.time(), "endpoint": e["name"], "ip": e["ip"], "port": e["port"], "tls": tlsv, "authn_presented": presented, "scope_presented": (lambda c: sorted(c.get("scope", [])) if c else None)(claims or _peek(tok)),
                       "status": status, "why": why, "req_id": rid, "data_class": self.headers.get("X-Data-Class"), "has_canary": CANARY.encode() in body, "probe": probe, "mode": mode}
                jw("endpoints.jsonl", row)
                if status == 200 and mode == "ok":
                    if e.get("audit"): post(cfg["audit_port"], "/a", {"req_id": rid, "endpoint": e["name"]})
                    if e.get("tee"): post(cfg["side_port"], "/t", {"req_id": rid, "endpoint": e["name"], "has_canary": CANARY.encode() in body})
                out = json.dumps({"endpoint": e["name"], "status": status}).encode(); self.send_response(status); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
        return H
    def _peek(tok):
        try: return json.loads(_b64d(tok.split(".")[0]))
        except Exception: return None
    servers = []
    for e in cfg["endpoints"]:
        s = ThreadingHTTPServer((e["ip"], e["port"]), handler_for(e)); s.daemon_threads = True
        if e["tls"] != "none":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cfg["cert"], cfg["key"])
            if e["tls"] == "1.2": ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            if e["tls"] == "1.3": ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            s.socket = ctx.wrap_socket(s.socket, server_side=True)
        threading.Thread(target=s.serve_forever, daemon=True).start(); servers.append(s)
    class Ctl(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0); j = json.loads(self.rfile.read(n)); modes.update(j.get("modes", {})); out = b"ok"; self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(out)
    c = ThreadingHTTPServer(("127.0.9.1", cfg["ctl_port"]), Ctl); open(os.path.join(wd, "ready"), "w").write("1"); c.serve_forever()


def free_ports(n):
    socks = [socket.socket() for _ in range(n)]
    for s in socks: s.bind(("127.0.0.1", 0))
    ports = [s.getsockname()[1] for s in socks]; [s.close() for s in socks]; return ports


class World:
    """Endpoint process + journals + helpers the gateway/oracle share. `specs` = list of endpoint dicts."""
    def __init__(self, workdir, specs, broker_pub_hex, api_key="k-synthetic"):
        self.wd, self.api_key = workdir, api_key; ports = free_ports(len(specs) + 3); self.audit_port, self.side_port, self.ctl_port = ports[:3]
        self.cert, self.key = make_cert(workdir); self.eps = {}
        for s, p in zip(specs, ports[3:]): self.eps[s["name"]] = {**s, "port": p}
        cfg = {"workdir": workdir, "endpoints": list(self.eps.values()), "audit_port": self.audit_port, "side_port": self.side_port, "ctl_port": self.ctl_port, "cert": self.cert, "key": self.key, "broker_pub": broker_pub_hex, "api_key": api_key}
        self.cfgfile = os.path.join(workdir, "cfg.json"); json.dump(cfg, open(self.cfgfile, "w"))
        for f in ("endpoints.jsonl", "audit.jsonl", "side.jsonl"): open(os.path.join(workdir, f), "w").close()
    def start(self):
        self.p = subprocess.Popen([sys.executable, "-m", "horizon.downgrade.network", self.cfgfile], cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(300):
            if os.path.exists(os.path.join(self.wd, "ready")): return self
            if self.p.poll() is not None: raise RuntimeError("endpoint process exited")
            time.sleep(0.05)
        raise RuntimeError("endpoints did not start")
    def stop(self): self.p.kill(); self.p.wait()
    def __enter__(self): return self.start()
    def __exit__(self, *a): self.stop()
    def set_modes(self, modes):
        c = http.client.HTTPConnection("127.0.9.1", self.ctl_port, timeout=3); b = json.dumps({"modes": modes}).encode(); c.request("POST", "/", b, {"Content-Length": str(len(b))}); c.getresponse().read(); c.close()
    def rows(self, name):
        out = []
        for ln in open(os.path.join(self.wd, name)).read().splitlines():
            try: out.append(json.loads(ln))
            except ValueError: pass          # a partially written trailing line
        return out
    def ctx(self, tls):
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.load_verify_locations(self.cert); c.check_hostname = False
        if tls == "1.2": c.maximum_version = ssl.TLSVersion.TLSv1_2
        if tls == "1.3": c.minimum_version = ssl.TLSVersion.TLSv1_3
        return c
    def request(self, name, body: bytes, headers: dict, timeout=0.6, client_tls="any"):
        e = self.eps[name]; hd = {**headers, "Content-Length": str(len(body))}
        try:
            c = http.client.HTTPSConnection(e["ip"], e["port"], timeout=timeout, context=self.ctx(client_tls)) if e["tls"] != "none" else http.client.HTTPConnection(e["ip"], e["port"], timeout=timeout)
            c.request("POST", "/op", body, hd); r = c.getresponse(); data = r.read(); c.close(); return r.status, data
        except (OSError, http.client.HTTPException, ssl.SSLError) as ex: return None, str(type(ex).__name__).encode()


if __name__ == "__main__": serve(sys.argv[1])
