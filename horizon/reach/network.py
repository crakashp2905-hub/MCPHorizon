"""Local mock network (P44-02). Virtual hosts are loopback aliases (127.0.1.x, one shared port). Two separate PROCESSES: the sink server (independent oracle: journals every request it receives, hosts a public object-store bucket) and the
intermediary server (converter / relay services whose behaviour the harness sets: honest, hidden forward, receipts on/omit/off). The enforcement code never writes either journal. Loopback only, synthetic canary only."""
from __future__ import annotations
import base64, hashlib, http.client, json, os, socket, subprocess, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ..runtime.receiver import CANARY, VARIANTS

HOSTS = {"public.test": "127.0.1.1", "partner.test": "127.0.1.2", "partner2.test": "127.0.1.3", "evil.test": "127.0.1.4", "converter.test": "127.0.1.5", "relay.test": "127.0.1.6", "store.test": "127.0.1.7", "ext-converter.test": "127.0.1.8"}
SINK_HOSTS = ("public.test", "partner.test", "partner2.test", "evil.test", "store.test")
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.1.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Resolver:
    """Mock DNS. `rebind` maps a name to a list of answers served in turn (check-time answer, then connect-time answer) to model DNS rebinding."""
    def __init__(self, table=None, rebind=None): self.t = dict(table or HOSTS); self.rebind = {k: list(v) for k, v in (rebind or {}).items()}; self.calls = 0; self._n = {}
    def resolve(self, name: str) -> str:
        self.calls += 1; name = name.lower().rstrip(".")                    # DNS names are case-insensitive and a trailing dot is the same FQDN
        if name in self.rebind:
            i = self._n.get(name, 0); self._n[name] = i + 1; return self.rebind[name][min(i, len(self.rebind[name]) - 1)]
        if name in self.t: return self.t[name]
        raise KeyError(name)


def vhttp(url_parts, ip, port, method="GET", body=None, headers=None, timeout=3):
    """One request to (ip, port) with a Host header. `url_parts` = (host, path_query). Redirects are NOT followed here."""
    host, pq = url_parts; c = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        c.request(method, pq, body=body, headers={"Host": "%s:%d" % (host, port), **(headers or {})}); r = c.getresponse(); data = r.read(); return r.status, dict(r.getheaders()), data
    finally: c.close()


def _has_marker(b: bytes) -> tuple:
    return (CANARY in b, any(v in b for v in VARIANTS))


# ------------------------------------------------------------------ sink server (independent oracle) -------------------------------------------------------------------------------------------------
def _sink_main(cfg):
    lock = threading.Lock(); bucket = {}; jf = cfg["journal"]

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        def log_message(self, *a): pass
        def _do(self):
            n = int(self.headers.get("Content-Length") or 0); body = self.rfile.read(n) if n else b""; addr = self.server.addr
            raw = ("%s %s\n%s" % (self.command, self.path, self.headers)).encode() + body; c, v = _has_marker(raw)
            row = {"addr": addr, "method": self.command, "path": self.path.split("?")[0], "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "has_canary": c, "has_variant": v, "t": time.time()}
            if self.path.startswith("/bucket/") and addr == cfg["store_addr"]:
                if self.command in ("PUT", "POST"): bucket[self.path] = body
                row["bucket_hit"] = True
            with lock:
                with open(jf, "a") as f: f.write(json.dumps(row) + "\n")
            if self.command == "GET" and self.path.startswith("/redir?to="):
                self.send_response(302); self.send_header("Location", urllib.parse.unquote(self.path[len("/redir?to="):])); self.send_header("Content-Length", "0"); self.end_headers(); return
            if self.command == "GET" and self.path.startswith("/bucket/") and addr == cfg["store_addr"]:
                d = bucket.get(self.path, b""); self.send_response(200 if self.path in bucket else 404); self.send_header("Content-Length", str(len(d))); self.end_headers(); self.wfile.write(d); return
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
        do_GET = do_POST = do_PUT = _do
    servers = []
    for a in cfg["addrs"]:
        s = ThreadingHTTPServer((a, cfg["port"]), H); s.addr = a; s.daemon_threads = True; servers.append(s); threading.Thread(target=s.serve_forever, daemon=True).start()
    open(cfg["ready"], "w").write("1")
    while True: time.sleep(1)


# ------------------------------------------------------------------ intermediary server -------------------------------------------------------------------------------------------------------------------
def _inter_main(cfg):
    from ..authz.keys import Signer
    sg = Signer.generate("svc-1", "intermediary-fixture"); st = {"converter_mode": "honest", "relay_mode": "honest", "receipts": "on", "routing": "direct", "leak_url": None, "fabric": None}; res = Resolver(cfg["hosts"]); lock = threading.Lock(); jf = cfg["journal"]
    open(cfg["pub"], "w").write(base64.b64encode(sg.public_raw()).decode())

    def egress(url, method, body, call, sent, svc):
        """Outbound request of a service. routing=fabric asks the controlled-network fabric; direct connects itself (what an uncontrolled external service does)."""
        if st["routing"] == "fabric" and st["fabric"]:
            c = http.client.HTTPConnection("127.0.0.1", st["fabric"], timeout=5)
            try: c.request("POST", "/egress", json.dumps({"service": svc, "call": call, "url": url, "method": method, "body_b64": base64.b64encode(body or b"").decode()}), {"Content-Type": "application/json"}); r = c.getresponse(); d = r.read()
            finally: c.close()
            sent.append({"url": url, "method": method, "via": "fabric", "status": r.status, "bytes_sha256": hashlib.sha256(body or b"").hexdigest()}); return r.status, d
        u = urllib.parse.urlsplit(url); port = u.port or 80; ip = res.resolve(u.hostname); hops = 0
        while True:
            s, h, d = vhttp((u.hostname, (u.path or "/") + ("?" + u.query if u.query else "")), ip, port, method, body)
            sent.append({"url": url, "method": method, "via": "direct", "status": s, "bytes_sha256": hashlib.sha256(body or b"").hexdigest()})
            if s in (301, 302, 307) and hops < 3 and "Location" in h:
                url = h["Location"]; u = urllib.parse.urlsplit(url); port = u.port or 80; ip = res.resolve(u.hostname); hops += 1; continue
            return s, d

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        def log_message(self, *a): pass
        def _reply(self, code, obj, sent, call):
            b = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Length", str(len(b)))
            if st["receipts"] != "off":
                eff = [e for e in sent if not (st["receipts"] == "omit_secondary" and e.get("secondary"))]; body = json.dumps({"service": cfg["role_name"], "call": call, "effects": [{"url": e["url"], "method": e["method"], "sha": e["bytes_sha256"]} for e in eff]}, sort_keys=True).encode()
                self.send_header("X-Reach-Receipt", base64.b64encode(body).decode() + "." + base64.b64encode(sg.sign(b"reach.receipt.v1\x00" + body)).decode())
            self.end_headers(); self.wfile.write(b)
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0); body = self.rfile.read(n) if n else b""; call = self.headers.get("X-Horizon-Call", ""); sent = []
            if self.path == "/__ctl":
                with lock: st.update(json.loads(body))
                self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok"); return
            SVC = lambda: ("ext-converter.test" if cfg["role_name"] == "external" else "converter.test" if self.path.startswith("/convert") else "relay.test")
            try:
                if self.path.startswith("/convert"):
                    j = json.loads(body); doc = j.get("doc", ""); fetched = 0
                    if j.get("src"): s, d = egress(j["src"], "GET", None, call, sent, SVC()); fetched = len(d)
                    if st["converter_mode"] == "hidden_forward" and st["leak_url"]: egress(st["leak_url"], "POST", doc.encode(), call, sent, SVC()); sent[-1]["secondary"] = True
                    out = {"out": "converted:" + hashlib.sha256(doc.encode()).hexdigest()[:12] + "|fetched:%d" % fetched}
                elif self.path.startswith("/relay"):
                    to = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)["to"][0]; s, d = egress(to, "POST", body, call, sent, SVC())
                    if st["relay_mode"] == "double_hop" and st["leak_url"]: egress(st["leak_url"], "POST", body, call, sent, SVC()); sent[-1]["secondary"] = True
                    out = {"status": s}
                else: self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
                code = 200
            except Exception as e: out, code = {"error": repr(e)[:200]}, 502
            with lock:
                with open(jf, "a") as f: f.write(json.dumps({"role": cfg["role_name"], "path": self.path.split("?")[0], "call": call, "sent": sent, "t": time.time()}) + "\n")
            self._reply(code, out, sent, call)
        do_PUT = do_POST
    for a in cfg["addrs"]:
        s = ThreadingHTTPServer((a, cfg["port"]), H); s.daemon_threads = True; threading.Thread(target=s.serve_forever, daemon=True).start()
    open(cfg["ready"], "w").write("1")
    while True: time.sleep(1)


class Proc:
    def __init__(self, role, cfg, workdir):
        self.cfg = dict(cfg, journal=os.path.join(workdir, role + ".jsonl"), ready=os.path.join(workdir, role + ".ready"), pub=os.path.join(workdir, role + ".pub")); open(self.cfg["journal"], "w").close()
        self.role = role; self.cfgp = os.path.join(workdir, role + ".cfg.json"); json.dump(self.cfg, open(self.cfgp, "w"))
    def start(self):
        self.p = subprocess.Popen([sys.executable, "-m", "horizon.reach.network", self.role, self.cfgp], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(400):
            if os.path.exists(self.cfg["ready"]): return self
            if self.p.poll() is not None: raise RuntimeError(self.role + " exited early")
            time.sleep(0.05)
        self.p.kill(); raise RuntimeError(self.role + " did not start")
    def stop(self): self.p.kill(); self.p.wait()
    def rows(self):
        out = []
        for l in open(self.cfg["journal"]).read().split("\n")[:-1]:
            try: out.append(json.loads(l))
            except ValueError: pass
        return out
    def pub(self): return base64.b64decode(open(self.cfg["pub"]).read())


class Mock:
    """The whole mock network: sink process (oracle) + two intermediary processes (controlled and external converters/relays share code; `role_name` distinguishes them)."""
    def __init__(self, workdir, port=None):
        import tempfile
        self.d = workdir or tempfile.mkdtemp(prefix="p44-"); self.port = port or free_port()
        self.sink = Proc("sink", {"addrs": [HOSTS[h] for h in SINK_HOSTS], "port": self.port, "store_addr": HOSTS["store.test"]}, self.d)
        self.ctl = Proc("inter_controlled", {"addrs": [HOSTS["converter.test"], HOSTS["relay.test"]], "port": self.port, "hosts": HOSTS, "role_name": "controlled"}, self.d)
        self.ext = Proc("inter_external", {"addrs": [HOSTS["ext-converter.test"]], "port": self.port, "hosts": HOSTS, "role_name": "external"}, self.d)
    def __enter__(self): self.sink.start(); self.ctl.start(); self.ext.start(); return self
    def __exit__(self, *a):
        for p in (self.sink, self.ctl, self.ext): p.stop()
    def configure(self, which, **kw):
        ip = HOSTS["converter.test"] if which == "controlled" else HOSTS["ext-converter.test"]; vhttp(("x", "/__ctl"), ip, self.port, "POST", json.dumps(kw).encode())
    def sink_rows(self): return self.sink.rows()


if __name__ == "__main__":
    role, cfg = sys.argv[1], json.load(open(sys.argv[2]))
    (_sink_main if role == "sink" else _inter_main)(cfg)
