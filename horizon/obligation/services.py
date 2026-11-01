"""Mock evidence services + the deploy target (independent oracle). Loopback only. Evidence services hold their OWN Issuer (private key); the enforcement engine never sees one.
The deploy target is a SEPARATE PROCESS with an append-only journal: whether a commit really happened is read from it, never from the engine."""
from __future__ import annotations
import json, os, subprocess, sys, threading, time, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class _Srv:
    def __init__(self, handler_fn):
        outer = self
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _go(self):
                u = urllib.parse.urlsplit(self.path); q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
                n = int(self.headers.get("Content-Length") or 0); body = json.loads(self.rfile.read(n) or b"{}") if n else {}
                code, out = handler_fn(self.command, u.path, q, body); b = json.dumps(out).encode()
                self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
            do_GET = do_POST = _go
        self.httpd = HTTPServer(("127.0.0.1", 0), H); self.port = self.httpd.server_address[1]; self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
    def __enter__(self): self.t.start(); return self
    def __exit__(self, *a): self.httpd.shutdown(); self.httpd.server_close()
    def url(self, path): return "http://127.0.0.1:%d%s" % (self.port, path)


def call(url, method="GET", body=None, timeout=3):
    assert urllib.parse.urlsplit(url).hostname == "127.0.0.1", "loopback only"
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")


class CIService(_Srv):
    """Build/test status. `results` is the CI system's own state (set by the harness when a pipeline actually ran)."""
    def __init__(self, issuer, kind="TEST_STATUS"):
        self.issuer, self.kind, self.results = issuer, kind, {}
        super().__init__(self.handle)
    def handle(self, m, path, q, body):
        r = self.results.get(q.get("digest"))
        if r is None: return 404, {"error": "no such run"}
        return 200, {"token": self.issuer.issue(self.kind, principal=q.get("principal", "agent"), artifact=q["digest"], object_version=int(q.get("ver", 1)), ttl=int(q.get("ttl", 600)), claim={"result": r})}


class ApprovalService(_Srv):
    """Human approvals. Refuses self-approval on its own (independent of the engine's check)."""
    def __init__(self, issuers: dict):
        self.issuers, self.granted = issuers, {}      # approver id -> Issuer; (digest, args_digest) granted by whom
        super().__init__(self.handle)
    def handle(self, m, path, q, body):
        ap = q.get("approver"); iss = self.issuers.get(ap)
        if iss is None: return 403, {"error": "unknown approver"}
        if ap == q.get("requester"): return 403, {"error": "self-approval refused"}
        if (q["digest"], q["args"]) not in self.granted.get(ap, set()): return 403, {"error": "approver has not approved this change"}
        return 200, {"token": iss.issue("APPROVAL", principal=q["requester"], artifact=q["digest"], args_digest=q["args"], object_version=int(q.get("ver", 1)), ttl=int(q.get("ttl", 600)))}


class SigService(_Srv):
    """Verifies a REAL Ed25519 signature over the artifact digest against its own key list and only then issues SIGNATURE evidence."""
    def __init__(self, issuer, keys: dict):
        self.issuer, self.keys = issuer, keys           # signer id -> raw public key bytes
        super().__init__(self.handle)
    def handle(self, m, path, q, body):
        try:
            Ed25519PublicKey.from_public_bytes(self.keys[body["signer"]]).verify(bytes.fromhex(body["sig"]), body["digest"].encode())
        except Exception: return 403, {"error": "signature does not verify"}
        return 200, {"token": self.issuer.issue("SIGNATURE", principal=body.get("principal", "agent"), artifact=body["digest"], object_version=int(body.get("ver", 1)), ttl=int(body.get("ttl", 600)), claim={"signer": body["signer"]})}


def deploy_server(port, journal):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0); b = json.loads(self.rfile.read(n) or b"{}")
            with open(journal, "a") as f: f.write(json.dumps({"t": time.time(), "artifact": b.get("artifact"), "args": b.get("args"), "task": b.get("task"), "branch": b.get("branch"), "op": b.get("op"), "action": b.get("action")}) + "\n")
            o = b'{"committed": true}'; self.send_response(200); self.send_header("Content-Length", str(len(o))); self.end_headers(); self.wfile.write(o)
    HTTPServer(("127.0.0.1", port), H).serve_forever()


class DeployTarget:
    """Independent oracle: a separate process that commits whatever it is asked to and journals it. It has NO policy of its own, on purpose."""
    def __init__(self, port, workdir): self.port, self.journal = port, os.path.join(workdir, "deploy.jsonl"); open(self.journal, "w").close()
    def __enter__(self):
        self.p = subprocess.Popen([sys.executable, "-m", "horizon.obligation.services", str(self.port), self.journal], cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import socket
        for _ in range(200):
            try: socket.create_connection(("127.0.0.1", self.port), timeout=.2).close(); return self
            except OSError:
                if self.p.poll() is not None: raise RuntimeError("deploy target exited early")
                time.sleep(.05)
        self.p.kill(); raise RuntimeError("deploy target did not start")
    def __exit__(self, *a): self.p.terminate(); self.p.wait(5)
    def deploy(self, **body): return call("http://127.0.0.1:%d/deploy" % self.port, "POST", body)
    def commits(self): return [json.loads(l) for l in open(self.journal).read().splitlines() if l.strip()]


if __name__ == "__main__": deploy_server(int(sys.argv[1]), sys.argv[2])
