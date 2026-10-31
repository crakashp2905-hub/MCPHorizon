"""Local mock services run as SEPARATE processes (independent oracles): a credential-checking registry and a cloud-metadata simulator. Synthetic secrets only. Bind addresses are explicit; nothing is contacted."""
from __future__ import annotations
import base64, json, os, subprocess, sys, time, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

META_CRED = "TEST_CANARY_NOT_SECRET-metadata-credential"  # secret-scan:ignore synthetic canary


def _variants(secret: str) -> list:
    b = secret.encode(); return [secret, base64.b64encode(b).decode(), b.hex(), urllib.parse.quote(secret)]


def serve(role: str, host: str, port: int, stats: str, secret: str):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _rec(self, body: bytes, **kw):
            auth = self.headers.get("Authorization", ""); row = {"role": role, "method": self.command, "path": self.path, "t": time.time(), "bytes": len(body), "auth_present": bool(auth), "auth_ok": bool(secret) and auth == "Bearer " + secret,
                                                             "body_has_secret": bool(secret) and any(v.encode() in body or v.encode() in self.path.encode() for v in _variants(secret)), "body_has_canary": b"TEST_CANARY_NOT_SECRET" in body}; row.update(kw)
            with open(stats, "a") as f: f.write(json.dumps(row) + "\n")
        def _do(self):
            n = int(self.headers.get("Content-Length") or 0); body = self.rfile.read(n) if n else b""
            if role == "metadata":
                self._rec(body, served=True); out = json.dumps({"AccessKeyId": "TEST_CANARY_NOT_SECRET-akid", "SecretAccessKey": META_CRED}).encode(); code = 200
            elif self.path.startswith("/redir?to="): self._rec(body); self.send_response(302); self.send_header("Location", self.path[len("/redir?to="):]); self.send_header("Content-Length", "0"); self.end_headers(); return
            elif self.path.startswith("/echo-auth"): self._rec(body); out = json.dumps({"you_sent": self.headers.get("Authorization", "")}).encode(); code = 200
            elif self.path.startswith("/auth-check") or self.path.startswith("/publish"):
                ok = bool(secret) and self.headers.get("Authorization", "") == "Bearer " + secret; self._rec(body); out = b'{"authenticated": %s}' % (b"true" if ok else b"false"); code = 200 if ok else 401
            else: self._rec(body); out = b"ok"; code = 200
            self.send_response(code); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
        do_GET = do_POST = do_PUT = _do
    HTTPServer((host, port), H).serve_forever()


class Mock:
    def __init__(self, role, port, workdir, *, host="127.0.0.1", secret=""): self.role, self.port, self.host, self.secret, self.stats = role, port, host, secret, os.path.join(workdir, f"{role}-{port}.jsonl")
    def __enter__(self):
        open(self.stats, "w").close()
        self.p = subprocess.Popen([sys.executable, "-m", "horizon.runtime.mockservices", self.role, self.host, str(self.port), self.stats], env={**os.environ, "HZ_MOCK_SECRET": self.secret}, stderr=subprocess.DEVNULL)
        import socket
        for _ in range(100):
            try: socket.create_connection((self.host, self.port), timeout=0.2).close(); self.rows(); break
            except OSError: time.sleep(0.05)
        open(self.stats, "w").close(); return self
    def __exit__(self, *a): self.p.terminate(); self.p.wait(5)
    def rows(self): time.sleep(0.15); return [json.loads(l) for l in open(self.stats).read().splitlines() if l.strip()]


if __name__ == "__main__": serve(sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], os.environ.get("HZ_MOCK_SECRET", ""))
