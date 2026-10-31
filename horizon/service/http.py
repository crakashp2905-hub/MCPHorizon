"""Stdlib HTTP transport: Unix domain socket (mode 0600) or loopback-only TCP. Refuses non-loopback binds (P3-01)."""
from __future__ import annotations
import http.server, json, os, socket, socketserver, ipaddress, threading
from .core import Service, ApiError, MAX_BODY


def make_handler(svc: Service):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 10                                   # slowloris bound
        def log_message(self, *a): pass
        def _go(self, method):
            body = None
            if method == "POST":
                try: n = int(self.headers.get("Content-Length", "0"))
                except ValueError: n = -1
                if n < 0 or n > MAX_BODY: return self._send(413, ApiError(413, "TOO_LARGE", "body too large").body())
                raw = self.rfile.read(n)
                try: body = json.loads(raw or b"{}")
                except ValueError: return self._send(400, ApiError(400, "BAD_JSON", "invalid JSON").body())
            auth = self.headers.get("Authorization", "")
            bearer = auth[7:] if auth.startswith("Bearer ") else None
            status, out = svc.handle(method, self.path.split("?")[0], bearer, body, self.headers.get("X-Trace-Id"))
            self._send(status, out)
        def _send(self, status, obj):
            data = json.dumps(obj).encode()
            self.send_response(status); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
        def do_GET(self): self._go("GET")
        def do_POST(self): self._go("POST")
    return H


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    def get_request(self):
        req, _ = super().get_request(); return req, ("local", 0)


class TcpServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def serve(svc: Service, unix_path: str | None = None, host: str = "127.0.0.1", port: int = 0):
    h = make_handler(svc)
    if unix_path:
        if os.path.exists(unix_path): os.unlink(unix_path)
        old = os.umask(0o177)
        try: srv = UnixServer(unix_path, h)
        finally: os.umask(old)
        os.chmod(unix_path, 0o600)
        return srv
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("refusing to bind a non-loopback address; use a Unix socket or 127.0.0.1/::1")
    return TcpServer((host, port), h)


def start_thread(srv):
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start(); return t
