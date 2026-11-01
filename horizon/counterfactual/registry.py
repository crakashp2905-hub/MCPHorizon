"""Mock package registry as a SEPARATE process with an append-only journal (independent oracle for publication effects). Loopback only."""
import json, os, subprocess, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer


def serve(port, journal):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0); b = json.loads(self.rfile.read(n) or b"{}")
            open(journal, "a").write(json.dumps(b, sort_keys=True) + "\n"); o = b'{"ok": true}'; self.send_response(200); self.send_header("Content-Length", str(len(o))); self.end_headers(); self.wfile.write(o)
    HTTPServer(("127.0.0.1", port), H).serve_forever()


class Registry:
    def __init__(self, port, workdir): self.port, self.journal = port, os.path.join(workdir, "registry.jsonl"); open(self.journal, "w").close()
    @property
    def url(self): return "http://127.0.0.1:%d" % self.port
    def __enter__(self):
        import socket
        self.p = subprocess.Popen([sys.executable, "-m", "horizon.counterfactual.registry", str(self.port), self.journal], cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(200):
            try: socket.create_connection(("127.0.0.1", self.port), timeout=.2).close(); return self
            except OSError: time.sleep(.05)
        raise RuntimeError("registry did not start")
    def __exit__(self, *a): self.p.terminate(); self.p.wait(5)
    def entries(self): return [json.loads(l) for l in open(self.journal).read().splitlines() if l.strip()]


if __name__ == "__main__": serve(int(sys.argv[1]), sys.argv[2])
