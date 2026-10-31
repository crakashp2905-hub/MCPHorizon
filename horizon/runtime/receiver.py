"""Independent synthetic receiver (P25-13): a SEPARATE PROCESS that listens on local TCP ports and appends one JSON line per connection to a stats file: port, bytes received, sha256 of payload,
whether the payload contained the (non-sensitive) test canary. The enforcement code never writes this file, so it is an oracle, not a self-report."""
from __future__ import annotations
import hashlib, json, os, selectors, socket, subprocess, sys, time

CANARY = b"TEST_CANARY_NOT_SECRET"


def serve(ports: list, stats: str, ready: str):
    sel = selectors.DefaultSelector(); lst = []
    for p in ports:
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", p)); s.listen(64); s.setblocking(False); sel.register(s, selectors.EVENT_READ, ("L", p)); lst.append(s)
    open(ready, "w").write("1"); conns = {}
    while True:
        for key, _ in sel.select(0.2):
            kind, p = key.data
            if kind == "L":
                c, _a = key.fileobj.accept(); c.setblocking(False); sel.register(c, selectors.EVENT_READ, ("C", p)); conns[c] = [p, b"", time.time()]
            else:
                c = key.fileobj
                try: d = c.recv(65536)
                except BlockingIOError: continue
                except OSError: d = b""
                if d:
                    conns[c][1] += d
                    if b"\r\n\r\n" in conns[c][1] or len(conns[c][1]) > 1 << 20:
                        first = conns[c][1].split(b"\r\n", 1)[0]
                        try:
                            if first.startswith(b"GET /redir?to="): loc = first.split(b" ")[1][len(b"/redir?to="):]; c.sendall(b"HTTP/1.1 302 Found\r\nLocation: " + loc + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            else: c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                        except OSError: pass
                        d = b""
                if not d:
                    sel.unregister(c); pt, buf, _t = conns.pop(c); c.close()
                    with open(stats, "a") as f: f.write(json.dumps({"port": pt, "bytes": len(buf), "sha256": hashlib.sha256(buf).hexdigest(), "has_canary": CANARY in buf, "t": time.time()}) + "\n")


class Receiver:
    def __init__(self, ports, workdir):
        self.ports, self.stats, self.ready = ports, os.path.join(workdir, "stats.jsonl"), os.path.join(workdir, "ready"); open(self.stats, "w").close()
    def start(self):
        self.p = subprocess.Popen([sys.executable, "-m", "horizon.runtime.receiver", ",".join(map(str, self.ports)), self.stats, self.ready], cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if os.path.exists(self.ready): return self
            time.sleep(0.05)
        raise RuntimeError("receiver did not start")
    def stop(self): self.p.kill(); self.p.wait()
    def rows(self, port=None): return [r for r in map(json.loads, open(self.stats).read().splitlines()) if port is None or r["port"] == port]
    def bytes(self, port): return sum(r["bytes"] for r in self.rows(port))
    def __enter__(self): return self.start()
    def __exit__(self, *a): self.stop()


if __name__ == "__main__": serve([int(x) for x in sys.argv[1].split(",")], sys.argv[2], sys.argv[3])
