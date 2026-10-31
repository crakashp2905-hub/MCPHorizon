"""Python SDK (P3-09/P3-11). Fail-closed: transport errors/timeouts on protected effects raise Denied, never return ALLOW."""
from __future__ import annotations
import http.client, json, socket


class Denied(Exception): pass
class HorizonError(Exception):
    def __init__(self, status, body): super().__init__(f"{status} {body}"); self.status, self.body = status, body


class _UnixConn(http.client.HTTPConnection):
    def __init__(self, path, timeout): super().__init__("localhost", timeout=timeout); self.path = path
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.sock.settimeout(self.timeout); self.sock.connect(self.path)


class Client:
    def __init__(self, token: str, unix_path: str | None = None, host: str = "127.0.0.1", port: int | None = None, timeout: float = 2.0):
        self.token, self.unix, self.host, self.port, self.timeout = token, unix_path, host, port, timeout

    def _call(self, method, path, body=None):
        c = _UnixConn(self.unix, self.timeout) if self.unix else http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            c.request(method, path, json.dumps(body) if body is not None else None,
                      {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
            r = c.getresponse(); data = json.loads(r.read() or b"{}")
        finally: c.close()
        if r.status >= 400: raise HorizonError(r.status, data)
        return data

    def decide(self, req: dict, protected: bool = True) -> dict:
        """Return the decision; on any transport failure return a synthetic DENY (protected) so callers cannot mistake it for ALLOW."""
        try: return self._call("POST", "/v2/decisions", req)
        except Exception as e:
            if protected: return {"verdict": "DENY", "reason_codes": ["SERVICE_UNREACHABLE"], "error": type(e).__name__}
            return {"verdict": "UNKNOWN", "reason_codes": ["SERVICE_UNREACHABLE"], "error": type(e).__name__}

    def require_allow(self, req: dict) -> dict:
        d = self.decide(req)
        if d["verdict"] not in ("ALLOW", "SHADOW_ALLOW"): raise Denied(f"{d['verdict']}: {d['reason_codes']}")
        return d

    def outcome(self, body): return self._call("POST", "/v2/outcomes", body)
    def artifact(self, a): return self._call("POST", "/v2/artifacts", {"artifact": a})
    def health(self): return self._call("GET", "/v2/health")
