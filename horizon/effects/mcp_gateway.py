"""Reference MCP stdio gateway that carries a REAL tools/call through authorization -> ledger -> sink -> receipt (blueprint S1-09). CANDIDATE.
Newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP stdio framing). Exposes ONE tool, `write_file`. The agent/client never touches the sink: this process holds the authority (in-process
Ed25519 signer + policy), mints a single-use permit for the exact effect only if policy allows, and writes through ProtectedFileWriter (permit verify, durable ledger, locked sink journal).
LIMITS: authority and gateway share one process here (test harness), so this is NOT the separate-principal deployment; keys are generated in memory; one effect type; no auth on the stdio client.
Run: python -m horizon.effects.mcp_gateway ROOT JOURNAL LEDGER_DB   (reserved/synthetic paths only)"""
from __future__ import annotations
import hashlib, json, os, sys, time
from horizon import normalize as N
from horizon.authz import effect as E
from horizon.authz.gateway import NonceStore, Verifier
from horizon.authz.keys import Signer, TrustStore
from horizon.effects.canonical import CanonicalEffect
from horizon.effects.filesink import FileSink, ProtectedFileWriter
from horizon.effects.ledger import EffectLedger

TOOL = {"name": "write_file", "description": "Write text to a file under the protected workspace.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}, "effect_id": {"type": "string"}}, "required": ["path", "content", "effect_id"], "additionalProperties": False}}


class Gateway:
    def __init__(self, root: str, journal: str, ledger_db: str, *, tenant="t1", principal="agent-a", server_id="srv-files", session_id="sess-1", gate=None):
        self.root = os.path.realpath(root); self.tenant, self.principal, self.server, self.session = tenant, principal, server_id, session_id
        self.s = Signer.generate("gk1", "iss"); ts = TrustStore(); ts.add("gk1", "iss", self.s.public_raw(), not_before=0, not_after=2 ** 40)
        self.v = Verifier(ts, NonceStore(), issuer="iss", audience="gw", contract_version="c1", policy_version=lambda: "p1")
        self.ledger = EffectLedger(ledger_db); self.sink = FileSink(self.root, journal); self.w = ProtectedFileWriter(self.v, self.ledger, self.sink, gate=gate)

    def _policy_allows(self, path: str) -> bool:
        """Authority policy: writes only to plain files directly inside the workspace root (no traversal, no symlinks escaping, no hidden files)."""
        real = os.path.realpath(path)
        return os.path.dirname(real) == self.root and not os.path.basename(real).startswith(".") and real == os.path.abspath(path)

    def _mint(self, ce: CanonicalEffect) -> str:
        now = int(time.time()); e = dict(v=1, iss="iss", sub=ce.principal, tenant=ce.tenant, effect=ce.effect, target=N.canonical_target(ce.target_kind, ce.target_raw), args_digest=ce.bound_args_digest(),
                                         contract_version="c1", policy_version="p1", aud="gw", iat=now - 1, exp=now + 30, nonce=os.urandom(8).hex(), decision_id="d-" + os.urandom(4).hex())
        return E.sign(self.s._p, "gk1", e)

    def call_write(self, a: dict) -> dict:
        if not (isinstance(a, dict) and set(a) == {"path", "content", "effect_id"} and all(isinstance(a[k], str) and a[k] for k in ("path", "effect_id")) and isinstance(a["content"], str)):
            return {"isError": True, "content": [{"type": "text", "text": "INVALID_ARGUMENTS"}]}
        path = os.path.join(self.root, a["path"]) if not os.path.isabs(a["path"]) else a["path"]; data = a["content"].encode()
        ce = CanonicalEffect(self.tenant, self.server, self.session, self.principal, "write", "file", path, {"sha256": hashlib.sha256(data).hexdigest()})
        if not self._policy_allows(path): return {"isError": True, "content": [{"type": "text", "text": "POLICY_DENIED"}], "structuredContent": {"status": "BLOCKED", "code": "POLICY_DENIED"}}
        r = self.w.write(self._mint(ce), ce, data, a["effect_id"])
        ok = r["status"] == "ALLOW_COMMITTED"
        return {"isError": not ok, "content": [{"type": "text", "text": r["status"] + (":" + r.get("code", "") if r.get("code") else "")}], "structuredContent": {**r, "ledger_state": self.ledger.state(a["effect_id"])}}

    def handle(self, req: dict):
        m, i = req.get("method"), req.get("id")
        if i is None: return None                                            # notifications: no reply
        if m == "initialize": res = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "horizon-effect-gateway", "version": "0"}}
        elif m == "tools/list": res = {"tools": [TOOL]}
        elif m == "tools/call":
            p = req.get("params") or {}
            if p.get("name") != "write_file": return {"jsonrpc": "2.0", "id": i, "error": {"code": -32602, "message": "unknown tool"}}
            res = self.call_write(p.get("arguments"))
        else: return {"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "method not found"}}
        return {"jsonrpc": "2.0", "id": i, "result": res}


def main(argv):
    g = Gateway(argv[1], argv[2], argv[3])
    for line in sys.stdin:
        try: req = json.loads(line)
        except ValueError: sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}) + "\n"); sys.stdout.flush(); continue
        if not isinstance(req, dict): continue
        out = g.handle(req)
        if out is not None: sys.stdout.write(json.dumps(out) + "\n"); sys.stdout.flush()


if __name__ == "__main__": main(sys.argv)
