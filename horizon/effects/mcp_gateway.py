"""Reference MCP stdio gateway that carries a REAL tools/call through authorization -> ledger -> sink -> receipt (blueprint S1-09). CANDIDATE.
Newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP stdio framing). Exposes ONE tool, `write_file`. The agent/client never touches the sink: this process holds the authority (in-process
Ed25519 signer + policy), mints a single-use permit for the exact effect only if policy allows, and writes through EffectKernel (permit verify, durable ledger, locked sink journal); receipts are signed by a separate enforcement identity.
LIMITS: authority and gateway share one process here (test harness), so this is NOT the separate-principal deployment; keys are generated in memory; one effect type; no auth on the stdio client.
Run: python -m horizon.effects.mcp_gateway ROOT JOURNAL LEDGER_DB   (reserved/synthetic paths only)"""
from __future__ import annotations
import fnmatch, hashlib, json, os, sys, time
from horizon import normalize as N
from horizon.authz import effect as E
from horizon.authz.gateway import NonceStore, Verifier
from horizon.authz.issuer import LocalIssuer, IssuerDenied
from horizon.authz.keys import TrustStore
from horizon.contracts.v1 import ContractError
from horizon.effects.kernel import Context, EffectKernel, FileAdapter, _check_identities, make_enforcer_signer
from horizon.effects.filesink import FileSink
from horizon.effects.ledger import EffectLedger

TOOL = {"name": "write_file", "description": "Write text to a file under the protected workspace.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}, "effect_id": {"type": "string"}}, "required": ["path", "content", "effect_id"], "additionalProperties": False}}


# A bare error code invites a model to retry the same call (the live-agent run N3 saw looping on a blocked call). The text says the call is final and what IS allowed.
# Whether this changes live-agent behaviour is UNTESTED here (no live agent).
DENIAL_TEXT = "POLICY_DENIED: this write is not permitted and repeating it will not succeed. Writes are allowed only for files directly inside the configured root. Continue the task with an allowed path, or tell the user this action was blocked."

class Gateway:
    """Reference MCP gateway. Since K1 it holds NO execution logic of its own: every write goes through EffectKernel (one pipeline), the permit is minted by a separate issuer and covers a full CanonicalEffectV1, and the receipt is signed by a
    separate enforcement identity. Honest limit: a single-tool, single-sink reference; the unassured claim id below means a real Zero gate would deny until a claim is installed."""
    def __init__(self, root: str, journal: str, ledger_db: str, *, tenant="t1", principal="agent-a", server_id="srv-files", session_id="sess-1", gate=None, issuer=None, agent_id=None,
                 assurance_claim=("claim:unassured", 0), purpose="gateway-task", policy_epoch=1, deadline_s=30, clock=time.time, receipt_signer=None, allow_subdirs=False, allow_globs=None):
        self.allow_subdirs, self.allow_globs = allow_subdirs, (tuple(allow_globs) if allow_globs is not None else None)
        self.root = os.path.realpath(root); self.tenant, self.principal, self.server, self.session = tenant, principal, server_id, session_id
        self.agent_id, self.claim, self.purpose, self.policy_epoch, self.deadline_s, self.clock = agent_id or principal, assurance_claim, purpose, policy_epoch, deadline_s, clock
        self.policy_digest = "sha256:" + hashlib.sha256(json.dumps({"policy": "files-directly-in-root", "root": self.root}, sort_keys=True).encode()).hexdigest()
        # The gateway never holds a permit-signing key: it is given an issuer (default: a LocalIssuer in V1-required mode with this gateway's path policy; inject a ProcessIssuer to separate the key from this process).
        self.issuer = issuer if issuer is not None else LocalIssuer(lambda ce: self._policy_allows(ce.target_raw), require_v1=True); ts = self.issuer.trust_store()
        self.v = Verifier(ts, NonceStore(), issuer="iss", audience="gw", contract_version="c1", policy_version=lambda: "p1")
        self.ledger = EffectLedger(ledger_db); self.sink = FileSink(self.root, journal)
        rs = receipt_signer if receipt_signer is not None else make_enforcer_signer()      # separate enforcement identity; the kernel refuses a key that is also a permit-issuer key
        self.enforcer_trust = TrustStore(); self.enforcer_trust.add(rs.kid, "enforcer", rs.public_raw(), not_before=0, not_after=2 ** 40)
        self.kernel = EffectKernel(self.v, self.ledger, {"file": FileAdapter(self.sink)}, gate=gate, receipt_signer=rs, clock=clock)
        _check_identities(self.kernel)                                                                  # fail at construction, not at first write

    def _policy_allows(self, path: str) -> bool:
        """Authority policy: writes only to plain files directly inside the workspace root (no traversal, no symlinks escaping, no hidden files)."""
        real = os.path.realpath(path)
        if self.allow_subdirs:        # nested plain files inside root; any hidden component (.git, .github, .env, .ssh) is refused, and no symlink may be on the path
            rel = os.path.relpath(real, self.root)
            if self.allow_globs is not None and not any(fnmatch.fnmatchcase(rel, g) for g in self.allow_globs): return False       # least-privilege path list from the installed policy (fnmatch: '*' also crosses '/')
            return real == os.path.abspath(path) and not rel.startswith("..") and rel != "." and not any(c.startswith(".") for c in rel.split(os.sep))
        return os.path.dirname(real) == self.root and not os.path.basename(real).startswith(".") and real == os.path.abspath(path)

    def _blocked(self, code: str, text: str, **kw) -> dict:
        return {"isError": True, "content": [{"type": "text", "text": text}], "structuredContent": {"status": "BLOCKED", "code": code, "retryable": False, "effect": "DID_NOT_HAPPEN", **kw}}

    def call_write(self, a: dict) -> dict:
        if not (isinstance(a, dict) and set(a) == {"path", "content", "effect_id"} and all(isinstance(a[k], str) and a[k] for k in ("path", "effect_id")) and isinstance(a["content"], str)):
            return {"isError": True, "content": [{"type": "text", "text": "INVALID_ARGUMENTS"}]}
        path = os.path.join(self.root, a["path"]) if not os.path.isabs(a["path"]) else a["path"]; data = a["content"].encode()
        if not self._policy_allows(path): return self._blocked("POLICY_DENIED", DENIAL_TEXT, allowed="files directly inside the configured root")
        ctx = Context(a["effect_id"], self.tenant, self.agent_id, self.session, self.principal, self.server, "write_file", "mcp-stdio", self.purpose, self.policy_digest, self.policy_epoch, int(self.clock()) + self.deadline_s,
                      os.urandom(8).hex(), "trace-" + a["effect_id"], self.claim[0], self.claim[1])
        if self.allow_subdirs: os.makedirs(os.path.dirname(path), exist_ok=True)        # only reached after the policy allowed this exact path
        try: prep = self.kernel.prepare("file", {"path": path, "data": data}, ctx)
        except ContractError as e: return self._blocked(e.code, "NOT_AUTHORIZED:" + e.code)
        try: tok = self.issuer.mint(prep.ce, prep.v1)
        except IssuerDenied as e: return self._blocked(str(e), "NOT_AUTHORIZED:" + str(e))        # no permit => nothing started
        r = self.kernel.execute_v1(tok, "file", prep, {"path": path, "data": data})
        ok = r["status"] == "ALLOW_COMMITTED"
        return {"isError": not ok, "content": [{"type": "text", "text": r["status"] + (":" + r.get("code", "") if r.get("code") else "")}], "structuredContent": {**r, **({"sink_receipt": r["receipt"]["sink_receipt"]} if ok and "sink_receipt" in r.get("receipt", {}) else {}), "ledger_state": self.ledger.state(a["effect_id"])}}

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
