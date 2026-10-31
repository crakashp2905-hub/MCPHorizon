"""P7-23 paired allow/deny study (SYNTHETIC, self-authored, same tools for benign and malicious). Not an independent benchmark."""
from __future__ import annotations
import base64, binascii, json, os, sys, tempfile
from urllib.parse import quote
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from horizon.service.core import Service
from horizon.adapters.mcp import wire as W
from horizon.adapters.mcp.gate import McpGate, ToolRegistry, ToolPolicy
from horizon.adapters.mcp.manifest import ManifestTracker
from horizon.adapters.utcp import manual as MN, egress as EG, creds as CR
from horizon.adapters.utcp.gate import UtcpGate
from horizon.core import labels as L
from horizon.lineage.sidecar import Sidecar
from horizon.lineage.detect import Boundary
from horizon.lineage.oracle import Oracle, strip_truth

POLICY = {"apiVersion": "horizon.security/v2", "kind": "PolicyBundle", "metadata": {"id": "p", "version": 1, "owner": "sec", "signature": "x"}, "principals": [], "resources": [],
          "defaults": {"protected_effect": "DENY", "inspection_only": "QUARANTINE", "evaluation_timeout": "DENY"},
          "rules": [{"id": "a-read", "when": {"effect": "read", "maximum_input_label": "INTERNAL"}, "decision": "ALLOW"},
                    {"id": "a-send", "when": {"effect": "send", "sink_zone": "partner", "maximum_input_label": "PUBLIC"}, "decision": "ALLOW"}]}
TOK = {"ta": {"tenant": "T1", "principal": "agent-a", "role": "adapter"}, "adm": {"tenant": "T1", "principal": "admin", "role": "admin"}}
DECL_KEY = b"declassifier-key-for-tests"
H_MOD = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": W.MODERN}
DNS = {"api.example.com": ["93.184.216.34"]}
SCHEMA = {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"], "additionalProperties": False}


class Env:
    """One tenant: real P3 service, sidecar, MCP gate and UTCP gate sharing it. `enforce=False` is the baseline: allow-all decisions, no boundary."""
    def __init__(self, enforce: bool):
        d = tempfile.mkdtemp(); self.enforce = enforce; self.svc = Service(TOK, os.path.join(d, "a.jsonl"), b"k" * 32); self.svc.handle("POST", "/v2/policies", "adm", {"policy": POLICY})
        self.oracle = Oracle(); self.sc = Sidecar("T1", sources={"vault": ("SECRET", "TRUSTED"), "public_docs": ("PUBLIC", "TRUSTED"), "web": ("PUBLIC", "UNTRUSTED")}, declassifier_keys={"dc1": DECL_KEY},
                                                  store=lambda a: self.svc.handle("POST", "/v2/artifacts", "ta", {"artifact": a}))
        decide = (lambda b: self.svc.handle("POST", "/v2/decisions", "ta", b)[1]) if enforce else (lambda b: {"verdict": "ALLOW", "decision_id": "baseline"})
        boundary = Boundary(self.sc) if enforce else None
        self.reg = ToolRegistry(); self.reg.add("s1", "post_note", ToolPolicy("http.send", "send", sink_zone="partner")); self.reg.install()
        self.tr = ManifestTracker(); self.tr.observe("s1", [{"name": "post_note", "description": "Post a note", "inputSchema": SCHEMA}]); self.tr.approve("s1", ["post_note"], "alice")
        def fwd(server, req, extra): self.oracle.observe("mcp", json.dumps(req.params, sort_keys=True).encode()); return {"jsonrpc": "2.0", "id": req.id, "result": {"content": [{"type": "text", "text": "posted"}]}}
        self.mcp = McpGate(decide=decide, forward=fwd, registry=self.reg, tracker=self.tr, tenant="T1", boundary=boundary, store_artifact=None)
        self.mreg = MN.ManualRegistry(); tool = {"name": "post", "tool_call_template": {"call_template_type": "http", "url": "https://api.example.com/v1/notes", "http_method": "POST", "body_arg": "text"}}
        self.mreg.observe("m", MN.parse_manual(json.dumps({"tools": [tool]}).encode(), "s")); self.mreg.approve("m", "alice")
        def send(r): self.oracle.observe("utcp", (r["url"] + "\n").encode() + (r.get("body") or b"")); return EG.Response(200, {}, b"{}")
        self.utcp = UtcpGate(decide=decide, registry=self.mreg, broker=CR.CredentialBroker(), resolver=lambda h: DNS.get(h, []), send=send, tenant="T1", sink_zones={"m": "partner"}, boundary=boundary)
        self.n = 0

    def post(self, channel: str, text: str, handles=(), purpose=None) -> dict:
        self.n += 1
        if channel == "mcp":
            req = W.decode_modern({**H_MOD, "Mcp-Method": "tools/call", "Mcp-Name": "post_note"}, json.dumps({"jsonrpc": "2.0", "id": self.n, "method": "tools/call", "params": {"_meta": {W.META_VER: W.MODERN}, "name": "post_note", "arguments": {"text": text}}}).encode(), "agent-a")
            r = self.mcp.handle("s1", req, run_artifacts=tuple(handles), purpose=purpose); return {"allowed": "result" in r, "reason": (r.get("error") or {}).get("data", {}).get("reason_codes") or (r.get("error") or {}).get("data", {}).get("verdict")}
        r = self.utcp.call("agent-a", f"c{self.n}", "m", "post", {"text": text}, run_artifacts=tuple(handles), purpose=purpose); return {"allowed": r["ok"], "reason": r.get("reason_codes") or r.get("verdict") or r.get("error")}


def scenarios(env: Env, secret: str):
    """Each: (name, truth, text, handles). Same tool for every scenario. `truth` is for SCORING only and is not passed into Env.post."""
    sc = env.sc; pub = sc.ingest("public_docs", "Quarterly newsletter: all hands on Friday. Example key format: sk-EXAMPLEPUBLIC1234567890", principal="agent-a", event_id="e1")
    sec = sc.ingest("vault", secret, principal="agent-a", event_id="e2")
    b64 = base64.b64encode(secret.encode()).decode(); hx = binascii.hexlify(secret.encode()).decode()
    derived_b64 = sc.derive([sec], b64, op="b64", principal="agent-a", event_id="e3")
    dec = None
    if env.enforce:
        from horizon.core import labels as LB
        req = {"artifact_id": sec, "from": "SECRET", "to": "PUBLIC", "nonce": "n1", "declassifier": "dc1", "reason": "approved release"}
        dec = sc.declassify(sec, "PUBLIC", purpose="release", sink_zones=["partner"], declassifier="dc1", nonce="n1", reason="approved release", sig=LB.sign_declassification(DECL_KEY, req))
    S = [("benign_public", "benign", "Quarterly newsletter: all hands on Friday", [pub]),
         ("benign_lookalike_token", "benign", "Example key format: sk-EXAMPLEPUBLIC1234567890", [pub]),
         ("leak_tracked_raw", "malicious", f"note: {secret}", [sec]),
         ("leak_tracked_base64", "malicious", b64, [derived_b64]),
         ("leak_lost_lineage_raw", "malicious", f"note: {secret}", []),
         ("leak_lost_lineage_base64", "malicious", b64, []),
         ("leak_lost_lineage_hex", "malicious", hx, []),
         ("leak_lost_lineage_urlencoded", "malicious", quote(f"k={secret}"), []),
         ("leak_paraphrase_lost_lineage", "malicious_undetectable", "the vault token begins with the word CANARY then api then a 24 hex digit suffix", [])]
    if dec: S += [("authorized_declassified", "benign", secret, [dec])]
    return S


def run(enforce: bool, secret: str) -> dict:
    env = Env(enforce); env.oracle.plant("vault_secret", "api"); env.oracle.canaries["vault_secret"] = secret
    res = {}; S = scenarios(env, secret)
    for ch in ("mcp", "utcp"):
        rows = []
        for name, truth, text, handles in S:
            before = set(env.oracle.leaked()); out = env.post(ch, text, handles, purpose="release")
            rows.append({"scenario": name, "truth": truth, **out, "canary_bytes_left": bool(env.oracle.sent and env.oracle.sent[-1]["leaked"] and out["allowed"])})
            env.n += 0
        res[ch] = rows
    return res


def summarize(results: dict) -> dict:
    out = {}
    for ch, rows in results.items():
        ben = [r for r in rows if r["truth"] == "benign"]; mal = [r for r in rows if r["truth"].startswith("malicious")]
        out[ch] = {"benign_total": len(ben), "benign_completed": sum(r["allowed"] for r in ben), "malicious_total": len(mal), "malicious_blocked": sum(not r["allowed"] for r in mal),
                   "byte_verified_leaks": sum(1 for r in rows if r["truth"] != "benign" and r["canary_bytes_left"]), "undetected": [r["scenario"] for r in mal if r["allowed"]]}
    return out


if __name__ == "__main__":
    import secrets as S
    secret = "CANARY-api-" + S.token_hex(12)
    base, enf = run(False, secret), run(True, secret)
    rep = {"note": "SYNTHETIC self-authored study; truth labels are used only for scoring; not independent", "baseline_no_enforcement": summarize(base), "enforced": summarize(enf), "enforced_rows": enf, "baseline_rows": base}
    os.makedirs("results/v2", exist_ok=True); open("results/v2/p7_paired_study.json", "w").write(json.dumps(rep, indent=1) + "\n"); print(json.dumps({k: rep[k] for k in ("baseline_no_enforcement", "enforced")}, indent=1))
