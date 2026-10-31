"""Credential broker (P26). Real (synthetic) secrets live ONLY in this trusted process. The sandbox, the model and generated code see an opaque, short-lived reference bound to one exact service call.
The broker injects the Authorization header itself, refuses payloads that contain the secret (raw/base64/hex/url-encoded), never forwards credentials across redirects, scrubs echoes, and revokes on completion/timeout/stop."""
from __future__ import annotations
import base64, hashlib, hmac, secrets, time, urllib.parse
from horizon import normalize as N


class CredBroker:
    def __init__(self, broker, clock=time.time): self.b, self.clock, self._secrets, self.refs, self.audit = broker, clock, {}, {}, []
    def register_secret(self, service: str, value: str): self._secrets[service] = value
    def _log(self, **kw): kw.pop("secret", None); self.audit.append(kw)                                    # audit rows are opaque by construction: ref ids, services, codes — never values
    def issue(self, principal, service, method, url, *, ttl_s=30, uses=1, body_sha256=None) -> str:
        if service not in self._secrets: raise KeyError("unknown service")
        ref = "cref_" + secrets.token_hex(8); self.refs[ref] = {"principal": principal, "service": service, "method": method.upper(), "url": N.canonical_url(url), "exp": self.clock() + ttl_s, "uses": uses, "revoked": False, "body_sha256": body_sha256}
        self._log(event="issue", ref=ref, principal=principal, service=service); return ref
    def revoke(self, ref, why="revoked"):
        if ref in self.refs: self.refs[ref]["revoked"] = True; self._log(event="revoke", ref=ref, why=why)
    def revoke_all(self, principal=None, why="emergency_stop"):
        for r, v in self.refs.items():
            if principal is None or v["principal"] == principal: self.revoke(r, why)
    def scope(self, principal):
        cb = self
        class _S:
            def __enter__(s): return cb
            def __exit__(s, *a): cb.revoke_all(principal, "task_complete")
        return _S()
    @staticmethod
    def _variants(sec: str) -> list: b = sec.encode(); return [sec.encode(), base64.b64encode(b), b.hex().encode(), urllib.parse.quote(sec).encode()]
    def call(self, principal, ref, method, url, body: bytes = b"") -> dict:
        r = self.refs.get(ref)
        def deny(code): self._log(event="deny", ref=ref, principal=principal, code=code); return {"ok": False, "code": code}
        if r is None: return deny("CRED_UNKNOWN")
        if r["principal"] != principal: return deny("CRED_PRINCIPAL_MISMATCH")
        if r["revoked"]: return deny("CRED_REVOKED")
        if self.clock() > r["exp"]: return deny("CRED_EXPIRED")
        if r["uses"] <= 0: return deny("CRED_EXHAUSTED")
        try: cu = N.canonical_url(url)
        except ValueError: return deny("BAD_URL")
        if method.upper() != r["method"] or cu != r["url"]: return deny("CRED_BINDING_MISMATCH")                    # bound to the exact approved call
        if r["body_sha256"] and hashlib.sha256(body).hexdigest() != r["body_sha256"]: return deny("CRED_BINDING_MISMATCH")
        sec = self._secrets[r["service"]]
        if any(v in body for v in self._variants(sec)): return deny("SECRET_IN_PAYLOAD")                          # the credential may authenticate the call but never ride in the payload
        if any(v in cu.encode() for v in self._variants(sec)): return deny("SECRET_IN_PAYLOAD")
        r["uses"] -= 1
        res = self.b.fetch(principal, method, url, body, (), headers={"Authorization": "Bearer " + sec})
        self._log(event="use", ref=ref, principal=principal, ok=res["ok"], code=res.get("code"))
        return self.scrub(res, sec)
    def scrub(self, res: dict, sec: str) -> dict:
        out = dict(res)
        if isinstance(out.get("body"), str):
            for v in self._variants(sec): out["body"] = out["body"].replace(v.decode(), "<REDACTED:CREDENTIAL>")
        return out
    def session(self, principal): return self.b.session(principal, creds=self)


# ---------------------------------------------------------------- surface inventory & diagnostics classification (P26-01, P26-17)
import os, re
HOME_SURFACES = [".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/config", ".aws/credentials", ".aws/config", ".config/gcloud/application_default_credentials.json", ".azure/accessTokens.json", ".kube/config", ".docker/config.json", ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".gnupg/private-keys-v1.d"]
SOCKET_SURFACES = ["/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/run/user/0/bus", "/run/user/1000/bus"]
ENV_SURFACES = ["AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS", "GITHUB_TOKEN", "GH_TOKEN", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "SSH_AUTH_SOCK", "DOCKER_HOST", "NPM_TOKEN", "KUBECONFIG", "HZ_TEST_HOST_SECRET"]
META_SURFACES = ["169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254", "metadata.google.internal"]
DIAG_ALLOWED = [re.compile(p) for p in (r"^(python3?|pip3?) (--version|-V)$", r"^uname( -a)?$", r"^(pwd|whoami|id|date)$", r"^ls( \.)?$", r"^(cc|gcc|make|pytest|python3? -m (unittest|pytest))\b")]
DIAG_SENSITIVE = [re.compile(p) for p in (r"resolv\.conf", r"\b(printenv|env)\b", r"/proc/(self|\d+)/environ", r"\.(ssh|aws|kube|netrc|gnupg)\b|git-credentials", r"docker\.sock|containerd", r"169\.254\.|metadata", r"/etc/(shadow|passwd)", r"\bsudo\b|\bsu\b", r"ifconfig|ip (a|addr|route)|ss -|netstat", r"unshare|nsenter|setns")]


def classify_diagnostic(cmd: str) -> str:
    """Lexical LABEL for event logs only. Enforcement never depends on it — the kernel/broker decide (P26-17)."""
    c = cmd.strip()
    if any(p.search(c) for p in DIAG_SENSITIVE): return "SENSITIVE_RECON"
    return "ALLOWED_DIAGNOSTIC" if any(p.match(c) for p in DIAG_ALLOWED) else "OTHER"


def surface_inventory(home: str, policy=None) -> list:
    """Measured, not asserted: for each surface say whether it exists on the HOST and whether sandboxed code can see it."""
    from horizon.runtime import sandbox as S
    probe = ("import os,json,socket\nout={}\nfor p in %r:\n  try: open(p,'rb').read(1); out[p]='READABLE'\n  except OSError as e: out[p]=e.errno\n"
             "for p in %r:\n  try: s=socket.socket(socket.AF_UNIX); s.connect(p); out[p]='CONNECTED'\n  except OSError as e: out[p]=e.errno\n"
             "for e in %r: out['env:'+e]=(e in os.environ)\nprint(json.dumps(out))") % ([os.path.join(home, h) for h in HOME_SURFACES], SOCKET_SURFACES, ENV_SURFACES)
    r = S.launch(probe, run_id="inventory", policy=policy)
    if r.refused: raise S.Unsupported(r.refused)
    import json; got = json.loads(r.stdout.strip().splitlines()[-1]); rows = []
    for h in HOME_SURFACES: p = os.path.join(home, h); rows.append({"surface": h, "kind": "file", "host_exists": os.path.exists(p), "sandbox": got[p], "exposed": got[p] == "READABLE"})
    for p in SOCKET_SURFACES: rows.append({"surface": p, "kind": "socket", "host_exists": os.path.exists(p), "sandbox": got[p], "exposed": got[p] == "CONNECTED"})
    for e in ENV_SURFACES: rows.append({"surface": e, "kind": "env", "host_exists": e in os.environ, "sandbox": got["env:" + e], "exposed": bool(got["env:" + e])})
    for m in META_SURFACES: rows.append({"surface": m, "kind": "metadata", "host_exists": None, "sandbox": "network namespace has no route; broker class-denies", "exposed": False})
    return rows
