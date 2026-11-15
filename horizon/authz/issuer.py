"""PR-02 (masterplan M1): the permit-signing authority lives HERE, not in the gateway. The gateway receives an `Issuer` and can only ask it to mint a permit for a canonical effect; it never sees the private key.
`Issuer.mint` re-checks its own policy callable before signing (deny-only: the gateway's pre-check is advisory, the issuer decides whether a permit exists at all).
CANDIDATE / honest limit: this separates the key from the gateway CODE, not from its PROCESS: `LocalIssuer` is still in-process, so a compromised gateway process can reach it through memory. Process separation is `ProcessIssuer`
(a child that owns the key and signs over a pipe); OS-level isolation of that child needs the Linux host in masterplan section 12 and is NOT shown here. Imports nothing from horizon.effects (graph rule R4)."""
from __future__ import annotations
import hashlib, json, os, subprocess, sys, time
from dataclasses import asdict
from types import SimpleNamespace
from horizon.contracts.v1 import CanonicalEffectV1, ContractError
from horizon import normalize as N
from horizon.authz import effect as E
from horizon.authz.keys import Signer, TrustStore

TTL = 30


class IssuerDenied(Exception):
    pass


def _claims(ce, aud: str, iss: str, now: int) -> dict:
    return dict(v=1, iss=iss, sub=ce.principal, tenant=ce.tenant, effect=ce.effect, target=N.canonical_target(ce.target_kind, ce.target_raw), args_digest=ce.bound_args_digest(), contract_version="c1",
                policy_version="p1", aud=aud, iat=now - 1, exp=now + TTL, nonce=os.urandom(8).hex(), decision_id="d-" + os.urandom(4).hex())


def _check_v1(ce, v1) -> None:
    """The permit's bound args must carry the digest of a VALID CanonicalEffectV1 whose identity/effect fields match the permit's own, so one signature covers every V1 field (delegation, epochs, claim, idempotency, deadline, ...)."""
    try:
        if not isinstance(v1, CanonicalEffectV1): raise IssuerDenied("V1_REQUIRED")
        d = v1.digest()
    except ContractError: raise IssuerDenied("V1_INVALID")
    args = getattr(ce, "args", None)
    if not (isinstance(args, dict) and args.get("v1") == d): raise IssuerDenied("V1_BINDING_MISMATCH")
    if (v1.tenant_id, v1.tool_server_id, v1.session_id, v1.principal_id, v1.effect_class, v1.target_kind) != (ce.tenant, ce.server_id, ce.session_id, ce.principal, ce.effect, ce.target_kind): raise IssuerDenied("V1_BINDING_MISMATCH")
    if v1.target_canonical != N.canonical_target(ce.target_kind, ce.target_raw)["canonical_id"]: raise IssuerDenied("V1_BINDING_MISMATCH")


class LocalIssuer:
    """Holds the Signer privately; exposes only mint() and the public trust material."""
    def __init__(self, policy, *, kid="gk1", issuer="iss", aud="gw", require_v1: bool = False):
        self._s = Signer.generate(kid, issuer); self._policy = policy; self.kid, self.issuer, self.aud = kid, issuer, aud; self.require_v1 = require_v1

    def public_raw(self) -> bytes: return self._s.public_raw()

    def trust_store(self) -> TrustStore:
        ts = TrustStore(); ts.add(self.kid, self.issuer, self._s.public_raw(), not_before=0, not_after=2 ** 40); return ts

    def mint(self, ce, v1: CanonicalEffectV1 | None = None) -> str:
        if self.require_v1 or v1 is not None: _check_v1(ce, v1)
        if not self._policy(ce): raise IssuerDenied("POLICY_DENIED")
        return E.sign(self._s._p, self.kid, _claims(ce, self.aud, self.issuer, int(time.time())))


DOMAIN = b"mcphorizon.canonical-effect.v1\x00"   # duplicated from effects.canonical on purpose (R4: authz cannot import effects); tests pin parity
FIELDS = ("tenant", "server_id", "session_id", "principal", "effect", "target_kind", "target_raw")


def _wrap(d: dict):
    """Rebuild a ce-like object inside the signer from plain fields and recompute the bound digest itself (the caller's digest is never trusted)."""
    if not (isinstance(d, dict) and set(d) == set(FIELDS) | {"args"} and all(isinstance(d[k], str) and d[k] and "\x00" not in d[k] for k in FIELDS)): raise IssuerDenied("MALFORMED")
    if d["effect"] not in E.EFFECTS: raise IssuerDenied("UNKNOWN_EFFECT")
    body = E.canonical({"tenant": d["tenant"], "server": d["server_id"], "session": d["session_id"], "args": d["args"]})
    return SimpleNamespace(**{k: d[k] for k in FIELDS}, args=d["args"], bound_args_digest=lambda: "sha256:" + hashlib.sha256(DOMAIN + body).hexdigest())


def root_policy(root: str):
    """Named policy for the child: plain files directly inside `root`, no hidden names, no traversal."""
    root = os.path.realpath(root)
    def ok(ce) -> bool:
        real = os.path.realpath(ce.target_raw)
        return os.path.dirname(real) == root and not os.path.basename(real).startswith(".") and real == os.path.abspath(ce.target_raw)
    return ok


def _v1_from(d):
    if d is None: return None
    if not isinstance(d, dict): raise IssuerDenied("V1_INVALID")
    try: d = dict(d); d["artifact_lineage_digests"] = None if d.get("artifact_lineage_digests") is None else tuple(d["artifact_lineage_digests"]); return CanonicalEffectV1(**d)
    except TypeError: raise IssuerDenied("V1_INVALID")


def serve(root: str, require_v1: bool = False) -> int:
    """Child loop: JSON lines in, JSON lines out. The private key exists only in this process."""
    iss = LocalIssuer(root_policy(root), require_v1=require_v1)
    for line in sys.stdin:
        try:
            req = json.loads(line)
            if req.get("op") == "pub": out = {"ok": True, "pub": iss.public_raw().hex(), "kid": iss.kid, "issuer": iss.issuer}
            elif req.get("op") == "mint": out = {"ok": True, "token": iss.mint(_wrap(req.get("ce")), _v1_from(req.get("v1")))}
            else: out = {"ok": False, "code": "BAD_OP"}
        except IssuerDenied as e: out = {"ok": False, "code": str(e)}
        except Exception: out = {"ok": False, "code": "ERROR"}
        sys.stdout.write(json.dumps(out) + "\n"); sys.stdout.flush()
    return 0


class ProcessIssuer:
    """Key-owning child process; the parent (gateway) holds only a pipe. Separates the key from the gateway PROCESS memory (same uid here, so NOT an OS security boundary)."""
    def __init__(self, root: str, *, python=None, require_v1: bool = False):
        self._p = subprocess.Popen([python or sys.executable, "-B", "-m", "horizon.authz.issuer", root] + (["--require-v1"] if require_v1 else []), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, cwd=os.getcwd(), env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)})
        r = self._rpc({"op": "pub"}); self._pub = bytes.fromhex(r["pub"]); self.kid, self.issuer, self.aud = r["kid"], r["issuer"], "gw"

    def _rpc(self, req: dict) -> dict:
        try: self._p.stdin.write(json.dumps(req) + "\n"); self._p.stdin.flush(); line = self._p.stdout.readline()
        except (OSError, ValueError): raise IssuerDenied("ISSUER_DOWN")
        if not line: raise IssuerDenied("ISSUER_DOWN")
        return json.loads(line)

    def public_raw(self) -> bytes: return self._pub

    def trust_store(self) -> TrustStore:
        ts = TrustStore(); ts.add(self.kid, self.issuer, self._pub, not_before=0, not_after=2 ** 40); return ts

    def mint(self, ce, v1: CanonicalEffectV1 | None = None) -> str:
        r = self._rpc({"op": "mint", "ce": {**{k: getattr(ce, k) for k in FIELDS}, "args": ce.args}, "v1": None if v1 is None else asdict(v1)})
        if not r.get("ok"): raise IssuerDenied(r.get("code", "ERROR"))
        return r["token"]

    def close(self):
        try: self._p.stdin.close(); self._p.wait(timeout=5)
        except Exception: self._p.kill()


if __name__ == "__main__": sys.exit(serve(sys.argv[1], "--require-v1" in sys.argv[2:]))
