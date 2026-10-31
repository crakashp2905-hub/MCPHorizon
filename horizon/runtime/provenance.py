"""Frozen-artifact manifest, digest verification, approval provenance, harness preflight (P23-01/09/14/15)."""
from __future__ import annotations
import hashlib, json, os, time
from horizon.authz.keys import Signer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def sha256_file(p) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()


def _msg(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def freeze(paths, root, signer: Signer, *, note="") -> dict:
    files = {os.path.relpath(p, root): {"sha256": sha256_file(p), "bytes": os.path.getsize(p)} for p in sorted(paths)}
    body = {"kind": "hz.freeze.v1", "kid": signer.kid, "files": files, "note": note}
    return {"body": body, "sig": signer.sign(_msg(body)).hex()}


def verify_manifest(m: dict, pub_raw: bytes) -> bool:
    try: Ed25519PublicKey.from_public_bytes(pub_raw).verify(bytes.fromhex(m["sig"]), _msg(m["body"])); return True
    except (InvalidSignature, KeyError, ValueError): return False


def verify_digests(m: dict, root) -> dict:
    """Returns {'ok':bool,'mismatch':[...],'missing':[...]}. Used before any benchmark input is read (P23-14)."""
    bad, miss = [], []
    for rel, d in m["body"]["files"].items():
        p = os.path.join(root, rel)
        if not os.path.isfile(p): miss.append(rel)
        elif sha256_file(p) != d["sha256"]: bad.append(rel)
    return {"ok": not bad and not miss, "mismatch": bad, "missing": miss}


class ApprovalError(Exception):
    def __init__(self, code): super().__init__(code); self.code = code


def issue_approval(signer: Signer, *, approver: str, role: str, policy_digest: str, scope: dict, ttl_s: int = 300, now=None) -> dict:
    if role not in ("user", "admin"): raise ApprovalError("ROLE_NOT_AUTHORIZED")                 # an agent can never mint an approval
    body = {"kind": "hz.approval.v1", "kid": signer.kid, "approver": approver, "role": role, "policy_digest": policy_digest, "scope": scope, "exp": int((now or time.time()) + ttl_s)}
    return {"body": body, "sig": signer.sign(_msg(body)).hex()}


def check_approval(a: dict, pub_raw: bytes, *, policy_digest: str, want_scope: dict, now=None) -> bool:
    if not verify_manifest(a, pub_raw): raise ApprovalError("BAD_SIGNATURE")
    b = a["body"]
    if b["role"] not in ("user", "admin"): raise ApprovalError("ROLE_NOT_AUTHORIZED")
    if (now or time.time()) > b["exp"]: raise ApprovalError("EXPIRED")
    if b["policy_digest"] != policy_digest: raise ApprovalError("POLICY_DIGEST_MISMATCH")      # approval was for a different policy
    if any(b["scope"].get(k) != v for k, v in want_scope.items()): raise ApprovalError("SCOPE_MISMATCH")
    return True


class Preflight:
    """Result of probing that the harness really is isolated. Importer refuses to open traces without an ok token."""
    def __init__(self, ok: bool, reason: str, evidence: dict): self.ok, self.reason, self.evidence = ok, reason, evidence


def preflight_isolation() -> Preflight:
    from horizon.runtime import sandbox as S
    if os.geteuid() != 0 or S.landlock_abi() < 4: return Preflight(False, "UNSUPPORTED environment: root + Landlock>=4 required", {})
    r = S.launch("import socket,os\ntry:\n  socket.create_connection(('127.0.0.1',9),timeout=1); print('NETWORK')\nexcept OSError as e: print('net-denied')\nprint(os.getuid())", run_id="preflight")
    if r.refused: return Preflight(False, f"launcher refused: {r.refused}", {})
    out = r.stdout.split()
    return Preflight(out == ["net-denied", "10001"], "ok" if out == ["net-denied", "10001"] else f"probe failed: {out}", {"policy_digest": r.policy_digest, "profile": r.profile})
