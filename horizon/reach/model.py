"""Effect model, labels/lineage, signed service-effect manifests, attestation and receipts (P44-01, 05, 06, 07). Enforcement code holds only a public-key Verifier: attestation is issued by an evidence service, never by this module."""
from __future__ import annotations
import base64, hashlib, json
from dataclasses import dataclass, field
from ..authz.keys import Signer
from ..authz.effect import canonical
from ..hpolicy.authority import EvidenceError

LABELS = ("PUBLIC", "INTERNAL", "SECRET"); RANK = {l: i for i, l in enumerate(LABELS)}
KEEP_OPS = {"identity", "b64", "rot13", "reverse", "weak_sanitize"}; CLEAR_OPS = {"hash", "redact"}
VERDICTS = ("ALLOW", "DENY", "UNKNOWN")
RECEIPT_DOMAIN = b"reach.receipt.v1\x00"


def worst(a, b): return a if RANK[a] >= RANK[b] else b


@dataclass(frozen=True)
class EffectiveEffect:
    """EffectiveEffect(p, i, d, e) of spec 64.2: principal p reaches destination d with effect e through intermediary i (None for a direct call)."""
    principal: str; intermediary: str | None; destination: tuple; effect: str; label: str; trust: str       # trust: direct | unverified-declaration | attested | receipt-evidenced


class ArtifactStore:
    """Trusted runtime artifact table: the broker takes payload bytes and labels from here, never from agent-supplied claims."""
    def __init__(self): self.a = {}; self.n = 0
    def put(self, value: str, label: str, parent=None, op=None) -> str:
        self.n += 1; aid = "art-%d" % self.n; self.a[aid] = {"value": value, "label": label, "parent": parent, "op": op}; return aid
    def transform(self, aid: str, op: str, fn) -> str:
        p = self.a[aid]; lab = "PUBLIC" if op in CLEAR_OPS else p["label"]
        if op not in KEEP_OPS | CLEAR_OPS: lab = p["label"]          # unknown transform: label is kept (conservative)
        return self.put(fn(p["value"]), lab, aid, op)
    def get(self, aid): return self.a[aid]


def manifest_body(service, version, controlled, ops, egress, key_b64, exp=2 ** 40) -> dict:
    return {"service": service, "version": version, "controlled": bool(controlled), "ops": sorted(ops), "egress": sorted(egress), "key": key_b64, "exp": exp}


def manifest_digest(m: dict) -> str: return "sha256:" + hashlib.sha256(b"reach.manifest.v1\x00" + canonical(m)).hexdigest()


def sign_manifest(signer: Signer, m: dict) -> dict: return {"body": m, "sig": base64.b64encode(signer.sign(b"reach.manifest.sig\x00" + canonical(m))).decode(), "operator_key": base64.b64encode(signer.public_raw()).decode()}


class Registry:
    """Service registry holding only a Verifier. UNVERIFIED = signed by the operator but not attested: its declarations are claims. ATTESTED = an evidence service bound the exact manifest digest. REVOKED after contrary independent evidence."""
    def __init__(self, verifier, clock): self.v, self.clock, self.s, self.log = verifier, clock, {}, []
    def declare(self, signed: dict, token: str | None = None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        m = signed["body"]; name = m["service"]
        try: Ed25519PublicKey.from_public_bytes(base64.b64decode(signed["operator_key"])).verify(base64.b64decode(signed["sig"]), b"reach.manifest.sig\x00" + canonical(m))
        except Exception: self.log.append((name, "BAD_MANIFEST_SIGNATURE")); return "REJECTED"
        status = "UNVERIFIED"
        if token:
            try:
                p = self.v.verify(token, now=self.clock())
                if p["kind"] == "ATTESTATION" and p["artifact"] == name and p["args_digest"] == manifest_digest(m) and p["claim"].get("key") == m["key"]: status = "ATTESTED"
                else: self.log.append((name, "ATTESTATION_NOT_BOUND_TO_MANIFEST"))
            except EvidenceError as e: self.log.append((name, "ATTESTATION_" + e.code))
        self.s[name] = {"manifest": m, "status": status}; return status
    def status(self, name): return self.s.get(name, {}).get("status", "UNKNOWN_SERVICE")
    def manifest(self, name): return self.s.get(name, {}).get("manifest")
    def revoke(self, name, why):
        if name in self.s: self.s[name]["status"] = "REVOKED"; self.log.append((name, "REVOKED: " + why))


def verify_receipt(header: str | None, manifest: dict | None, call: str) -> dict:
    """-> {state: MISSING|INVALID|MISMATCH|OK, effects}. OK = signed by the admitted service key, bound to this call id. Content is checked by the caller against the policy."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not header: return {"state": "MISSING", "effects": []}
    try:
        b, s = header.split("."); body = base64.b64decode(b); Ed25519PublicKey.from_public_bytes(base64.b64decode(manifest["key"])).verify(base64.b64decode(s), RECEIPT_DOMAIN + body); r = json.loads(body)
    except Exception: return {"state": "INVALID", "effects": []}
    if r.get("call") != call: return {"state": "MISMATCH", "effects": []}
    return {"state": "OK", "effects": r.get("effects", [])}
