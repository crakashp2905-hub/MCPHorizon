"""Attested connector security-profile manifests and the guarantee cache (P46-03, P46-12).

A profile is the operator's CLAIM about an endpoint's guarantees. The registry treats a claim as evidence only if an evidence service (role `downgrade-attestor`, kind ATTESTATION) bound the exact profile digest. Unattested, expired or revoked profiles yield an all-UNKNOWN vector: 'real capability evidence' is kept apart from 'unverified tool metadata'.
Cached admission verdicts are keyed by (endpoint, profile digest, policy version, floor digest) and are dropped whenever the registry epoch changes (declare, revoke, expiry observed) or the policy version differs.
"""
import base64, hashlib, json
from ..authz.effect import canonical
from ..authz.keys import Signer
from ..hpolicy.authority import EvidenceError
from . import order as O


def profile_body(endpoint, version, claims: dict, tools=(), host="", port=0) -> dict:
    return {"endpoint": endpoint, "version": int(version), "claims": O.to_json({d: O.norm(d, v) if v is not None else None for d, v in claims.items()}), "tools": sorted(tools), "host": host, "port": port}


def profile_digest(body) -> str: return "sha256:" + hashlib.sha256(b"downgrade.profile.v1\x00" + canonical(body)).hexdigest()
def sign_profile(signer: Signer, body) -> dict: return {"body": body, "sig": base64.b64encode(signer.sign(b"downgrade.profile.sig\x00" + canonical(body))).decode(), "operator_key": base64.b64encode(signer.public_raw()).decode()}


class Registry:
    def __init__(self, verifier, clock):
        self.v, self.clock, self.p, self.log, self.epoch = verifier, clock, {}, [], 0
    def declare(self, signed, token=None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        b = signed["body"]; name = b["endpoint"]
        try: Ed25519PublicKey.from_public_bytes(base64.b64decode(signed["operator_key"])).verify(base64.b64decode(signed["sig"]), b"downgrade.profile.sig\x00" + canonical(b))
        except Exception: self.log.append((name, "BAD_PROFILE_SIGNATURE")); return "REJECTED"
        old = self.p.get(name)
        if old and b["version"] <= old["body"]["version"]: self.log.append((name, "STALE_VERSION")); return "REJECTED"          # no rollback to an older (possibly stronger-looking) profile
        status, exp = "UNVERIFIED", 0
        if token:
            try:
                pl = self.v.verify(token, now=self.clock())
                if pl["kind"] == "ATTESTATION" and pl["artifact"] == name and pl["args_digest"] == profile_digest(b) and pl["claim"].get("level") == "ATTESTED": status, exp = "ATTESTED", pl["exp"]
                else: self.log.append((name, "ATTESTATION_NOT_BOUND"))
            except EvidenceError as e: self.log.append((name, "ATTESTATION_" + e.code))
        self.p[name] = {"body": b, "status": status, "exp": exp, "digest": profile_digest(b)}; self.epoch += 1; return status
    def revoke(self, name, why):
        if name in self.p: self.p[name]["status"] = "REVOKED"; self.epoch += 1; self.log.append((name, "REVOKED: " + why))
    def status(self, name):
        e = self.p.get(name)
        if e is None: return "UNKNOWN_ENDPOINT"
        if e["status"] == "ATTESTED" and self.clock() >= e["exp"]: e["status"] = "EXPIRED"; self.epoch += 1
        return e["status"]
    def digest(self, name): return self.p[name]["digest"] if name in self.p else None
    def vector(self, name) -> dict:
        """Guarantees that count as evidence: only from an ATTESTED, unexpired profile. Everything else is UNKNOWN (None)."""
        if self.status(name) != "ATTESTED": return {d: None for d in O.DIMS}
        c = self.p[name]["body"]["claims"]; return {d: (O.norm(d, c[d]) if c.get(d) is not None else None) for d in O.DIMS}
    def claimed(self, name) -> dict:
        """Unverified metadata as claimed. Used only by the ablation that wrongly trusts it."""
        e = self.p.get(name); c = e["body"]["claims"] if e else {}
        return {d: (O.norm(d, c[d]) if c.get(d) is not None else None) for d in O.DIMS}
    def tools(self, name): return self.p[name]["body"]["tools"] if name in self.p else []


class Cache:
    """Admission verdict cache with explicit invalidation."""
    def __init__(self, registry, policy_version):
        self.r, self.pv, self.d, self.epoch, self.hits, self.invalidations = registry, policy_version, {}, registry.epoch, 0, 0
    def get(self, key, compute, policy_version):
        if self.r.epoch != self.epoch or policy_version != self.pv: self.d.clear(); self.epoch, self.pv = self.r.epoch, policy_version; self.invalidations += 1
        if key in self.d: self.hits += 1; return self.d[key]
        self.d[key] = compute(); return self.d[key]
