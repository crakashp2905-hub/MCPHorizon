"""One policy authority; issuers hold private keys, consumers hold only a Verifier. Modules never self-sign approvals (enforced structurally and by a static test)."""
from __future__ import annotations
import hashlib, json, os, time
from ..authz.keys import Signer, TrustStore, TrustError
from ..authz.effect import b64e, b64d, canonical

KINDS = {"APPROVAL", "TEST_STATUS", "SIGNATURE", "SMOKE_TEST", "REVIEW", "ATTESTATION"}
FIELDS = ("v", "kind", "role", "iss", "principal", "artifact", "args_digest", "object_version", "policy_version", "iat", "exp", "nonce", "claim")
DOMAIN = b"mcphorizon.evidence.v1\x00"


class EvidenceError(Exception):
    def __init__(self, code, msg=""): super().__init__(code + (": " + msg if msg else "")); self.code = code


def validate(p: dict) -> dict:
    if not isinstance(p, dict) or set(p) != set(FIELDS): raise EvidenceError("MALFORMED", "fields must be exactly %s" % (FIELDS,))
    if p["v"] != 1 or p["kind"] not in KINDS: raise EvidenceError("MALFORMED", "bad version or kind")
    for k in ("role", "iss", "principal", "artifact", "args_digest", "policy_version", "nonce"):
        if not isinstance(p[k], str) or not p[k] or len(p[k]) > 256: raise EvidenceError("MALFORMED", k)
    for k in ("object_version", "iat", "exp"):
        if not isinstance(p[k], int) or isinstance(p[k], bool) or p[k] < 0: raise EvidenceError("MALFORMED", k)
    if p["exp"] <= p["iat"]: raise EvidenceError("MALFORMED", "exp must be after iat")
    if not isinstance(p["claim"], dict) or len(canonical(p["claim"])) > 1024: raise EvidenceError("MALFORMED", "claim")
    return p


class Issuer:
    """Held by an evidence SERVICE (CI, approver, signer...). Never handed to an enforcement module."""
    def __init__(self, authority, role, signer): self._a, self.role, self._s = authority, role, signer
    def issue(self, kind, *, principal, artifact, args_digest="*", object_version=0, ttl=600, claim=None, nonce=None, now=None) -> str:
        if kind not in self._a.roles.get(self.role, ()): raise EvidenceError("ROLE_NOT_ALLOWED", "%s may not issue %s" % (self.role, kind))
        now = int(self._a.clock() if now is None else now)
        p = validate({"v": 1, "kind": kind, "role": self.role, "iss": self._s.iss, "principal": principal, "artifact": artifact, "args_digest": args_digest, "object_version": object_version,
                      "policy_version": self._a.version, "iat": now, "exp": now + int(ttl), "nonce": nonce or hashlib.sha256(os.urandom(16)).hexdigest()[:24], "claim": claim or {}})
        h = {"alg": "EdDSA", "typ": "horizon-evidence", "kid": self._s.kid}; s = b64e(canonical(h)) + "." + b64e(canonical(p))
        return s + "." + b64e(self._s.sign(DOMAIN + s.encode()))
    def forge_with_wrong_role(self, *a, **k): raise EvidenceError("NOT_SUPPORTED")


class Verifier:
    """Public-key-only view of the authority. This is all an enforcement module gets."""
    def __init__(self, authority): self._a = authority; self.seen = set()
    def verify(self, token, *, now=None, consume=False, policy_version=None) -> dict:
        now = int(self._a.clock() if now is None else now)
        try:
            h, p, sig = token.split("."); hd, pl = json.loads(b64d(h)), json.loads(b64d(p)); sg = b64d(sig)
        except Exception: raise EvidenceError("MALFORMED", "not a compact token")
        validate(pl)
        try: pub = self._a.trust.resolve(hd.get("kid", ""), pl["iss"], now)
        except TrustError as e: raise EvidenceError("UNTRUSTED_ISSUER", e.code)
        try: pub.verify(sg, DOMAIN + (h + "." + p).encode())
        except Exception: raise EvidenceError("BAD_SIGNATURE")
        if pl["kind"] not in self._a.roles.get(pl["role"], ()) or self._a.role_of_kid.get(hd["kid"]) != pl["role"]: raise EvidenceError("ROLE_NOT_ALLOWED", "issuer role may not issue this kind")
        if pl["policy_version"] != (policy_version or self._a.version): raise EvidenceError("POLICY_VERSION", "evidence bound to a different policy version")
        if not (pl["iat"] <= now < pl["exp"]): raise EvidenceError("EXPIRED" if now >= pl["exp"] else "NOT_YET_VALID")
        if consume:
            if pl["nonce"] in self.seen: raise EvidenceError("REPLAY")
            self.seen.add(pl["nonce"])
        return pl


class HorizonPolicy:
    def __init__(self, version="pol-1", clock=time.time):
        self.version, self.clock, self.trust, self.roles, self.role_of_kid = version, clock, TrustStore(clock), {}, {}
        self._env = Signer.generate("env-1", "horizon-authority"); self.trust.add("env-1", "horizon-authority", self._env.public_raw(), not_before=0, not_after=2 ** 40)
    def register_issuer(self, role, kinds, *, issuer_id=None) -> Issuer:
        if not set(kinds) <= KINDS: raise EvidenceError("MALFORMED", "unknown kind")
        kid = "k-%s-%d" % (role, len(self.role_of_kid) + 1); s = Signer.generate(kid, issuer_id or role); self.trust.add(kid, s.iss, s.public_raw(), not_before=0, not_after=2 ** 40)
        self.roles.setdefault(role, set()).update(kinds); self.role_of_kid[kid] = role; return Issuer(self, role, s)
    def verifier(self) -> Verifier: return Verifier(self)
    def seal(self, obj: dict) -> str:
        b = canonical(obj); return b64e(b) + "." + b64e(self._env.sign(b"mcphorizon.envelope.v1\x00" + b))
    def open(self, sealed: str) -> dict:
        try: b, s = sealed.split("."); raw = b64d(b); self.trust.resolve("env-1", "horizon-authority").verify(b64d(s), b"mcphorizon.envelope.v1\x00" + raw)
        except Exception: raise EvidenceError("BAD_ENVELOPE")
        return json.loads(raw)
