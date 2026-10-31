"""Root-issuer trust store with rotation windows; verification-only public keys (P13-03). Private keys live only in the authority process (`Signer`); gateways and workers get a TrustStore."""
from __future__ import annotations
import os, stat, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


class TrustError(Exception):
    def __init__(self, code, msg): super().__init__(msg); self.code = code


class TrustStore:
    """kid -> (public key, issuer, not_before, not_after, revoked). Contains NO private material."""
    def __init__(self, clock=time.time): self.k: dict[str, dict] = {}; self.clock = clock

    def add(self, kid: str, issuer: str, public_raw: bytes, *, not_before: float, not_after: float):
        if kid in self.k: raise TrustError("DUPLICATE_KID", "kid already registered (rotation must use a new kid)")
        if not_after <= not_before: raise TrustError("BAD_WINDOW", "validity window is empty")
        self.k[kid] = {"pub": Ed25519PublicKey.from_public_bytes(public_raw), "iss": issuer, "nbf": not_before, "naf": not_after, "revoked": False}

    def revoke(self, kid: str):
        if kid not in self.k: raise TrustError("UNKNOWN_KID", kid)
        self.k[kid]["revoked"] = True

    def resolve(self, kid: str, issuer: str, at: float | None = None) -> Ed25519PublicKey:
        r = self.k.get(kid); at = self.clock() if at is None else at
        if r is None: raise TrustError("UNKNOWN_KID", "unknown key id")
        if r["revoked"]: raise TrustError("KEY_REVOKED", "key revoked")
        if r["iss"] != issuer: raise TrustError("ISSUER_MISMATCH", "key does not belong to this issuer")
        if not (r["nbf"] <= at < r["naf"]): raise TrustError("KEY_OUT_OF_WINDOW", "key not valid at this time")
        return r["pub"]

    def export_public(self) -> dict:
        return {kid: {"iss": r["iss"], "nbf": r["nbf"], "naf": r["naf"], "revoked": r["revoked"], "public": r["pub"].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()} for kid, r in self.k.items()}

    @classmethod
    def from_public(cls, doc: dict, clock=time.time):
        t = cls(clock)
        for kid, r in doc.items():
            if "private" in r or "secret" in r: raise TrustError("PRIVATE_MATERIAL", "trust documents must not contain private keys")
            t.add(kid, r["iss"], bytes.fromhex(r["public"]), not_before=r["nbf"], not_after=r["naf"]); t.k[kid]["revoked"] = bool(r.get("revoked"))
        return t


class Signer:
    """Held only by the call authority. Loads from a 0600 file owned by the service user, or generates in memory."""
    def __init__(self, kid: str, issuer: str, priv: Ed25519PrivateKey): self.kid, self.iss, self._p = kid, issuer, priv

    @classmethod
    def generate(cls, kid: str, issuer: str): return cls(kid, issuer, Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, kid: str, issuer: str, path: str):
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode): raise TrustError("BAD_KEY_FILE", "key must be a regular file")
        if st.st_mode & 0o077 or st.st_uid != os.getuid(): raise TrustError("BAD_KEY_FILE", "key file must be mode 0600 and owned by the service user")
        return cls(kid, issuer, serialization.load_pem_private_key(open(path, "rb").read(), None))

    def save(self, path: str):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f: f.write(self._p.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    def public_raw(self) -> bytes: return self._p.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    def sign(self, data: bytes) -> bytes: return self._p.sign(data)
    def __repr__(self): return f"Signer(kid={self.kid!r}, <private key hidden>)"
    def __reduce__(self): raise TypeError("Signer is not serialisable")
