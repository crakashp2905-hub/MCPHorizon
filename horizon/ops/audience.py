"""Issuer/audience-bound credentials for MCP/UTCP authentication (P10-03). HS256 compact tokens, stdlib only.
Defends the token-passthrough / confused-deputy pattern: a token minted for service A is rejected by service B."""
from __future__ import annotations
import base64, hashlib, hmac, json, time


class AuthError(Exception):
    def __init__(self, code, msg): super().__init__(msg); self.code = code


def _b64(b: bytes) -> str: return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def _unb64(s: str) -> bytes:
    if not isinstance(s, str) or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in s): raise AuthError("MALFORMED", "bad base64url")  # secret-scan:ignore
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint(key: bytes, kid: str, *, iss: str, aud: str, sub: str, tenant: str, scopes=(), ttl_s: float = 300, now: float | None = None) -> str:
    now = time.time() if now is None else now; h = {"alg": "HS256", "typ": "JWT", "kid": kid}; p = {"iss": iss, "aud": aud, "sub": sub, "tenant": tenant, "scope": " ".join(scopes), "iat": int(now), "nbf": int(now), "exp": int(now + ttl_s)}
    s = _b64(json.dumps(h, sort_keys=True).encode()) + "." + _b64(json.dumps(p, sort_keys=True).encode())
    return s + "." + _b64(hmac.new(key, s.encode(), hashlib.sha256).digest())


class Validator:
    """One validator per protected resource: fixed issuer, fixed audience (this resource), key set by kid. No algorithm negotiation."""
    def __init__(self, *, issuer: str, audience: str, keys: dict[str, bytes], leeway_s: float = 5.0, max_ttl_s: float = 3600, clock=time.time, revoked: set | None = None):
        self.iss, self.aud, self.keys, self.leeway, self.max_ttl, self.clock, self.revoked = issuer, audience, keys, leeway_s, max_ttl_s, clock, revoked if revoked is not None else set()

    def validate(self, token: str, *, need_scopes=()) -> dict:
        parts = token.split(".") if isinstance(token, str) else []
        if len(parts) != 3: raise AuthError("MALFORMED", "not a compact token")
        try: h, p = json.loads(_unb64(parts[0])), json.loads(_unb64(parts[1]))
        except (ValueError, UnicodeDecodeError): raise AuthError("MALFORMED", "bad token JSON") from None
        if not isinstance(h, dict) or not isinstance(p, dict): raise AuthError("MALFORMED", "bad token JSON")
        if h.get("alg") != "HS256": raise AuthError("BAD_ALG", "only HS256 is accepted")                       # rejects alg=none and algorithm confusion
        key = self.keys.get(h.get("kid"))
        if key is None: raise AuthError("UNKNOWN_KEY", "unknown or revoked key id")
        if not hmac.compare_digest(_unb64(parts[2]), hmac.new(key, (parts[0] + "." + parts[1]).encode(), hashlib.sha256).digest()): raise AuthError("BAD_SIGNATURE", "signature mismatch")
        if p.get("iss") != self.iss: raise AuthError("BAD_ISSUER", "issuer not trusted")
        aud = p.get("aud")
        if aud != self.aud: raise AuthError("BAD_AUDIENCE", "token was not issued for this resource")             # exact match; lists/wildcards are not accepted
        now = self.clock()
        try: exp, nbf, iat = float(p["exp"]), float(p["nbf"]), float(p["iat"])
        except (KeyError, TypeError, ValueError): raise AuthError("MALFORMED", "missing time claims") from None
        if now > exp + self.leeway: raise AuthError("EXPIRED", "token expired")
        if now + self.leeway < nbf: raise AuthError("NOT_YET_VALID", "token not yet valid")
        if exp - iat > self.max_ttl: raise AuthError("TTL_TOO_LONG", "token lifetime exceeds policy")
        if not p.get("sub") or not p.get("tenant"): raise AuthError("MALFORMED", "missing subject or tenant")
        if p.get("jti") in self.revoked or digest(token) in self.revoked: raise AuthError("REVOKED", "token revoked")
        have = set(str(p.get("scope", "")).split()); missing = set(need_scopes) - have
        if missing: raise AuthError("INSUFFICIENT_SCOPE", f"missing scopes {sorted(missing)}")
        return p


def digest(token: str) -> str: return hashlib.sha256(token.encode()).hexdigest()
