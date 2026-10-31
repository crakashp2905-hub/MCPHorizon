"""AuthorizedEffect v1: the claim a call-authority signs about ONE concrete effect (P13-02, P13-04). Canonical JSON, domain-separated digest, JWS-compact (RFC 7515, alg EdDSA per RFC 8037) envelope."""
from __future__ import annotations
import base64, hashlib, json, re

VERSION = 1
TYP = "mcphorizon-effect+jws"
DOMAIN = b"mcphorizon.authorized-effect.v1\x00"
FIELDS = ("v", "iss", "sub", "tenant", "effect", "target", "args_digest", "contract_version", "policy_version", "aud", "iat", "exp", "nonce", "decision_id")
EFFECTS = {"read", "list", "write", "modify", "delete", "execute", "send", "admin"}
HEX64 = re.compile(r"sha256:[0-9a-f]{64}")
MAX_TOKEN = 4096


class EffectError(ValueError):
    def __init__(self, code, msg): super().__init__(msg); self.code = code


def b64e(b: bytes) -> str: return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64d(s: str) -> bytes:
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s): raise EffectError("MALFORMED", "bad base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj: dict) -> bytes: return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def validate(e: dict) -> dict:
    if not isinstance(e, dict): raise EffectError("MALFORMED", "effect must be an object")
    if set(e) != set(FIELDS): raise EffectError("MALFORMED", f"fields must be exactly {FIELDS}")                       # no unknown fields: nothing unsigned-but-trusted
    if e["v"] != VERSION: raise EffectError("VERSION", "unsupported effect version")
    for k in ("iss", "sub", "tenant", "aud", "contract_version", "policy_version", "decision_id", "nonce"):
        if not isinstance(e[k], str) or not e[k] or len(e[k]) > 256: raise EffectError("MALFORMED", f"{k} must be a non-empty string")
    if e["effect"] not in EFFECTS: raise EffectError("MALFORMED", "unknown effect")
    t = e["target"]
    if not (isinstance(t, dict) and set(t) == {"kind", "canonical_id"} and all(isinstance(v, str) and v and len(v) <= 2048 for v in t.values())): raise EffectError("MALFORMED", "target must be {kind, canonical_id}")
    if not (isinstance(e["args_digest"], str) and HEX64.fullmatch(e["args_digest"])): raise EffectError("MALFORMED", "args_digest must be sha256:<hex>")
    for k in ("iat", "exp"):
        if not isinstance(e[k], int) or isinstance(e[k], bool) or e[k] < 0: raise EffectError("MALFORMED", f"{k} must be a non-negative integer")
    if e["exp"] <= e["iat"]: raise EffectError("MALFORMED", "exp must be after iat")
    return e


def digest(e: dict) -> str:
    """Stable, domain-separated digest of the validated effect (used in receipts)."""
    return "sha256:" + hashlib.sha256(DOMAIN + canonical(validate(e))).hexdigest()


def args_digest(args) -> str: return "sha256:" + hashlib.sha256(b"mcphorizon.args.v1\x00" + canonical(args if isinstance(args, (dict, list)) else {"_": args})).hexdigest()


def sign(priv, kid: str, e: dict) -> str:
    h = {"alg": "EdDSA", "typ": TYP, "kid": kid}; s = b64e(canonical(h)) + "." + b64e(canonical(validate(e)))
    return s + "." + b64e(priv.sign(s.encode()))


def parse(token: str) -> tuple[dict, dict, bytes, bytes]:
    if not isinstance(token, str) or len(token) > MAX_TOKEN: raise EffectError("MALFORMED", "token missing or too large")
    p = token.split(".")
    if len(p) != 3: raise EffectError("MALFORMED", "not a compact JWS")
    try: h, e = json.loads(b64d(p[0])), json.loads(b64d(p[1]))
    except (ValueError, UnicodeDecodeError): raise EffectError("MALFORMED", "bad JSON") from None
    if not isinstance(h, dict): raise EffectError("MALFORMED", "bad header")
    return h, e, (p[0] + "." + p[1]).encode(), b64d(p[2])
