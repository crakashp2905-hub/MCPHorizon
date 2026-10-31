"""Immutable policy digest and request-bound ALLOW tokens with expiry, replay and mismatch protection (P2-12, P2-13).
In-memory nonce/idempotency stores: a restart forgets them — a protected persistent store is required in production."""
from __future__ import annotations
import hashlib, hmac, json, secrets


def policy_digest(policy: dict) -> str:
    return "policy-sha256:" + hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _binding(req: dict) -> dict:
    return {k: req[k] for k in ("principal_id", "target_digest", "args_digest", "policy_digest", "logical_operation")}


def mint(key: bytes, req: dict, now: float, ttl: float = 60.0, nonce: str | None = None) -> dict:
    body = {**_binding(req), "expires_at": now + min(ttl, 300.0), "nonce": nonce or secrets.token_hex(16)}
    return {**body, "mac": hmac.new(key, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()}


class Redeemer:
    def __init__(self, key: bytes): self.key, self.used, self.results = key, set(), {}

    def redeem(self, token: dict, req: dict, now: float, idempotency_key: str | None = None) -> tuple[bool, str]:
        body = {k: v for k, v in token.items() if k != "mac"}
        want = hmac.new(self.key, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(token.get("mac", "")), want): return False, "BAD_MAC"
        if now > token["expires_at"]: return False, "EXPIRED"
        if _binding(req) != {k: token[k] for k in _binding(req)}: return False, "BINDING_MISMATCH"   # altered args/target/principal/policy
        if idempotency_key is not None and idempotency_key in self.results:
            prev_nonce, prev_ok = self.results[idempotency_key]
            return (prev_ok, "IDEMPOTENT_REPLAY_SAME") if prev_nonce == token["nonce"] else (False, "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_TOKEN")
        if token["nonce"] in self.used: return False, "REPLAYED_NONCE"
        self.used.add(token["nonce"])
        if idempotency_key is not None: self.results[idempotency_key] = (token["nonce"], True)
        return True, "OK"
