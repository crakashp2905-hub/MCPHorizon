"""Idea 3: differential kernels. A SECOND, independently structured implementation of the commit-time decision rule (pure function over plain data, no I/O, written without reusing the Verifier's code path) and a
deterministic differential tester. Same language and same author as the original: this finds implementation drift, not shared specification errors."""
from __future__ import annotations
import random

ORDER = ("MALFORMED", "BAD_ISSUER", "BAD_AUDIENCE", "EXPIRED", "NOT_YET_VALID", "TTL_TOO_LONG", "PRINCIPAL_MISMATCH", "TENANT_MISMATCH", "EFFECT_MISMATCH", "TARGET_MISMATCH", "ARGS_MISMATCH", "CONTRACT_MISMATCH", "STALE_POLICY", "REPLAY")


def ref_decide(claim: dict, req: dict, env: dict, seen: set) -> str:
    """Return 'OK' or the FIRST failing code in ORDER (the documented precedence). Pure."""
    checks = (("MALFORMED", claim["exp"] > claim["iat"]), ("BAD_ISSUER", claim["iss"] == env["issuer"]), ("BAD_AUDIENCE", claim["aud"] == env["audience"]), ("EXPIRED", env["now"] <= claim["exp"] + env["skew"]),
              ("NOT_YET_VALID", env["now"] + env["skew"] >= claim["iat"]), ("TTL_TOO_LONG", claim["exp"] - claim["iat"] <= env["max_ttl"]), ("PRINCIPAL_MISMATCH", claim["sub"] == req["principal"]),
              ("TENANT_MISMATCH", claim["tenant"] == req["tenant"]), ("EFFECT_MISMATCH", claim["effect"] == req["effect"]), ("TARGET_MISMATCH", claim["target"] == req["target"]),
              ("ARGS_MISMATCH", claim["args_digest"] == req["args_digest"]), ("CONTRACT_MISMATCH", claim["contract_version"] == env["contract"]), ("STALE_POLICY", env["policy"] is None or claim["policy_version"] == env["policy"]),
              ("REPLAY", claim["nonce"] not in seen))
    for code, ok in checks:
        if not ok: return code
    return "OK"


def gen_case(rng: random.Random) -> tuple:
    env = {"issuer": "iss", "audience": "gw", "now": 1000, "skew": 5, "max_ttl": 300, "contract": "c1", "policy": rng.choice(["p1", None])}
    claim = {"iss": "iss", "aud": "gw", "iat": 990, "exp": 1020, "sub": "a", "tenant": "t", "effect": "write", "target": {"kind": "file", "canonical_id": "/x"}, "args_digest": "sha256:" + "a" * 64, "contract_version": "c1", "policy_version": "p1", "nonce": "n1", "decision_id": "d"}
    req = {"principal": "a", "tenant": "t", "effect": "write", "target": {"kind": "file", "canonical_id": "/x"}, "args_digest": claim["args_digest"]}
    seen = set()
    for _ in range(rng.randint(0, 3)):
        k = rng.choice(["iss", "aud", "iat", "exp", "sub", "tenant", "effect", "target", "args_digest", "contract_version", "policy_version", "nonce"])
        if k in ("iat", "exp"): claim[k] += rng.choice([-2000, -20, -4, 4, 20, 2000])
        elif k == "target": claim[k] = {"kind": "file", "canonical_id": "/y"}
        elif k == "nonce": seen.add(claim["nonce"])
        else: claim[k] = claim[k] + "x"
    return claim, req, env, seen
