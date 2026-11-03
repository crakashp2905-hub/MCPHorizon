"""Idea 2: adversarial permit fuzzing. For a valid (permit, effect) pair, generate every single-field near-miss — each CanonicalEffect field altered, each claim field altered and RE-SIGNED with the trusted key
(so only the verifier's binding checks can catch it), plus token-level corruptions — and report which mutations the commit-time verifier accepts. Fields in EXPECT_UNBOUND are legitimately free (freshness/bookkeeping)."""
from __future__ import annotations
import dataclasses, os
from horizon import normalize as N
from horizon.authz import effect as E
from horizon.authz.gateway import ProofError
from horizon.effects.canonical import CanonicalEffect, commit_verify

EXPECT_UNBOUND = {"decision_id"}          # nonce is checked for replay, iat/exp for time; decision_id is an audit reference only
CE_ALT = {"tenant": "t-x", "server_id": "srv-x", "session_id": "sess-x", "principal": "agent-x", "effect": "delete", "target_kind": "resource", "target_raw": "other/res", "args": {"z": 9}}
CLAIM_ALT = {"iss": "iss-x", "sub": "agent-x", "tenant": "t-x", "effect": "delete", "target": {"kind": "resource", "canonical_id": "other/res"}, "args_digest": "sha256:" + "0" * 64, "contract_version": "c-x",
             "policy_version": "p-x", "aud": "gw-x", "decision_id": "d-x"}


def run(make_verifier, signer, ce: CanonicalEffect, now: int, mint) -> dict:
    """make_verifier() -> fresh Verifier (fresh nonce store). mint(claim_dict)->token signed. Returns {'accepted': [mutation names], 'tested': n, 'baseline_ok': bool}."""
    base = mint(None)
    try: commit_verify(make_verifier(), base, ce); baseline = True
    except ProofError: baseline = False
    accepted, tested = [], 0
    for f, v in CE_ALT.items():
        tested += 1
        try: commit_verify(make_verifier(), mint(None), dataclasses.replace(ce, **{f: v})); accepted.append(f"ce.{f}")
        except ProofError: pass
    for f, v in CLAIM_ALT.items():
        tested += 1
        try: commit_verify(make_verifier(), mint({f: v}), ce); accepted.append(f"claim.{f}")
        except ProofError: pass
    for name, fn in (("exp_extended", lambda: mint({"exp": now + 100000})), ("exp_past", lambda: mint({"iat": now - 100, "exp": now - 50})), ("future_iat", lambda: mint({"iat": now + 1000, "exp": now + 1030})),
                     ("truncated", lambda: mint(None)[:-5]), ("sig_flip", lambda: mint(None)[:-2] + ("AA" if not mint(None).endswith("AA") else "BB")), ("alg_none", lambda: "e30." + mint(None).split(".", 1)[1]), ("empty", lambda: ""), ("dots", lambda: "..")):
        tested += 1
        try: commit_verify(make_verifier(), fn(), ce); accepted.append(f"token.{name}")
        except (ProofError, Exception): pass
    return {"baseline_ok": baseline, "tested": tested, "accepted": [a for a in accepted if a.split(".", 1)[1] not in EXPECT_UNBOUND], "accepted_expected_unbound": [a for a in accepted if a.split(".", 1)[1] in EXPECT_UNBOUND]}
