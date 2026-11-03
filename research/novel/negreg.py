"""Idea 7: negative-result registry. Append-only, hash-chained, Ed25519-signed records of defense-vs-attack outcomes (FAILED / PARTIAL / HELD_UNDER_TEST). A FAILED/PARTIAL record for a defense suspends
HorizonZero claims that depend on that defense via horizon.assurance.registry.invalidate. The custodian key is separate from the code under test (tests use a throwaway key)."""
from __future__ import annotations
import hashlib, json
from horizon.authz.keys import Signer, TrustStore

OUTCOMES = ("FAILED", "PARTIAL", "HELD_UNDER_TEST")


class NegError(Exception):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


def _h(b: bytes) -> str: return hashlib.sha256(b).hexdigest()


class NegRegistry:
    def __init__(self, signer: Signer): self.signer, self.recs = signer, []
    def append(self, defense: str, attack: str, outcome: str, evidence_sha256: str, commit: str) -> dict:
        if outcome not in OUTCOMES: raise NegError("BAD_OUTCOME")
        if not all(isinstance(x, str) and x for x in (defense, attack, evidence_sha256, commit)): raise NegError("MALFORMED")
        body = {"seq": len(self.recs), "prev": self.recs[-1]["hash"] if self.recs else "0" * 64, "defense": defense, "attack": attack, "outcome": outcome, "evidence_sha256": evidence_sha256, "commit": commit}
        raw = json.dumps(body, sort_keys=True).encode(); rec = dict(body, hash=_h(raw), sig=self.signer.sign(raw).hex(), kid=self.signer.kid); self.recs.append(rec); return rec
    def query(self, defense=None, outcome=None): return [r for r in self.recs if (defense is None or r["defense"] == defense) and (outcome is None or r["outcome"] == outcome)]
    def suspend_dependants(self, claims_registry) -> list:
        bad = sorted({r["defense"] for r in self.recs if r["outcome"] in ("FAILED", "PARTIAL")})
        for d in bad: claims_registry.invalidate(d, "negative_result_recorded")
        return bad


def verify_chain(recs: list, trust: TrustStore, now=None) -> bool:
    prev = "0" * 64
    for i, r in enumerate(recs):
        body = {k: r[k] for k in ("seq", "prev", "defense", "attack", "outcome", "evidence_sha256", "commit")}
        raw = json.dumps(body, sort_keys=True).encode()
        if r["seq"] != i or r["prev"] != prev or r["hash"] != _h(raw): return False
        try: trust.resolve(r["kid"], "custodian", now).verify(bytes.fromhex(r["sig"]), raw)
        except Exception: return False
        prev = r["hash"]
    return True
