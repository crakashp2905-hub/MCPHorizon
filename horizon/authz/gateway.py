"""Gateway-side verification (P13-06/07/08/09): reconstruct what is ABOUT to execute, compare with the signed effect, consume the nonce atomically, only then run it."""
from __future__ import annotations
import functools, sqlite3, threading, time
from horizon import normalize as N
from . import effect as E
from .keys import TrustStore, TrustError


class ProofError(Exception):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


class NonceStore:
    """Single-use nonces with atomic insert; persistent (restart-consistent) when given a path. Bounded: refuses new nonces when full (fail closed)."""
    def __init__(self, path: str = ":memory:", max_rows: int = 1_000_000, clock=time.time):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None); self.db.execute("create table if not exists used(nonce text primary key, exp integer not null)"); self.l, self.max, self.clock = threading.Lock(), max_rows, clock

    def consume(self, nonce: str, exp: int) -> bool:
        with self.l:
            self.db.execute("begin immediate")
            try:
                self.db.execute("delete from used where exp < ?", (int(self.clock()) - 3600,))
                if self.db.execute("select count(*) from used").fetchone()[0] >= self.max: self.db.execute("rollback"); raise ProofError("NONCE_STORE_FULL")
                try: self.db.execute("insert into used values(?,?)", (nonce, exp))
                except sqlite3.IntegrityError: self.db.execute("rollback"); return False
                self.db.execute("commit"); return True
            except ProofError: raise
            except Exception: self.db.execute("rollback"); raise

    def close(self): self.db.close()


class Verifier:
    def __init__(self, trust: TrustStore, nonces: NonceStore, *, issuer: str, audience: str, contract_version: str, policy_version=None, clock=time.time, skew_s: int = 5, max_ttl_s: int = 300, receipts=None):
        self.t, self.n, self.iss, self.aud, self.cv, self.pv, self.clock, self.skew, self.max_ttl, self.receipts = trust, nonces, issuer, audience, contract_version, policy_version, clock, skew_s, max_ttl_s, receipts

    def verify(self, token, *, principal: str, tenant: str, effect: str, target: dict, args_digest: str, consume: bool = True) -> dict:
        try:
            p = self._verify(token, principal, tenant, effect, target, args_digest, consume)
            if self.receipts: self.receipts.record("verified", {"principal": principal, "tenant": tenant}, p, []); return p
            return p
        except ProofError as e:
            if self.receipts: self.receipts.record("refused", {"principal": principal, "tenant": tenant}, None, [e.code])
            raise

    def _verify(self, token, principal, tenant, effect, target, args_digest, consume):
        try: h, e, signing_input, sig = E.parse(token)
        except E.EffectError as x: raise ProofError(x.code, str(x)) from None
        if h.get("alg") != "EdDSA" or h.get("typ") != E.TYP or not isinstance(h.get("kid"), str): raise ProofError("BAD_HEADER", "unsupported alg/typ")
        try: pub = self.t.resolve(h["kid"], e.get("iss") if isinstance(e, dict) else "")
        except TrustError as x: raise ProofError(x.code, str(x)) from None
        try: pub.verify(sig, signing_input)
        except Exception: raise ProofError("BAD_SIGNATURE", "signature mismatch") from None
        try: E.validate(e)
        except E.EffectError as x: raise ProofError(x.code, str(x)) from None
        if e["iss"] != self.iss: raise ProofError("BAD_ISSUER")
        if e["aud"] != self.aud: raise ProofError("BAD_AUDIENCE")
        now = self.clock()
        if now > e["exp"] + self.skew: raise ProofError("EXPIRED")
        if now + self.skew < e["iat"]: raise ProofError("NOT_YET_VALID")
        if e["exp"] - e["iat"] > self.max_ttl: raise ProofError("TTL_TOO_LONG")
        if e["sub"] != principal: raise ProofError("PRINCIPAL_MISMATCH")
        if e["tenant"] != tenant: raise ProofError("TENANT_MISMATCH")
        if e["effect"] != effect: raise ProofError("EFFECT_MISMATCH")
        try: cur = N.canonical_target(target["kind"], target["raw"])                      # re-canonicalised HERE from what the gateway will actually touch
        except (ValueError, KeyError, TypeError): raise ProofError("TARGET_REJECTED") from None
        if cur != e["target"]: raise ProofError("TARGET_MISMATCH")
        if e["args_digest"] != args_digest: raise ProofError("ARGS_MISMATCH")
        if e["contract_version"] != self.cv: raise ProofError("CONTRACT_MISMATCH")
        if self.pv is not None and e["policy_version"] != self.pv(): raise ProofError("STALE_POLICY")      # policy revision race: proofs from an older policy are void
        if consume and not self.n.consume(e["nonce"], e["exp"]): raise ProofError("REPLAY")
        return e


def guard(verifier: Verifier, describe):
    """Decorator: `describe(*args, **kw)` -> dict(token, principal, tenant, effect, target, args). The wrapped function runs ONLY after verify() succeeds; otherwise ProofError and no effect."""
    def deco(fn):
        @functools.wraps(fn)
        def inner(*a, **k):
            d = describe(*a, **k)
            if not isinstance(d, dict): raise ProofError("DESCRIBE_FAILED")
            verifier.verify(d.get("token"), principal=d["principal"], tenant=d["tenant"], effect=d["effect"], target=d["target"], args_digest=E.args_digest(d["args"]))
            return fn(*a, **k)
        return inner
    return deco
