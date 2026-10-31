"""Protected call-authority (P13-05): deterministic issue/reject. Only this process holds the signing key. Fail-closed: any error => reject."""
from __future__ import annotations
import secrets, threading, time
from horizon import normalize as N
from horizon.service.limits import RateLimiter
from . import effect as E
from .keys import Signer

MAX_TTL_S = 300
REJECT = lambda *codes: {"ok": False, "reason_codes": list(codes)}


class CallAuthority:
    def __init__(self, signer: Signer, decide, *, audiences: set[str], contract_version: str, max_ttl_s: int = 60, clock=time.time, rate: float = 100.0, burst: int = 200, receipts=None):
        if max_ttl_s > MAX_TTL_S or max_ttl_s < 1: raise ValueError("max_ttl_s out of bounds")
        self.signer, self.decide, self.aud, self.cv, self.ttl, self.clock, self.receipts = signer, decide, set(audiences), contract_version, max_ttl_s, clock, receipts
        self.rl, self.lock = RateLimiter(rate, burst, clock), threading.Lock()

    def _rcpt(self, outcome, who, eff, reasons):
        if self.receipts: self.receipts.record(outcome, who, eff, reasons)

    def issue(self, who: dict, req: dict) -> dict:
        """who: authenticated caller {principal, tenant} (from the transport, never from the request body).
        req: {effect, target:{kind,raw}, args_digest, aud, decision_body} — decision_body is exactly what the gate sends to /v2/decisions."""
        eff = None
        try:
            if not (isinstance(who, dict) and who.get("principal") and who.get("tenant")): return REJECT("UNAUTHENTICATED")
            if not self.rl.allow(f"{who['tenant']}/{who['principal']}"): return REJECT("RATE_LIMITED")
            if not isinstance(req, dict): return REJECT("MALFORMED")
            effect, aud, tgt = req.get("effect"), req.get("aud"), req.get("target")
            if effect not in E.EFFECTS: return REJECT("UNKNOWN_EFFECT")
            if aud not in self.aud: return REJECT("AUDIENCE_NOT_SERVED")
            if not (isinstance(tgt, dict) and set(tgt) == {"kind", "raw"}): return REJECT("MALFORMED_TARGET")
            try: target = N.canonical_target(tgt["kind"], tgt["raw"])
            except ValueError: return REJECT("TARGET_REJECTED")
            ad = req.get("args_digest")
            if not isinstance(ad, str): return REJECT("MALFORMED_ARGS_DIGEST")
            ad = ad if ad.startswith("sha256:") else "sha256:" + ad
            if not E.HEX64.fullmatch(ad): return REJECT("MALFORMED_ARGS_DIGEST")
            body = req.get("decision_body")
            if not isinstance(body, dict): return REJECT("NO_DECISION_BODY")
            if body.get("effect") != effect or body.get("args_digest") not in (ad, ad.split(":", 1)[-1]) or (body.get("target") or {}).get("raw") != tgt["raw"]: return REJECT("DECISION_BODY_MISMATCH")    # the decision must be about THIS effect
            dec = self.decide(body)
            if not isinstance(dec, dict) or dec.get("verdict") != "ALLOW": return REJECT(*(dec.get("reason_codes") or ["NOT_ALLOWED"]) if isinstance(dec, dict) else ["POLICY_SERVICE_MALFORMED"])
            pv, did = dec.get("policy_digest") or dec.get("policy_version"), dec.get("decision_id")
            if not pv or not did: return REJECT("DECISION_INCOMPLETE")
            now = int(self.clock()); eff = {"v": E.VERSION, "iss": self.signer.iss, "sub": who["principal"], "tenant": who["tenant"], "effect": effect, "target": target, "args_digest": ad, "contract_version": self.cv,
                                            "policy_version": str(pv), "aud": aud, "iat": now, "exp": now + self.ttl, "nonce": secrets.token_hex(16), "decision_id": str(did)}
            tok = E.sign(self.signer, self.signer.kid, eff); self._rcpt("issued", who, eff, []); return {"ok": True, "token": tok, "effect_digest": E.digest(eff), "expires": eff["exp"]}
        except Exception as e:                                              # includes policy-service errors: no proof without a positive decision
            self._rcpt("rejected", who if isinstance(who, dict) else {}, eff, ["AUTHORITY_ERROR"]); return REJECT("AUTHORITY_ERROR")
