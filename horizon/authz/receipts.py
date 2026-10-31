"""Append-only evidence receipts (P13-13): hash-chained, carry policy version and effect digest, never tokens, arguments, targets' query strings or secrets."""
from __future__ import annotations
import hashlib, time
from horizon.service.audit import AuditLog
from . import effect as E


class Receipts:
    def __init__(self, path: str, clock=time.time): self.log, self.clock = AuditLog(path), clock
    def close(self): self.log.close()

    def record(self, outcome: str, who: dict, eff: dict | None, reasons: list) -> str:
        who = who or {}; rec = {"ev": "effect_receipt", "outcome": outcome, "t": self.clock(), "principal_h": hashlib.sha256(str(who.get("principal", "")).encode()).hexdigest()[:16], "tenant_h": hashlib.sha256(str(who.get("tenant", "")).encode()).hexdigest()[:16], "reasons": list(reasons)[:8]}
        if eff:
            try: rec.update(effect_digest=E.digest(eff), policy_version=eff["policy_version"], effect=eff["effect"], decision_id=eff["decision_id"])
            except Exception: rec["effect_digest"] = None
        return self.log.write(rec)
