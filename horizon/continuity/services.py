"""Authoritative services outside any one runtime (P53-04, 05, 06): effect receiver, grants and label truth, budget ledger, revocation feed, credential broker, runtime attestor. The receiver and ledger are the oracle's evidence."""
import json
from . import core as C

class Receiver:
    """Independent operation receiver: records every effect that actually left a runtime, with the true time."""
    def __init__(self, clock): self.clock, self.effects = clock, []
    def record(self, **kw): self.effects.append({"seq": len(self.effects) + 1, "at": self.clock(), **kw}); return len(self.effects)

class Grants:
    def __init__(self, task, chain, permissions, labels, caps, obligations):
        self.task, self.chain, self.permissions, self.labels, self.caps, self.obligations = task, list(chain), list(permissions), dict(labels), dict(caps), [dict(o) for o in obligations]
    def grant(self): return {"chain": list(self.chain), "permissions": list(self.permissions)}

class Ledger:
    def __init__(self, caps): self.caps, self.spent = dict(caps), {}
    def charge(self, name, n):
        if self.spent.get(name, 0) + n > self.caps.get(name, 0): return False
        self.spent[name] = self.spent.get(name, 0) + n; return True
    def get(self, name): return self.spent.get(name, 0)

class Revocation:
    def __init__(self, clock): self.clock, self.revoked, self.feed_up = clock, {}, True
    def revoke(self, key): self.revoked[key] = self.clock()
    def status(self, key):
        """'REVOKED' | 'LIVE' | 'UNKNOWN' (feed down)."""
        if not self.feed_up: return "UNKNOWN"
        return "REVOKED" if key in self.revoked else "LIVE"

class Broker:
    """Holds raw secrets. Hands out only handle-bound, runtime-bound credentials; `rebind` revokes the old runtime's."""
    def __init__(self): self.secret = "SECRET-" + C.CANARY; self.creds = {}; self.n = 0
    def issue(self, task, rt, scope): self.n += 1; cid = "cred-%d" % self.n; self.creds[cid] = {"task": task, "rt": rt, "scope": scope, "revoked": False}; return cid
    def revoke_runtime(self, rt):
        for c in self.creds.values():
            if c["rt"] == rt: c["revoked"] = True
    def valid(self, cid, rt): c = self.creds.get(cid); return bool(c) and c["rt"] == rt and not c["revoked"]

class Attestor:
    """Evidence service: probes a runtime and signs what it actually supports. `deceived` maps runtime id -> guarantees the attestor wrongly believes (the trust-gap case)."""
    def __init__(self, issuer, clock, runtimes): self.iss, self.clock, self.rts, self.deceived = issuer, clock, runtimes, {}
    def attest(self, rt, ttl=60):
        r = self.rts[rt] if isinstance(rt, str) else rt
        if not r.attestable: raise KeyError("NO_ATTESTATION")
        g = self.deceived.get(r.id, r.supports); claim = {"rt": r.id, "g": dict(sorted(g.items())), "sm": r.sinks_mediated, "car": r.carrier}
        return self.iss.issue("ATTESTATION", principal=r.id, artifact=r.id, args_digest=C.digest(claim), claim=claim, ttl=ttl, now=int(self.clock()))
