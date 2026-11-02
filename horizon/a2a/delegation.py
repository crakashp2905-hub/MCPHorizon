"""P87: remote-agent delegation chains (A2A-style, local model). CANDIDATE, stdlib. Not tied to any pinned A2A SDK revision."""
import hashlib, hmac, json, os

def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
FIELDS = ("jti", "issuer", "subject", "audience", "tenant", "scope", "exp", "depth", "parent")

class Authority:
    def __init__(self, clock, secret=None): self.clock = clock; self._k = secret or os.urandom(32); self.revoked = set(); self.seen = set()
    def _sig(self, g): return hmac.new(self._k, canon({k: g[k] for k in FIELDS}), hashlib.sha256).hexdigest()
    def digest(self, g): return hashlib.sha256(canon(dict({k: g[k] for k in FIELDS}, sig=g["sig"]))).hexdigest()
    def root(self, issuer, subject, audience, tenant, scope, ttl):
        g = {"jti": os.urandom(6).hex(), "issuer": issuer, "subject": subject, "audience": audience, "tenant": tenant, "scope": sorted(scope), "exp": self.clock() + ttl, "depth": 0, "parent": None}
        g["sig"] = self._sig(g); return g
    def delegate(self, parent, subject, audience, scope, ttl):
        """Attenuating delegation by parent.subject. Refuses expansion of scope, lifetime, or tenant change at issue time."""
        if not set(scope) <= set(parent["scope"]): raise PermissionError("scope expansion")
        exp = self.clock() + ttl
        if exp > parent["exp"]: raise PermissionError("lifetime expansion")
        g = {"jti": os.urandom(6).hex(), "issuer": parent["subject"], "subject": subject, "audience": audience, "tenant": parent["tenant"], "scope": sorted(scope), "exp": exp, "depth": parent["depth"] + 1, "parent": self.digest(parent)}
        g["sig"] = self._sig(g); return g
    def revoke(self, g): self.revoked.add(g["jti"])
    def verify_chain(self, chain, *, verifier, tenant, op, consume=True, max_depth=4):
        """chain: root first. Returns (ok, reason). Every link is re-checked; nothing is trusted from the presenter."""
        if not chain: return False, "empty chain"
        if len(chain) > max_depth + 1: return False, "chain too deep"
        prev = None
        for i, g in enumerate(chain):
            if set(g) != set(FIELDS) | {"sig"}: return False, "malformed link"
            if not hmac.compare_digest(g["sig"], self._sig(g)): return False, "bad signature at %d" % i
            if g["jti"] in self.revoked: return False, "revoked link %d" % i
            if self.clock() >= g["exp"]: return False, "expired link %d" % i
            if g["tenant"] != tenant: return False, "cross-tenant"
            if g["depth"] != i: return False, "depth mismatch"
            if prev is None:
                if g["parent"] is not None: return False, "root has parent"
            else:
                if g["parent"] != self.digest(prev): return False, "broken parent link at %d" % i
                if g["issuer"] != prev["subject"]: return False, "issuer is not previous subject at %d" % i
                if not set(g["scope"]) <= set(prev["scope"]): return False, "privilege expansion at %d" % i
                if g["exp"] > prev["exp"]: return False, "lifetime expansion at %d" % i
            prev = g
        if prev["audience"] != verifier: return False, "wrong audience"
        if op not in prev["scope"]: return False, "operation not in scope"
        if consume:
            if prev["jti"] in self.seen: return False, "replayed credential"
            self.seen.add(prev["jti"])
        return True, ""

def callback_allowed(tenant_dests, tenant, url):
    """Remote callbacks only to the tenant's pre-registered destinations (exact match)."""
    return url in tenant_dests.get(tenant, ())

def discover(card):
    """Remote agent cards are DATA: free text is returned only inside 'untrusted_text'; capabilities must come from a verified manifest."""
    return {"name": str(card.get("name", ""))[:64], "untrusted_text": str(card.get("description", ""))[:2000], "capabilities_claimed": sorted(map(str, card.get("skills", []))), "trusted": False}

def artifact_may_influence(artifact, action_protected):
    """A received artifact may drive a protected action only if provenance verified and its labels allow it."""
    if not action_protected: return True
    return bool(artifact.get("provenance_verified")) and artifact.get("origin_tenant") == artifact.get("tenant") and not artifact.get("untrusted_instructions", True)

class HandoffLog:
    """Idempotent effects: a step key (run, step) executes at most once even across retries/resume."""
    def __init__(self): self.done = {}
    def run(self, run, step, effect):
        k = (run, step)
        if k in self.done: return self.done[k], False
        self.done[k] = effect(); return self.done[k], True
