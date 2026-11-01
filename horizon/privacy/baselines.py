"""Baselines (P45 spec 65.5). All use the same DP mechanism and noise; only the accounting/authorization differs.
  per-agent request limit         each principal may issue at most N queries; no shared view.
  standard accountant, no federation   a correct accountant, but one ledger PER PRINCIPAL (budget resets for a new identity).
  generic DLP                     scans released text for identifier-like patterns; numeric aggregates pass.
  raw token-count limit           refuses raw queries with more than T tokens.
  non-transactional shared ledger a shared budget checked with read-then-write (no atomic reservation)."""
import json, re, threading, time
from . import units as U, ledger as LG, mechanisms as MX, accountant as AC, service as SV


class Wrapped:
    """Adapter exposing the Service interface with a different accounting policy."""
    def __init__(self, service): self.sv = service
    def query(self, principal, q, ctx=None): return self.sv.query(principal, q, ctx)


class PerAgentLimit(Wrapped):
    def __init__(self, service, n): super().__init__(service); self.n, self.c, self.lock = n, {}, threading.Lock()
    def query(self, principal, q, ctx=None):
        d = self.sv.ds.get(q.get("dataset"))
        if d is not None and d.public: return self._noacct(principal, q, ctx)          # the limit protects sensitive data only
        with self.lock:
            self.c[principal] = self.c.get(principal, 0) + 1
            if self.c[principal] > self.n: return {"status": "DENY", "reason": "PER_AGENT_LIMIT"}
        return self._noacct(principal, q, ctx)
    def _noacct(self, principal, q, ctx):
        return _free_dp(self.sv, principal, q)


def _free_dp(sv, principal, q):
    """DP answer with no budget check at all (the baseline's own policy already approved the request)."""
    p = sv.principals.get(principal); d = sv.ds.get(q.get("dataset"))
    if p is None or d is None: return {"status": "DENY", "reason": "UNKNOWN"}
    if d.public: return sv._raw(principal, p, d, q, public=True)
    if q.get("mode", "dp") == "raw": return sv.query(principal, q)
    if d.name not in p["dp"]: return {"status": "DENY", "reason": "NOT_AUTHORIZED_DP"}
    rid = q.get("request_id"); sens = sv.sensitivity(d, q); eps = str(q.get("eps", "0.25")); st = MX.Stream(sv.secret, rid)
    true = len(d.match(q.get("where", []))) if q["agg"] == "count" else sum(x[q["column"]] for x in d.match(q.get("where", [])))
    ans = true + MX.discrete_laplace(st, float(eps), sens); sv._log(kind="dp", principal=principal, dataset=d.name, request_id=rid, mech="laplace", eps=eps, delta="0", sens=sens, sigma=None, answer=ans, agg=q["agg"], where=q.get("where", []))
    return {"status": "OK", "answer": ans}


class PerPrincipalAccountant(Wrapped):
    """A correct accountant keyed by (dataset, principal): identities do not share a budget."""
    def __init__(self, service, make_budget): super().__init__(service); self.make, self.leds = make_budget, {}
    def query(self, principal, q, ctx=None):
        d = self.sv.ds.get(q.get("dataset"))
        if d is None or d.public or q.get("mode", "dp") != "dp": return self.sv.query(principal, q, ctx)
        lid = self.leds.get(principal)
        if lid is None:
            lid = self.leds[principal] = LG.Ledger(":memory:", self.sv.v, self.sv.led.clock); self.make(lid, d.name, principal)
        sv2 = SV.Service(list(self.sv.ds.values()), lid, self.sv.v, self.sv.secret); sv2.principals, sv2.release_log, sv2.signer = self.sv.principals, self.sv.release_log, self.sv.signer
        return sv2.query(principal, q, ctx)


class DLP(Wrapped):
    PAT = re.compile(r"(\b\d{3}-\d{2}-\d{4}\b|\b[\w.]+@[\w.]+\.\w+\b|\bp\d{4}\b|target)")
    def query(self, principal, q, ctx=None):
        r = _free_dp(self.sv, principal, q)
        if r.get("status") == "OK" and self.PAT.search(json.dumps(r)): return {"status": "DENY", "reason": "DLP_PATTERN"}
        return r


class TokenLimit(Wrapped):
    def __init__(self, service, t): super().__init__(service); self.t = t
    def query(self, principal, q, ctx=None):
        if len(re.findall(r"\w+|[^\w\s]", json.dumps(q))) > self.t: return {"status": "DENY", "reason": "TOKEN_LIMIT"}
        return _free_dp(self.sv, principal, q) if q.get("mode", "dp") == "dp" else self.sv.query(principal, q, ctx)


class NonTransactional(Wrapped):
    """Shared budget checked with read-then-write in separate steps (what a naive in-memory or two-statement accountant does)."""
    def __init__(self, service, budget, accountant="basic", gap=0.002): super().__init__(service); self.b, self.acc, self.gap, self.charges, self.lock = budget, accountant, gap, {}, threading.Lock()
    def query(self, principal, q, ctx=None):
        d = self.sv.ds.get(q.get("dataset"))
        if d is None or d.public or q.get("mode", "dp") != "dp": return self.sv.query(principal, q, ctx)
        sens = self.sv.sensitivity(d, q); charge = MX.laplace_charge(str(q.get("eps", "0.25")), sens)
        with self.lock: snapshot = list(self.charges.get(d.name, []))                  # READ
        ok = AC.fits(self.acc, self.b, snapshot + [charge])[0]
        time.sleep(self.gap)                                            # ... another agent runs here
        if not ok: return {"status": "DENY", "reason": "BUDGET_EXCEEDED"}
        with self.lock: self.charges.setdefault(d.name, []).append(charge)                     # WRITE
        return _free_dp(self.sv, principal, q)
