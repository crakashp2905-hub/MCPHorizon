"""P91/P92 research-design and spend-control helpers. CANDIDATE, stdlib. Deterministic (seeded)."""
import hashlib, json, math, random

H = lambda o: hashlib.sha256(json.dumps(o, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
REQUIRED = ("hypothesis", "primary_metric", "unit", "success_threshold", "direction", "alpha", "seed", "config")

class Prereg:
    """Frozen before data. Any change to a frozen field after freeze is rejected (amendments are new records that cite the old digest)."""
    def __init__(self, **kw):
        miss = [k for k in REQUIRED if k not in kw]
        if miss: raise ValueError("missing: %s" % miss)
        if not (0 < kw["alpha"] < 1): raise ValueError("alpha")
        if kw["direction"] not in ("greater", "less"): raise ValueError("direction")
        self.f = {k: kw[k] for k in REQUIRED}; self.digest = H(self.f); self.data_seen = False
    def see_data(self): self.data_seen = True
    def amend(self, **changes):
        """Amendment after data is allowed only as a NEW labelled record; primary metric/threshold changes after data are refused."""
        if self.data_seen and any(k in changes for k in ("primary_metric", "success_threshold", "direction", "unit", "alpha")):
            raise PermissionError("cannot change primary analysis after seeing data")
        n = Prereg(**dict(self.f, **changes)); n.parent = self.digest; return n

def wilson(k, n, z=1.959964):
    if n == 0: return (0.0, 1.0)
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); w = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - w) / d, (c + w) / d)

def n_for_halfwidth(p, hw, z=1.959964):
    """Smallest n whose Wilson half-width at proportion p is <= hw (scan; deterministic)."""
    if not (0 <= p <= 1 and 0 < hw < 1): raise ValueError("args")
    n = 1
    while n < 10 ** 7:
        k = round(p * n); lo, hi = wilson(k, n, z)
        if (hi - lo) / 2 <= hw: return n
        n += 1
    raise ValueError("unreachable")

def cluster_bootstrap(values, clusters, reps=2000, seed=0, alpha=0.05):
    """Percentile CI for the mean resampling whole clusters (templates/seeds/replicas), not rows."""
    by = {}
    for v, c in zip(values, clusters): by.setdefault(c, []).append(v)
    keys = sorted(by); r = random.Random(seed); ms = []
    for _ in range(reps):
        s = [v for c in (r.choice(keys) for _ in keys) for v in by[c]]; ms.append(sum(s) / len(s))
    ms.sort(); return (ms[int(reps * alpha / 2)], ms[int(reps * (1 - alpha / 2)) - 1])

def holm(pvals, alpha=0.05):
    """Holm-Bonferroni; returns {name: reject}."""
    order = sorted(pvals, key=lambda k: pvals[k]); m = len(order); out = {k: False for k in order}
    for i, k in enumerate(order):
        if pvals[k] <= alpha / (m - i): out[k] = True
        else: break
    return out

def mcnemar_exact(b, c):
    """Two-sided exact McNemar on discordant pairs b (A only) and c (B only)."""
    n = b + c
    if n == 0: return 1.0
    k = min(b, c); p = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return min(1.0, 2 * p)

def split_audit(tune, confirm, templates=None):
    """P91-07/12: confirmatory holdout must be disjoint from tuning by ID and, if templates are given, by template."""
    t, c = set(tune), set(confirm); prob = []
    if t & c: prob.append("id overlap: %d" % len(t & c))
    if templates:
        tt = {templates[i] for i in t if i in templates}; ct = {templates[i] for i in c if i in templates}
        if tt & ct: prob.append("template overlap: %d" % len(tt & ct))
    return prob

def decide(ci, threshold, direction="greater", executed_correctly=True):
    """go/revise/stop from a CI. A correctly executed negative result is a legitimate STOP; an incorrectly executed run is REVISE_EXECUTION."""
    if not executed_correctly: return "REVISE_EXECUTION"
    lo, hi = ci
    if direction == "greater": return "GO" if lo >= threshold else ("STOP" if hi < threshold else "REVISE")
    return "GO" if hi <= threshold else ("STOP" if lo > threshold else "REVISE")

# ---- P92 spend control ----
class Spend:
    """Project cap recorded outside worker-editable config (constructor, signed digest), per-task ceilings, reserved verifier budget,
    stop-before-charge, reconciliation against a provider meter."""
    def __init__(self, cap, verifier_reserve, task_ceiling):
        if verifier_reserve > cap: raise ValueError("reserve exceeds cap")
        self.cap, self.reserve, self.tc = cap, verifier_reserve, task_ceiling; self.spent = 0.0; self.by_task = {}; self.v_spent = 0.0; self.blocked_calls = 0
        self.digest = H({"cap": cap, "reserve": verifier_reserve, "tc": task_ceiling})
    def worker_charge(self, task, amt):
        if amt < 0: raise ValueError("negative")
        if self.spent + amt > self.cap - self.reserve or self.by_task.get(task, 0.0) + amt > self.tc: self.blocked_calls += 1; return False
        self.spent += amt; self.by_task[task] = self.by_task.get(task, 0.0) + amt; return True
    def verifier_charge(self, amt):
        if amt < 0: raise ValueError("negative")
        if self.v_spent + amt > self.reserve: self.blocked_calls += 1; return False
        self.v_spent += amt; return True
    def total(self): return self.spent + self.v_spent
def reconcile(local_total, meter_total, tol=0.01):
    """Provider-side meter is authoritative when available; flag unmetered/under-reported spend."""
    if meter_total is None: return {"status": "UNKNOWN", "delta": None}
    d = meter_total - local_total
    return {"status": "OK" if abs(d) <= tol * max(meter_total, 1e-9) else ("UNDER_REPORTED" if d > 0 else "OVER_REPORTED"), "delta": d}
def variance_report(forecast, actual):
    return {k: {"forecast": forecast[k], "actual": actual.get(k), "variance": (None if actual.get(k) is None else actual[k] - forecast[k])} for k in forecast}
