"""P75-P82 campaign policy primitives (pure, stdlib, injectable clock). CANDIDATE: local-trust, no live providers.
Covers: failure classes + retry/backoff (P79-02/03), circuit breaker (P79-04), alternate READY selection (P79-05),
budgets (P78-08, P79-12), provider manifest + fallback (P78-11/12, P81-10), approvals bound to op digests (P80-10),
changed-path/protected-path checks (P78-16, P80-04/05), external-evidence and coverage gates (P77-10/12, P81-08/09),
negative results (P77-08, P81-11), ready-set with RC-R (P82-11/12), honest counts (P81-12, P82-06/14)."""
import hashlib, json, random
from dataclasses import dataclass, field

# ---------- failure classification and retry ----------
def classify_failure(kind, status=None):
    if kind in ("security_violation", "tamper", "forged_approval"): return "security_critical"
    if kind == "needs_authorization" or status in (401, 403): return "externally_authorized"
    if status == 429: return "rate_limited"
    if kind in ("dns", "timeout", "connection_reset", "interrupted_download") or (status is not None and 500 <= status < 600): return "transient"
    return "permanent"

def retry_delay(cls, attempt, *, retry_after=None, base=1.0, cap=60.0, max_attempts=5, rng=None):
    """Seconds to wait, or None = do not retry. Honors Retry-After as a floor; jitter in [0.5,1.0]*backoff."""
    if cls in ("permanent", "security_critical", "externally_authorized") or attempt >= max_attempts: return None
    r = rng or random.Random(0)
    back = min(cap, base * (2 ** attempt)) * (0.5 + 0.5 * r.random())
    if retry_after is not None: back = max(back, float(retry_after))
    return back

class Breaker:
    """closed -> open after `threshold` consecutive failures; open -> half_open after `cooldown`; half_open: one probe."""
    def __init__(self, threshold=3, cooldown=30.0, clock=None):
        self.t, self.cd, self.clock = threshold, cooldown, clock; self.fails = 0; self.state = "closed"; self.opened = None; self.probing = False
    def allow(self):
        if self.state == "open":
            if self.clock() - self.opened >= self.cd: self.state = "half_open"; self.probing = False
            else: return False
        if self.state == "half_open":
            if self.probing: return False
            self.probing = True
        return True
    def success(self): self.fails = 0; self.state = "closed"; self.probing = False
    def failure(self):
        self.fails += 1
        if self.state == "half_open" or self.fails >= self.t: self.state = "open"; self.opened = self.clock(); self.probing = False

# ---------- readiness ----------
def ready_set(tasks, *, rcr_signed=False, breaker_open_deps=()):
    """tasks: {id: {status, depends_on(task ids), gates(list), external_dep(optional)}}. READY = PENDING with all deps VERIFIED,
    RC-R signed if required, and its external dependency not blocked. Gate GATE:RC-R is never satisfied by an agent."""
    out = []
    for tid, t in sorted(tasks.items()):
        if t["status"] != "PENDING": continue
        if any(tasks[d]["status"] != "VERIFIED" for d in t.get("depends_on", []) if d in tasks): continue
        if any(d not in tasks for d in t.get("depends_on", [])): continue
        if "GATE:RC-R" in t.get("gates", []) and not rcr_signed: continue
        if t.get("external_dep") in set(breaker_open_deps): continue
        out.append(tid)
    return out

def next_task(tasks, **kw):
    r = ready_set(tasks, **kw); return r[0] if r else None  # alternate independent READY task if first is blocked via breaker_open_deps

# ---------- budgets ----------
class Budget:
    def __init__(self, task_max, project_max): self.tm, self.pm = task_max, project_max; self.task = {}; self.total = 0.0
    def charge(self, task, amount):
        if amount < 0: raise ValueError("negative charge")
        if self.total + amount > self.pm or self.task.get(task, 0.0) + amount > self.tm: return False  # refuse; nothing recorded
        self.task[task] = self.task.get(task, 0.0) + amount; self.total += amount; return True

# ---------- providers ----------
def provider_ok(manifest, provider, task):
    """manifest: {provider: {data_classes:[...], task_classes:[...]}}. task: {data_class, work_class}. Reject unsupported."""
    m = manifest.get(provider)
    if m is None: return False, "unknown provider"
    if task["data_class"] not in m["data_classes"]: return False, "data class %s not permitted for %s" % (task["data_class"], provider)
    if task["work_class"] not in m["task_classes"]: return False, "work class unsupported"
    return True, ""

def fallback(manifest, order, failed, failure_cls, task):
    """Approved fallback only for transient/rate_limited failures and only to a provider whose policy allows the task's data."""
    if failure_cls not in ("transient", "rate_limited"): return None, "failure class %s does not allow fallback" % failure_cls
    for p in order:
        if p != failed and provider_ok(manifest, p, task)[0]: return p, ""
    return None, "no provider permitted for data class"

# ---------- approvals ----------
def op_digest(op): return hashlib.sha256(json.dumps(op, sort_keys=True).encode()).hexdigest()
class ApprovalInbox:
    """Scoped to an operation digest + expiry; single use; no blanket approval."""
    def __init__(self, clock): self.clock = clock; self.items = {}
    def grant(self, approver, op, ttl): self.items[op_digest(op)] = {"approver": approver, "exp": self.clock() + ttl, "used": False}
    def consume(self, op):
        a = self.items.get(op_digest(op))
        if a is None or a["used"] or self.clock() >= a["exp"]: return False
        a["used"] = True; return True

# ---------- paths ----------
PROTECTED = ("results/", "LICENSE", ".github/", "spec/plan.lock", "spec/acceptance.json", "docs/MCPHORIZON_2_0_MASTER_SPEC.md")
def out_of_scope(changed, allow, protected=PROTECTED):
    """Changed files outside the task's allowlist or inside protected paths; empty list = accepted."""
    bad = []
    for c in changed:
        if c.startswith("/") or ".." in c.split("/"): bad.append(c); continue
        if any(c == p or c.startswith(p) for p in protected): bad.append(c); continue
        if not any(c == a or (a.endswith("/") and c.startswith(a)) for a in allow): bad.append(c)
    return bad

def conflicts(a_paths, b_paths):
    """Concurrent tasks allowed only if changed-path sets are disjoint (file or directory prefix)."""
    for x in a_paths:
        for y in b_paths:
            if x == y or (x.endswith("/") and y.startswith(x)) or (y.endswith("/") and x.startswith(y)): return True
    return False

# ---------- evidence gates ----------
def external_gate(task_class, evidence):
    """EXTERNAL/LIVE/legal tasks need authorized-party evidence; synthetic stand-ins are refused."""
    if task_class != "EXTERNAL": return True, ""
    if not evidence: return False, "no external evidence"
    if evidence.get("synthetic"): return False, "synthetic stand-in refused"
    if not evidence.get("party") or not evidence.get("signature"): return False, "missing party/signature"
    return True, ""

def coverage_verdict(sinks_seen, sinks_protected, effects_observed):
    """UNKNOWN when instrumentation cannot see a protected sink; success only with full coverage and no unauthorized effect."""
    if set(sinks_protected) - set(sinks_seen): return "UNKNOWN"
    return "FAIL" if effects_observed else "PASS"

def record_result(results, task, metric, value, ok, note=""):
    """Negative results are stored as-is; a stored negative result cannot be relabelled success."""
    key = (task, metric)
    if key in results and results[key]["ok"] is False and ok is True: raise ValueError("cannot relabel negative result")
    results[key] = {"value": value, "ok": ok, "note": note}

# ---------- honest counts ----------
def counts(tasks):
    c = {}
    for t in tasks.values(): c[t["status"]] = c.get(t["status"], 0) + 1
    n = len(tasks); v = c.get("VERIFIED", 0)
    return {"total": n, "by_status": dict(sorted(c.items())), "verified": v, "verified_fraction": (v / n if n else 0.0),
            "blocked_or_waiting": sum(c.get(s, 0) for s in ("WAITING_EXTERNAL", "NEEDS_APPROVAL", "BLOCKED_SECURITY")), "claimed_percent_complete": None}
