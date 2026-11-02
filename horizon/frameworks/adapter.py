"""P90: agent-framework adapter contract, support levels, auto-generated coverage matrix, fail-closed version check. CANDIDATE, stdlib.
No real framework SDK is integrated here; adapters are test doubles."""
LEVELS = ("NATIVE", "BRIDGED", "OBSERVE_ONLY", "PARTIAL", "UNSUPPORTED", "UNKNOWN")
ENFORCING = ("NATIVE", "BRIDGED")            # may be claimed as protecting effects
LINEAGE = ("principal", "run", "task", "tool_call", "artifact")

def valid_call(ctx):
    """Every intercepted call must carry full lineage; a missing field means the call is not mediated (fail closed)."""
    return all(isinstance(ctx.get(k), str) and ctx[k] for k in LINEAGE)

def effective_level(claimed, *, pinned, actual, conformance_passed, os_protected_paths=False, path="tool_call"):
    """Downgrade rules. Returns (level, reason). Never upgrades. Direct subprocess/raw-network paths are covered only if OS-protected."""
    if claimed not in LEVELS: raise ValueError("unknown level")
    if claimed in ENFORCING:
        if actual != pinned: return "UNKNOWN", "framework version %s differs from tested %s" % (actual, pinned)
        if not conformance_passed: return "UNKNOWN", "conformance not passed"
    if path in ("subprocess", "raw_network") and not os_protected_paths: return ("UNSUPPORTED" if claimed in ENFORCING else claimed), "direct %s path is outside claimed coverage" % path
    return claimed, ""

def coverage_matrix(results):
    """results: list of {framework, version, path, claimed, pinned, passed, os_protected}. Generated, never hand-written."""
    rows = []
    for r in results:
        lvl, why = effective_level(r["claimed"], pinned=r["pinned"], actual=r["version"], conformance_passed=r["passed"], os_protected_paths=r.get("os_protected", False), path=r["path"])
        rows.append({"framework": r["framework"], "version": r["version"], "path": r["path"], "level": lvl, "reason": why})
    return sorted(rows, key=lambda x: (x["framework"], x["version"], x["path"]))

class ToolCallQueue:
    """Bounded queue (backpressure), cancellation, and retry only for actions that declare an idempotency key."""
    def __init__(self, limit): self.limit, self.q, self.done, self.cancelled = limit, [], {}, set()
    def submit(self, call):
        if len(self.q) >= self.limit: return "REJECTED_BACKPRESSURE"
        if not valid_call(call["ctx"]): return "REJECTED_NO_LINEAGE"
        self.q.append(call); return "QUEUED"
    def cancel(self, tool_call):
        self.cancelled.add(tool_call); self.q = [c for c in self.q if c["ctx"]["tool_call"] != tool_call]
    def run_next(self, effect):
        if not self.q: return None
        c = self.q.pop(0); tc = c["ctx"]["tool_call"]
        if tc in self.cancelled: return "CANCELLED"
        key = c.get("idempotency_key")
        if key is not None and key in self.done: return self.done[key]          # retry of finished work: no second effect
        r = effect(c); 
        if key is not None: self.done[key] = r
        return r
    def retry(self, call):
        """Retry allowed only with an idempotency key; otherwise refused because the effect may already have happened."""
        if call.get("idempotency_key") is None: return "REFUSED_NON_IDEMPOTENT"
        return self.submit(call)
