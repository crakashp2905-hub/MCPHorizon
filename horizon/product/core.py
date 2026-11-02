"""P55/P57/P59 product-hardening primitives that need no external sign-off. CANDIDATE, stdlib.
These are library rules only; no SKU, customer, SDK package, or enforced sink is claimed."""
import re

# ---- P55-13: feature flags keep unreviewed research modules out of the mandatory path ----
class Flags:
    def __init__(self, reviewed): self.reviewed = set(reviewed); self.on = set()
    def enable(self, name, *, mandatory_path=False):
        """A module may enter the mandatory enforcement path only if it is in the reviewed set."""
        if mandatory_path and name not in self.reviewed: raise PermissionError("%s is not reviewed; cannot enter mandatory path" % name)
        self.on.add((name, mandatory_path))
    def mandatory(self): return sorted(n for n, m in self.on if m)

# ---- P55-02/11: status vocabulary and support matrix ----
STATUSES = ("DOCUMENTED", "IMPLEMENTED", "INDEPENDENTLY_VERIFIED", "UNSUPPORTED")
def feature_status(documented, implemented, independently_verified, supported=True):
    """Never skips a level: INDEPENDENTLY_VERIFIED requires IMPLEMENTED requires DOCUMENTED; unsupported dominates."""
    if not supported: return "UNSUPPORTED"
    if independently_verified and implemented and documented: return "INDEPENDENTLY_VERIFIED"
    if implemented and documented: return "IMPLEMENTED"
    if documented: return "DOCUMENTED"
    return "UNSUPPORTED"
def support_matrix(tested, requested):
    """Anything not in the tested set is UNSUPPORTED, never inferred."""
    return {r: ("SUPPORTED" if r in set(tested) else "UNSUPPORTED") for r in requested}

# ---- P57-07: structured redacted errors ----
SECRET = re.compile(r"(?i)(sk-[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{8,}|bearer\s+[A-Za-z0-9._-]{8,}|password\s*[=:]\s*\S+|TEST_CANARY_NOT_SECRET)")
CODES = {"E_DENIED": 403, "E_UNKNOWN_COVERAGE": 409, "E_UNSUPPORTED_VERSION": 426, "E_POLICY_UNAVAILABLE": 503, "E_INTERNAL": 500}
def error(code, detail=""):
    """Stable code + message; detail is redacted and capped; internal policy text is never included."""
    if code not in CODES: code = "E_INTERNAL"
    d = SECRET.sub("[REDACTED]", str(detail))[:200]
    return {"code": code, "status": CODES[code], "detail": d}

# ---- P57-15: audit vs enforce, fail-safe ----
def decide(mode, pdp_result, pep_present):
    """mode audit: never blocks, records. mode enforce: any missing PDP/PEP or UNKNOWN result blocks."""
    if mode not in ("audit", "enforce"): raise ValueError("mode")
    if mode == "audit": return {"allow": True, "recorded": pdp_result if pdp_result is not None else "NO_PDP", "enforced": False}
    if not pep_present or pdp_result is None: return {"allow": False, "recorded": "FAIL_SAFE_DENY", "enforced": True}
    return {"allow": pdp_result == "ALLOW", "recorded": pdp_result, "enforced": True}

# ---- P59-10: effect receipt states ----
EFFECT_STATES = ("ATTEMPTED", "BLOCKED", "COMMITTED", "UNKNOWN")
def effect_receipt(attempted, blocked_by_pep, sink_observed_commit):
    """sink_observed_commit: True/False/None (None = sink not observable). BLOCKED is only claimed when the sink was observed not to commit."""
    if not attempted: raise ValueError("no attempt")
    if sink_observed_commit is True: return {"state": "COMMITTED", "safe": False}
    if blocked_by_pep and sink_observed_commit is False: return {"state": "BLOCKED", "safe": True}
    if blocked_by_pep: return {"state": "UNKNOWN", "safe": False, "why": "blocked by PEP but sink not independently observed"}
    return {"state": "UNKNOWN" if sink_observed_commit is None else "ATTEMPTED", "safe": False}

# ---- P57-14: local-only metrics ----
class Metrics:
    def __init__(self): self.c = {}; self.export_enabled = False
    def inc(self, name, **labels):
        if any(k in ("prompt", "content", "body", "secret") for k in labels): raise ValueError("raw-content label refused")
        k = (name, tuple(sorted(labels.items()))); self.c[k] = self.c.get(k, 0) + 1
    def export(self):
        if not self.export_enabled: return None            # nothing leaves unless explicitly enabled
        return {"%s%s" % (n, dict(l)): v for (n, l), v in sorted(self.c.items())}
