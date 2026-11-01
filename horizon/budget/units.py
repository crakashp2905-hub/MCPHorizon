"""Metered effect classes, tool registry and the versioned budget policy (P50-01, 07). Costs are non-negative integers; fractional, negative, boolean and absurd values are refused so no request can lower a counter."""
import hashlib, json
CLASSES = ("export_rows", "compute_units", "spend_cents", "priv_writes", "requests")
IRREVERSIBLE = ("spend_cents", "priv_writes", "export_rows")                      # 'damage' classes: cannot be taken back once the effect happened
MAX_UNITS = 10 ** 9
POLICY = {"rev": 3, "tools": {"export_csv": ["export_rows", "rows"], "export_json": ["export_rows", "records"], "export_bulk": ["export_rows", "n"], "llm_call": ["compute_units", "tokens"], "pay": ["spend_cents", "cents"],
                              "db_write": ["priv_writes", "n"], "http_get": ["requests", None], "mail_report": ["requests", None]}}
def digest(o) -> str: return "sha256:" + hashlib.sha256(json.dumps(o, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
class CostError(ValueError): pass
def cost_of(tool, args, policy=POLICY) -> dict:
    """-> {class: units} derived from the tool registry, never from agent-declared cost."""
    t = policy["tools"].get(tool)
    if t is None: raise CostError("UNKNOWN_TOOL")
    cls, key = t; n = 1 if key is None else args.get(key)
    if isinstance(n, bool) or not isinstance(n, int) or n < 0 or n > MAX_UNITS: raise CostError("BAD_UNITS")
    return {cls: n}
def clean_limits(l):
    if not isinstance(l, dict) or any(k not in CLASSES for k in l) or any(isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > MAX_UNITS for v in l.values()): raise CostError("BAD_LIMITS")
    return {k: int(v) for k, v in l.items()}
