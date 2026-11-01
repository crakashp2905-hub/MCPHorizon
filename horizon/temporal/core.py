"""Security-relevant state vector, version semantics, preconditions and the policy function (P52-01, 02, 03).

STATE VECTOR for an export action (principal p, object o, destination host h):
  object     (id, version, class)      version increases on every security-relevant mutation (class change, content replacement, ACL change); it never decreases
  grant      (principal, version, active scopes)   version increases on grant / revoke
  policy     digest of exactly the rules that decide this action: rule `export.<class>` and `dest.<host>` (each with its own version); unrelated rules do not invalidate an approval
  destination (host, resolved addresses at the time of use, redirects)
  clock      revocation sequence number = high-water mark of the event log (a logical clock, so wall-clock skew cannot reorder a revocation)
VERSION CONSISTENCY: an approval is valid at the effect boundary iff every field of the vector it was granted in is unchanged there AND the policy function still permits the action in the current state AND the token is unexpired by the
authority's own clock, unrevoked and unused. A token carries the vector; the effect boundary recomputes it. 'Unchanged' is conservative: a version bump with no policy consequence still invalidates (the legitimate path is to re-approve)."""
import hashlib, json

def canonical(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def digest(o) -> str: return "sha256:" + hashlib.sha256(canonical(o)).hexdigest()
def short(o) -> str: return digest(o)[7:23]

CLASSES = ("PUBLIC", "INTERNAL", "RESTRICTED")
OPS = ("export",)
CANARY = "TEST_CANARY_NOT_SECRET"

RULES0 = {"export.PUBLIC": {"allow": True}, "export.INTERNAL": {"allow": True, "internal_dest_only": True}, "export.RESTRICTED": {"allow": True, "needs_scope": "restricted-export"},
          "dest.partner.test": {"ips": ["10.0.0.5"], "internal": False}, "dest.intra.test": {"ips": ["10.0.1.1"], "internal": True}, "import.PUBLIC": {"allow": True}}

def slice_ids(cls, host): return ["export." + cls, "dest." + host]
def slice_digest(rules, versions, cls, host): return short([[i, versions.get(i, 0), rules.get(i)] for i in slice_ids(cls, host)])

def permits(rules, scopes, cls, host, ips):
    """Policy function. scopes = the principal's active scopes; ips = addresses the connection will actually reach."""
    if "export" not in scopes: return False, "NO_GRANT"
    r = rules.get("export." + cls); d = rules.get("dest." + host)
    if r is None or not r.get("allow"): return False, "CLASS_NOT_EXPORTABLE"
    if d is None or not ips or not set(ips) <= set(d["ips"]): return False, "DESTINATION_NOT_ALLOWED"
    if r.get("needs_scope") and r["needs_scope"] not in scopes: return False, "SCOPE_MISSING"
    if r.get("internal_dest_only") and not d["internal"]: return False, "INTERNAL_ONLY"
    return True, "OK"

def vector(obj, grant, slice_d, host, ips, rev_seq, content_d):
    """obj=(id,version,class); grant=(principal,version,scopes)."""
    return {"o": [obj[0], obj[1], obj[2]], "g": [grant[0], grant[1], sorted(grant[2])], "s": slice_d, "d": [host, short(sorted(ips))], "r": rev_seq, "c": content_d}
FIELD_REASON = {"o": "OBJECT_CHANGED", "g": "GRANT_CHANGED", "s": "POLICY_CHANGED", "d": "DESTINATION_CHANGED", "c": "CONTENT_CHANGED"}
def diff(a, b): return [FIELD_REASON[k] for k in ("o", "g", "s", "d", "c") if a[k] != b[k]]

def envelope(op, actor, obj_id, host, vec): return {"op": op, "actor": actor, "obj": obj_id, "host": host, "vec": vec}
