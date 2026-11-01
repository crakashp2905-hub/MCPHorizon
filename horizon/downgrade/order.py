"""Typed security-guarantee vectors with partial-order semantics (P46-01, P46-16).

A guarantee value lives in a per-dimension poset; the vector order is the PRODUCT order over the dimensions a task makes mandatory. There is no numeric security score.
  chain     totally ordered levels, low -> high                       authn, transport, audit, egress
  scope     sets of privileges, SMALLER is stronger (least privilege)  credential scope, data classes the endpoint may receive
  member    unordered values; a requirement is a set of allowed values region (data locality): eu and us are incomparable
None / missing / unattested means UNKNOWN, and UNKNOWN never satisfies a requirement (spec 66.2).

satisfies(dim, required, got) -> SAT | UNSAT | UNKNOWN.      A requirement for `scope`/`member` dimensions is the permitted set; for chains it is the minimum level.
classify(floor, profile) -> ADMIT | DOWNGRADE | INCOMPARABLE | UNKNOWN
  ADMIT         every mandatory dimension SAT
  DOWNGRADE     some dimension UNSAT and none is strictly better than required (strictly weaker or equal elsewhere)
  INCOMPARABLE  some dimension UNSAT while another is strictly BETTER than required: a trade-off the order cannot rank (no invented exchange rate)
  UNKNOWN       some mandatory dimension has no verified value (checked after UNSAT so a known violation is reported as such)
"""
from dataclasses import dataclass

CHAINS = {"authn": ("none", "api_key", "oauth"), "transport": ("plaintext", "tls1.2", "tls1.3"), "audit": ("none", "local", "remote_tamper_evident"), "egress": ("unmediated", "mediated")}
SCOPES = ("scope", "data_scope"); MEMBERS = ("region",)
DIMS = tuple(CHAINS) + SCOPES + MEMBERS
SAT, UNSAT, UNKNOWN = "SAT", "UNSAT", "UNKNOWN"


def kind(dim):
    if dim in CHAINS: return "chain"
    if dim in SCOPES: return "scope"
    if dim in MEMBERS: return "member"
    raise KeyError("unknown guarantee dimension " + str(dim))


def norm(dim, v):
    """Canonical value; None stays None (UNKNOWN). Raises on values outside the dimension's domain, so a typo cannot silently become 'unknown but fine'."""
    if v is None: return None
    k = kind(dim)
    if k == "chain":
        if v not in CHAINS[dim]: raise ValueError("%s: %r not in %s" % (dim, v, CHAINS[dim]))
        return v
    if k == "scope": return frozenset(v)
    return v if isinstance(v, str) else frozenset(v)


def leq(dim, a, b):
    """a is at most as strong as b (a <= b in the stronger-is-higher order). Only defined for known values."""
    k = kind(dim)
    if k == "chain": return CHAINS[dim].index(a) <= CHAINS[dim].index(b)
    if k == "scope": return frozenset(a) >= frozenset(b)             # more privileges = weaker
    return a == b                                                    # members are pairwise incomparable


def satisfies(dim, required, got):
    if got is None: return UNKNOWN
    k = kind(dim)
    if k == "chain": return SAT if CHAINS[dim].index(got) >= CHAINS[dim].index(required) else UNSAT
    if k == "scope": return SAT if frozenset(got) <= frozenset(required) else UNSAT
    allowed = {required} if isinstance(required, str) else set(required)
    return SAT if (got in allowed if isinstance(got, str) else set(got) <= allowed) else UNSAT


def strictly_better(dim, required, got):
    """got exceeds the requirement in a way the requirement cares about (only chains and scopes have 'more than enough')."""
    if got is None: return False
    k = kind(dim)
    if k == "chain": return CHAINS[dim].index(got) > CHAINS[dim].index(required)
    if k == "scope": return frozenset(got) < frozenset(required)
    return False


def classify(floor: dict, profile: dict):
    """-> (outcome, per-dimension {dim: SAT|UNSAT|UNKNOWN})."""
    per = {d: satisfies(d, req, profile.get(d)) for d, req in floor.items()}
    if all(v == SAT for v in per.values()): return "ADMIT", per
    if any(v == UNSAT for v in per.values()):
        better = any(strictly_better(d, floor[d], profile.get(d)) for d in floor if per[d] == SAT)
        return ("INCOMPARABLE" if better else "DOWNGRADE"), per
    return "UNKNOWN", per


def compare(a: dict, b: dict):
    """Product-order comparison of two PROFILES over the dimensions both define. -> 'EQ' | 'GT' | 'LT' | 'INCOMPARABLE' | 'UNKNOWN'."""
    ds = sorted(set(a) | set(b))
    if any(a.get(d) is None or b.get(d) is None for d in ds): return "UNKNOWN"
    ge = all(leq(d, b[d], a[d]) for d in ds); le = all(leq(d, a[d], b[d]) for d in ds)
    return "EQ" if ge and le else "GT" if ge else "LT" if le else "INCOMPARABLE"


def join(f1: dict, f2: dict) -> dict:
    """Pointwise stricter floor (used when a delegation adds requirements). A dimension only one side requires is kept."""
    out = dict(f1)
    for d, r in f2.items():
        if d not in out: out[d] = r; continue
        k = kind(d); a = out[d]
        if k == "chain": out[d] = r if CHAINS[d].index(r) > CHAINS[d].index(a) else a
        elif k == "scope": out[d] = frozenset(a) & frozenset(r)
        else: out[d] = (frozenset([a]) if isinstance(a, str) else frozenset(a)) & (frozenset([r]) if isinstance(r, str) else frozenset(r))
    return out


def at_least_as_strict(new: dict, old: dict) -> bool:
    """new floor demands at least everything old demands (never weaker)."""
    for d, r in old.items():
        if d not in new: return False
        k = kind(d)
        if k == "chain" and CHAINS[d].index(new[d]) < CHAINS[d].index(r): return False
        if k == "scope" and not frozenset(new[d]) <= frozenset(r): return False
        if k == "member":
            n = {new[d]} if isinstance(new[d], str) else set(new[d]); o = {r} if isinstance(r, str) else set(r)
            if not n <= o: return False
    return True


def ser(v):
    return sorted(v) if isinstance(v, (set, frozenset)) else v


def to_json(vec: dict) -> dict: return {d: ser(v) for d, v in sorted(vec.items())}
def from_json(d: dict) -> dict: return {k: norm(k, v) if not (kind(k) == "member" and isinstance(v, list)) else frozenset(v) for k, v in d.items()}


def scalar_score(profile: dict) -> float:
    """The thing this module refuses to do: collapse a vector to one number. Kept only as a baseline/counterexample."""
    s = 0.0
    for d, v in profile.items():
        if v is None: continue
        k = kind(d)
        s += (CHAINS[d].index(v) / (len(CHAINS[d]) - 1)) if k == "chain" else (1.0 - min(len(v), 4) / 4.0) if k == "scope" else 0.5
    return s
