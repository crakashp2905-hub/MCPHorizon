"""Attenuating authority algebra (P15-02). Authority = (actions, tools, resources, dests, arg_max, nbf, exp). None for tools/resources/dests means 'any'.
subset(c,p) is the ONLY relation delegation may use; intersect() is the only way multiple parents combine (no union, P15-05)."""
from __future__ import annotations
from dataclasses import dataclass

EFFECTS = {"read", "list", "write", "modify", "delete", "execute", "send"}      # `admin` can never be delegated


class AuthorityError(ValueError):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


@dataclass(frozen=True)
class Authority:
    actions: frozenset
    tools: frozenset | None
    resources: tuple | None
    dests: frozenset | None
    arg_max: tuple                       # sorted ((name, int), ...)
    nbf: int
    exp: int

    @classmethod
    def make(cls, actions, tools=None, resources=None, dests=None, arg_max=None, nbf=0, exp=2 ** 31):
        a = frozenset(actions)
        if not a <= EFFECTS: raise AuthorityError("BAD_ACTION", f"actions must be within {sorted(EFFECTS)}")
        for v in (tools, dests):
            if v is not None and not all(isinstance(x, str) and x for x in v): raise AuthorityError("MALFORMED")
        if any(not isinstance(i, int) or isinstance(i, bool) or i < 0 for i in (arg_max or {}).values()) or not isinstance(nbf, int) or not isinstance(exp, int): raise AuthorityError("MALFORMED")
        return cls(a, None if tools is None else frozenset(tools), None if resources is None else tuple(sorted(set(resources))), None if dests is None else frozenset(dests), tuple(sorted((arg_max or {}).items())), nbf, exp)

    def to_json(self): return {"actions": sorted(self.actions), "tools": None if self.tools is None else sorted(self.tools), "resources": None if self.resources is None else list(self.resources),
                               "dests": None if self.dests is None else sorted(self.dests), "arg_max": dict(self.arg_max), "nbf": self.nbf, "exp": self.exp}

    @classmethod
    def from_json(cls, d):
        if not isinstance(d, dict) or set(d) != {"actions", "tools", "resources", "dests", "arg_max", "nbf", "exp"}: raise AuthorityError("MALFORMED", "authority fields")
        return cls.make(d["actions"], d["tools"], d["resources"], d["dests"], d["arg_max"], d["nbf"], d["exp"])

    @property
    def empty(self): return not self.actions or self.exp <= self.nbf


def covers(parent_prefix: str, child: str) -> bool:
    """Path-boundary prefix: 'https://a/v1' covers 'https://a/v1' and 'https://a/v1/x' but NOT 'https://a/v10'."""
    return child == parent_prefix or child.startswith(parent_prefix.rstrip("/") + "/")


def _set_sub(c, p): return p is None or (c is not None and c <= p)


def subset(c: Authority, p: Authority) -> bool:
    if c.empty: return True
    if not c.actions <= p.actions or not _set_sub(c.tools, p.tools) or not _set_sub(c.dests, p.dests): return False
    if p.resources is not None and (c.resources is None or not all(any(covers(pp, cc) for pp in p.resources) for cc in c.resources)): return False
    cm = dict(c.arg_max)
    if not all(k in cm and cm[k] <= v for k, v in p.arg_max): return False
    return c.nbf >= p.nbf and c.exp <= p.exp


def _iset(a, b): return b if a is None else a if b is None else a & b


def intersect(a: Authority, b: Authority) -> Authority:
    res = None
    if a.resources is None: res = b.resources
    elif b.resources is None: res = a.resources
    else: res = tuple(sorted({x for x in a.resources if any(covers(y, x) for y in b.resources)} | {y for y in b.resources if any(covers(x, y) for x in a.resources)}))
    am, bm = dict(a.arg_max), dict(b.arg_max); mx = {k: min(am.get(k, 2 ** 62), bm.get(k, 2 ** 62)) for k in set(am) | set(bm)}
    r = Authority(a.actions & b.actions, _iset(a.tools, b.tools), res, _iset(a.dests, b.dests), tuple(sorted(mx.items())), max(a.nbf, b.nbf), min(a.exp, b.exp))
    return r if r.resources != () or res is None else Authority(frozenset(), r.tools, (), r.dests, r.arg_max, r.nbf, r.exp)


def permits(auth: Authority, *, action: str, tool: str, resource: str, dest: str | None, args: dict, now: int) -> str | None:
    """None = permitted, else a reason code."""
    if auth.empty: return "EMPTY_AUTHORITY"
    if not auth.nbf <= now < auth.exp: return "OUT_OF_WINDOW"
    if action not in auth.actions: return "ACTION"
    if auth.tools is not None and tool not in auth.tools: return "TOOL"
    if auth.resources is not None and not any(covers(p, resource) for p in auth.resources): return "RESOURCE"
    if auth.dests is not None and (dest is None or dest not in auth.dests): return "DEST"
    for k, mx in auth.arg_max:
        v = args.get(k)
        if v is None: continue
        n = len(v) if isinstance(v, (str, bytes)) else v if isinstance(v, (int, float)) and not isinstance(v, bool) else None
        if n is None or n > mx: return "ARG_RANGE"
    return None
