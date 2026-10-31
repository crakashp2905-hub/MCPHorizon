"""Bounded scope matching and subsumption (P2-03, P2-04). Reference ("oracle") implementation.

Scope kinds: literal | glob | tenant | any.
Glob language (deliberately tiny): `?` = one non-'/' char, `*` = any run of non-'/' chars, `**` = any run of chars.
No character classes, alternation, backreferences or regex. Length and wildcard count are bounded, and matching is an
O(len(pattern)*len(text)) DP, so attacker-chosen patterns cannot cause exponential backtracking.
Subsumption `subsumes(a, b)` is SOUND and deliberately INCOMPLETE: True => every string matched by b is matched by a;
False means 'cannot prove' (callers must treat it as not covered).
"""
from __future__ import annotations

MAX_GLOB_LEN, MAX_WILDCARDS, MAX_TEXT = 256, 8, 4096
KINDS = ("literal", "glob", "tenant", "any")


class ScopeError(ValueError):
    pass


def _tokens(g: str) -> list[str]:
    """Split a glob into tokens: literal chars, '?', '*', '**'. Rejects unsafe patterns."""
    if len(g) > MAX_GLOB_LEN: raise ScopeError("glob too long")
    if any(c in g for c in "[]{}()\\|^$+") or "\x00" in g: raise ScopeError("unsupported glob syntax (regex-like characters)")
    out, i = [], 0
    while i < len(g):
        if g.startswith("**", i):
            if g.startswith("***", i): raise ScopeError("'***' is not allowed")
            out.append("**"); i += 2
        else:
            out.append(g[i]); i += 1
    if sum(t in ("?", "*", "**") for t in out) > MAX_WILDCARDS: raise ScopeError("too many wildcards")
    return out


def validate_scope(s: dict) -> None:
    k = s.get("kind")
    if k not in KINDS: raise ScopeError(f"bad scope kind {k!r}")
    if k == "any":
        if s.get("value") not in (None, ""): raise ScopeError("'any' takes no value")
        return
    v = s.get("value")
    if not isinstance(v, str) or not v: raise ScopeError(f"{k} scope needs a value")
    if k == "glob": _tokens(v)
    if k == "tenant" and ("/" in v or not v.isascii()): raise ScopeError("tenant value must be a plain ASCII id")


def glob_match(pattern: str, text: str) -> bool:
    if len(text) > MAX_TEXT: raise ScopeError("text too long")
    toks = _tokens(pattern)
    n = len(text)
    nxt_slash = [n] * (n + 1)                       # nxt_slash[i] = index of first '/' at or after i (else n)
    for i in range(n - 1, -1, -1): nxt_slash[i] = i if text[i] == "/" else nxt_slash[i + 1]
    cur = {0}                                       # set of reachable text positions
    for t in toks:
        nxt: set[int] = set()
        if t == "**":
            nxt.update(range(min(cur), n + 1))
        elif t == "*":
            covered = -1
            for p in sorted(cur):                   # union of intervals [p, nxt_slash[p]] in O(n)
                end = nxt_slash[p]
                if end > covered: nxt.update(range(max(p, covered + 1), end + 1)); covered = end
        else:
            for p in cur:
                if p < n and ((t == "?" and text[p] != "/") or text[p] == t): nxt.add(p + 1)
        cur = nxt
        if not cur: return False
    return n in cur


def matches(scope: dict, value: str) -> bool:
    validate_scope(scope)
    k = scope["kind"]
    if k == "any": return True
    if k == "literal": return scope["value"] == value
    if k == "tenant": return value == scope["value"] or value.startswith(scope["value"] + "/")
    return glob_match(scope["value"], value)


def subsumes(a: dict, b: dict) -> bool:
    """True iff a ⊒ b provably."""
    validate_scope(a); validate_scope(b)
    ka, kb = a["kind"], b["kind"]
    if ka == "any": return True
    if kb == "any": return False
    va, vb = a["value"], b["value"]
    if ka == "tenant":
        if kb == "tenant": return va == vb
        if kb == "literal": return vb == va or vb.startswith(va + "/")
        return vb.startswith(va + "/")                       # glob under the tenant prefix (prefix has no wildcard before '/')
    if ka == "literal": return kb == "literal" and va == vb
    # ka == glob
    if kb == "literal": return glob_match(va, vb)
    if kb == "tenant": return False
    if va == vb: return True
    if va.endswith("**") and "*" not in va[:-2] and "?" not in va[:-2]:
        return vb.startswith(va[:-2])                        # P** covers any glob whose fixed prefix starts with P
    if va.endswith("*") and not va.endswith("**") and "*" not in va[:-1] and "?" not in va[:-1]:
        p = va[:-1]
        if not vb.startswith(p): return False
        rest = vb[len(p):]
        return "/" not in rest and "**" not in rest          # P* covers P<non-slash-only globs>
    return False
