"""Structured value tracking (P7-02, P7-10..P7-12). A TV carries the set of handles its bytes depend on. Every operation unions sources
(conservative). Values that leave this wrapper (plain Python objects) LOSE tracking; the outgoing-boundary byte detector exists for that case."""
from __future__ import annotations
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class TV:
    v: object
    src: frozenset = frozenset()
    opaque: bool = False

    def __repr__(self): return f"TV(<{len(self.src)} sources>)"          # never print the value into logs by accident


def lit(v) -> TV: return TV(v)
def of(v, handle: str) -> TV: return TV(v, frozenset({handle}))
def _src(*xs) -> frozenset: return frozenset().union(*[x.src if isinstance(x, TV) else frozenset() for x in xs])
def _val(x): return x.v if isinstance(x, TV) else x
def _opq(*xs) -> bool: return any(isinstance(x, TV) and x.opaque for x in xs)


def concat(parts, sep: str = "") -> TV: return TV(sep.join(str(_val(p)) for p in parts), _src(*parts), _opq(*parts))
def fmt(template: str, **kw) -> TV: return TV(template.format(**{k: _val(v) for k, v in kw.items()}), _src(*kw.values()), _opq(*kw.values()))
def dumps(x: TV) -> TV: return TV(json.dumps(x.v, sort_keys=True), x.src, x.opaque)
def loads(x: TV) -> TV: return TV(json.loads(x.v), x.src, x.opaque)
def get(x: TV, k) -> TV: return TV(x.v[k], x.src, x.opaque)                      # element of a container inherits the whole container's sources
def slice_(x: TV, a=None, b=None) -> TV: return TV(x.v[a:b], x.src, x.opaque)
def items(x: TV) -> list[TV]: return [TV(e, x.src, x.opaque) for e in x.v]
def listof(xs) -> TV: return TV([_val(e) for e in xs], _src(*xs), _opq(*xs))
def dictof(d: dict) -> TV: return TV({k: _val(v) for k, v in d.items()}, _src(*d.values()), _opq(*d.values()))
def encode(x: TV, how: str) -> TV:
    import base64, binascii
    b = x.v.encode() if isinstance(x.v, str) else x.v
    return TV({"b64": lambda: base64.b64encode(b).decode(), "hex": lambda: binascii.hexlify(b).decode(), "rev": lambda: b[::-1].decode("utf-8", "replace")}[how](), x.src, x.opaque)


def map_(x: TV, fn) -> TV:
    """Loop/callback: each element's result inherits that element's sources plus the sources of anything the callback returns as a TV."""
    out, src, opq = [], set(x.src), x.opaque
    for e in x.v:
        r = fn(TV(e, x.src, x.opaque))
        if isinstance(r, TV): out.append(r.v); src |= r.src; opq = opq or r.opaque
        else: out.append(r)
    return TV(out, frozenset(src), opq)


def reduce_(x: TV, fn, init: TV) -> TV:
    acc = init
    for e in x.v: acc = fn(acc, TV(e, x.src, x.opaque))
    return acc


def paraphrase(x: TV, model) -> TV:
    """Opaque transform (LLM paraphrase etc.): the output bytes need not resemble the input, so labels are inherited and `opaque` is set."""
    return TV(model(x.v), x.src, True)


def materialize(sidecar, x: TV, *, op: str, principal: str, event_id: str, protocol: str = "codemode") -> str:
    """Record the value as a sidecar artifact whose parents are exactly its sources."""
    return sidecar.derive(sorted(x.src), x.v, op=op, principal=principal, event_id=event_id, opaque=x.opaque, protocol=protocol)
