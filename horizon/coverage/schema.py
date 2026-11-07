"""Typed, strictly validated schemas for the boundary-synthesis pipeline (blueprint S2-01/S2-02). CANDIDATE, no execution authority.
Closed enums, unknown fields rejected, unknown values fail closed, canonical JSON + digest so a certificate can bind exact inputs.
Instrumented vs uninstrumented is explicit (S2-02): an effect on an UNINSTRUMENTED edge can never yield a positive observation or coverage claim."""
from __future__ import annotations
import hashlib, json, re
from dataclasses import dataclass, fields

EFFECT_CLASSES = ("file_write", "http_egress", "child_process", "delegated_agent", "remote_service", "dns")
INSTRUMENTATION = ("instrumented", "uninstrumented")
ZONE_AUTHORITY = ("agent", "tool_server", "operator", "receiver")      # who can write inside the zone
OBSERVED = ("seen", "not_seen", "unobservable")
_ID = re.compile(r"[a-z][a-z0-9_.:-]{0,63}")


class SchemaError(ValueError): pass


def _id(v, what):
    if not (isinstance(v, str) and _ID.fullmatch(v)): raise SchemaError(f"bad {what}")
    return v


def _enum(v, allowed, what):
    if v not in allowed: raise SchemaError(f"bad {what}")
    return v


class _Base:
    def to_dict(self):
        out = {}
        for f in fields(self):
            v = getattr(self, f.name)
            out[f.name] = sorted(v) if isinstance(v, frozenset) else list(v) if isinstance(v, tuple) else v
        return out

    @classmethod
    def from_dict(cls, d):
        if not isinstance(d, dict): raise SchemaError("not an object")
        names = {f.name for f in fields(cls)}
        if set(d) - names: raise SchemaError("unknown field " + sorted(set(d) - names)[0])
        if names - set(d): raise SchemaError("missing field " + sorted(names - set(d))[0])
        kw = {}
        for f in fields(cls):
            v = d[f.name]
            if "frozenset" in str(f.type): v = frozenset(v) if isinstance(v, (list, tuple, set, frozenset)) else v
            elif "tuple" in str(f.type): v = tuple(v) if isinstance(v, (list, tuple)) else v
            kw[f.name] = v
        return cls(**kw)

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class TrustZone(_Base):
    name: str; authority: str
    def __post_init__(self): _id(self.name, "zone name"); _enum(self.authority, ZONE_AUTHORITY, "authority")


@dataclass(frozen=True)
class Witness(_Base):
    name: str; zone: str; channels: frozenset     # channels it can see; zone is who WRITES the witness
    def __post_init__(self):
        _id(self.name, "witness name"); _id(self.zone, "zone")
        if not (isinstance(self.channels, frozenset) and self.channels and all(isinstance(c, str) and _ID.fullmatch(c) for c in self.channels)): raise SchemaError("bad channels")
    def independent_of(self, zones: dict) -> bool:
        """Independent only if its zone is receiver- or operator-owned. A witness written inside the agent/tool-server zone is NOT independent."""
        z = zones.get(self.zone)
        return z is not None and z.authority in ("receiver", "operator")


@dataclass(frozen=True)
class EffectEdge(_Base):
    src: str; dst: str; effect_class: str; instrumentation: str
    def __post_init__(self):
        _id(self.src, "src"); _id(self.dst, "dst"); _enum(self.effect_class, EFFECT_CLASSES, "effect_class"); _enum(self.instrumentation, INSTRUMENTATION, "instrumentation")
        if self.src == self.dst: raise SchemaError("self edge")


@dataclass(frozen=True)
class Probe(_Base):
    name: str; synthetic_only: bool; max_external_effects: int
    def __post_init__(self):
        _id(self.name, "probe name")
        if self.synthetic_only is not True: raise SchemaError("probe must use synthetic data only")
        if not (isinstance(self.max_external_effects, int) and not isinstance(self.max_external_effects, bool) and self.max_external_effects == 0): raise SchemaError("probe effect ceiling must be 0 outside fixture-owned sinks")


@dataclass(frozen=True)
class Observation(_Base):
    probe: str; edge_dst: str; outcome: str; witness: str
    def __post_init__(self): _id(self.probe, "probe"); _id(self.edge_dst, "edge_dst"); _enum(self.outcome, OBSERVED, "outcome"); _id(self.witness, "witness")


@dataclass(frozen=True)
class HypothesisWorld(_Base):
    name: str; edges: tuple; violates: bool        # edges: tuple of "dst" ids this world adds beyond the declared graph
    def __post_init__(self):
        _id(self.name, "world name"); object.__setattr__(self, "edges", tuple(self.edges))
        if not all(isinstance(e, str) and _ID.fullmatch(e) for e in self.edges): raise SchemaError("bad edges")
        if not isinstance(self.violates, bool): raise SchemaError("bad violates")


def validate_observation(o: Observation, edge: EffectEdge, witness: Witness, zones: dict) -> str:
    """Return the evidence grade this observation can support: POSITIVE_INDEPENDENT | POSITIVE_SELF_REPORTED | UNKNOWN.
    A not_seen outcome on an uninstrumented edge or from a witness that cannot see the edge is NEVER absence evidence -> UNKNOWN."""
    if o.edge_dst != edge.dst or o.witness != witness.name: raise SchemaError("observation does not match edge/witness")
    sees = edge.dst in witness.channels and edge.instrumentation == "instrumented"
    if o.outcome == "seen":
        if not sees: raise SchemaError("witness reported an edge it cannot instrument")
        return "POSITIVE_INDEPENDENT" if witness.independent_of(zones) else "POSITIVE_SELF_REPORTED"
    return "UNKNOWN"
