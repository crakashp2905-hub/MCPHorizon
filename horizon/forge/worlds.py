"""Finite indistinguishability certificate (T3 slice, HF-043/044). Two worlds differ in a hidden effect; an observation map says which events a witness set can see.
If observations are identical but violation differs, no monitor over that map can separate them."""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class World:
    name: str; events: tuple          # events: (event_name, channel); channels name where it happens
    violates: bool


def observe(world: World, visible_channels: frozenset) -> tuple: return tuple(e for e, ch in world.events if ch in visible_channels)


def indistinguishable(a: World, b: World, visible_channels) -> dict | None:
    """Certificate if the pair is observation-equal yet differs in violation; else None (then the witnesses DO separate them or the pair is not a counterexample)."""
    v = frozenset(visible_channels)
    if a.violates != b.violates and observe(a, v) == observe(b, v): return {"safe": a.name if not a.violates else b.name, "leak": a.name if a.violates else b.name, "visible": sorted(v), "shared_observation": observe(a, v)}
    return None


def verify_certificate(cert: dict, a: World, b: World) -> bool:
    if cert is None: return False
    return {a.name, b.name} == {cert["safe"], cert["leak"]} and indistinguishable(a, b, cert["visible"]) is not None


def missing_witness(a: World, b: World, visible_channels, candidate_channels) -> list:
    """Smallest single added channels that would separate the pair (HF-046)."""
    return sorted(c for c in candidate_channels if c not in visible_channels and indistinguishable(a, b, set(visible_channels) | {c}) is None and observe(a, frozenset(set(visible_channels) | {c})) != observe(b, frozenset(set(visible_channels) | {c})))
