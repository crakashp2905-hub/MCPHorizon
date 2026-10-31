"""Deployable epistemic assessment (P16-01,02,04,05,06,07,08,14). States describe the EVIDENCE POSTURE, never factual truth: VERIFIED means 'the declared
evidence obligation is met by independent, relevant, fresh, attested, current evidence' — a collusion of independent forged sources still reads VERIFIED.
This module takes no ground truth and must not import bench/fixtures (enforced by a test)."""
from __future__ import annotations
import hashlib, hmac, json
from dataclasses import dataclass, field

STATES = ("VERIFIED", "UNVERIFIED", "CONFLICTED", "STALE", "UNKNOWN")


@dataclass(frozen=True)
class Prop:
    id: str
    claim_type: str
    subject: str
    domain: str
    deps: tuple = ()                       # proposition ids this proposition is derived from (must themselves be VERIFIED)


@dataclass(frozen=True)
class Obligation:
    max_age_s: int
    min_independent: int
    kinds: frozenset | None = None         # None = domain-agnostic default: evidence must merely address the claim type


DEFAULT = Obligation(max_age_s=3600, min_independent=2)


def attest_mac(key: bytes, ev: dict) -> str:
    body = {k: ev[k] for k in ("id", "prop", "addresses", "kind", "scope", "resource", "resource_version", "observed_at", "value", "schema", "roots")}
    return hmac.new(key, json.dumps(body, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()


@dataclass
class View:
    """Everything the detector may observe. No labels about truth."""
    now: float
    current_versions: dict = field(default_factory=dict)      # resource -> current version
    withdrawn: set = field(default_factory=set)
    attestor_keys: dict = field(default_factory=dict)          # attestor -> key
    schemas: dict = field(default_factory=dict)                # claim_type -> compatible schema versions
    policy: dict = field(default_factory=dict)                 # (domain, claim_type) -> Obligation


def _groups(evs):
    """Union-find over provenance roots: evidence sharing ANY root source counts as one independent group (P16-06)."""
    parent = {e["id"]: e["id"] for e in evs}
    def f(x):
        while parent[x] != x: parent[x] = parent[parent[x]]; x = parent[x]
        return x
    by_root = {}
    for e in evs:
        for r in e["roots"]:
            if r in by_root: parent[f(e["id"])] = f(by_root[r])
            else: by_root[r] = e["id"]
    return len({f(e["id"]) for e in evs})


def assess(prop: Prop, evidence: list, view: View, props: dict | None = None, _seen=None) -> dict:
    ob = view.policy.get((prop.domain, prop.claim_type), DEFAULT); dropped = []; valid = []
    for e in (x for x in evidence if x["prop"] == prop.id):
        why = None
        if e["addresses"] != prop.claim_type or e["scope"] != prop.subject or (ob.kinds is not None and e["kind"] not in ob.kinds): why = "IRRELEVANT"
        elif e["id"] in view.withdrawn: why = "WITHDRAWN"
        elif view.current_versions.get(e["resource"], e["resource_version"]) != e["resource_version"]: why = "OVERWRITTEN"
        elif view.now - e["observed_at"] > min(e["ttl"], ob.max_age_s): why = "STALE"
        elif e["schema"] not in view.schemas.get(prop.claim_type, {e["schema"]}): why = "SCHEMA_INCOMPATIBLE"
        else:
            k = view.attestor_keys.get(e["attestor"])
            if k is None or not hmac.compare_digest(attest_mac(k, e), e["attestation"]): why = "BAD_ATTESTATION"
        (dropped if why else valid).append((e["id"], why) if why else e)
    sup = [e for e in valid if e["value"] == "supports"]; con = [e for e in valid if e["value"] == "contradicts"]; reasons = sorted({w for _, w in dropped})
    need = []
    if con and sup: state = "CONFLICTED"; need.append("resolve conflicting evidence from an independent authority")
    elif con: state = "UNVERIFIED"; need.append("claim is contradicted by valid evidence")
    else:
        n = _groups(sup)
        if n >= ob.min_independent: state = "VERIFIED"
        else:
            if not [e for e in evidence if e["prop"] == prop.id]: state = "UNKNOWN"
            elif not valid and set(reasons) <= {"STALE", "OVERWRITTEN", "WITHDRAWN"}: state = "STALE"
            else: state = "UNVERIFIED"
            need.append(f"need {ob.min_independent} independent sources (have {n} valid independent group(s))")
    for r in reasons:
        need.append({"IRRELEVANT": "evidence must address this claim type and subject", "WITHDRAWN": "withdrawn evidence cannot be used", "OVERWRITTEN": "record changed since observation; re-read current version",
                     "STALE": f"re-observe within {ob.max_age_s}s", "SCHEMA_INCOMPATIBLE": "evidence uses an incompatible schema version", "BAD_ATTESTATION": "attestation invalid or attestor unknown"}[r])
    if prop.deps and props is not None:
        _seen = _seen or set()
        for d in prop.deps:
            if d in _seen: state = "UNVERIFIED"; need.append("dependency cycle"); continue
            ds = assess(props[d], evidence, view, props, _seen | {prop.id})
            if ds["state"] != "VERIFIED": state = "UNVERIFIED" if state == "VERIFIED" else state; need.append(f"dependency {d} is {ds['state']}")
    return {"prop": prop.id, "state": state, "dropped": [list(d) for d in dropped], "need": need if state != "VERIFIED" else []}


def gate(consequential: bool, deps: list, evidence: list, view: View, props: dict) -> dict:
    """Evidence-obligation policy (P16-04): a designated high-consequence operation proceeds only if every proposition it depends on is VERIFIED; otherwise REVIEW with a REVERIFY requirement (P16-14)."""
    if not consequential: return {"decision": "ALLOW", "reverify": []}
    res = [assess(props[p], evidence, view, props) for p in deps]; bad = [r for r in res if r["state"] != "VERIFIED"]
    if not deps: return {"decision": "REVIEW", "reverify": [{"prop": None, "state": "UNKNOWN", "need": ["operation declares no evidentiary basis"]}]}
    return {"decision": "REVIEW" if bad else "ALLOW", "reverify": [{"prop": r["prop"], "state": r["state"], "need": r["need"]} for r in bad]}
