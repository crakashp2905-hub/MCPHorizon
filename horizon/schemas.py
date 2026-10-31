"""Validation entry points + semantic checks that JSON Schema cannot express."""
from __future__ import annotations
import json, re
from pathlib import Path
from .jsonschema_lite import validate as _v
from .schema_defs import ALL, SCHEMA_MAJOR

_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "SECRET": 3}


class UnsupportedSchemaVersion(ValueError):
    pass


def check_version(doc: dict, kind: str = "document") -> None:
    v = doc.get("schema_version") if isinstance(doc, dict) else None
    if not isinstance(v, str) or not re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}", v):
        raise UnsupportedSchemaVersion(f"{kind}: missing or malformed schema_version {v!r}; expected '{SCHEMA_MAJOR}.x.y'")
    major = int(v.split(".")[0])
    if major != SCHEMA_MAJOR:
        raise UnsupportedSchemaVersion(
            f"{kind}: schema major version {major} is not supported (this build supports {SCHEMA_MAJOR}.x.y). "
            f"No automatic migration is performed; convert the document explicitly or upgrade the consumer.")


def validate(kind: str, doc) -> list[str]:
    """Return a list of human-readable errors; [] means valid. Never raises on hostile input."""
    if kind not in ALL: return [f"unknown schema kind {kind!r}"]
    if kind in ("event", "decision"):
        try: check_version(doc, kind)
        except UnsupportedSchemaVersion as e: return [str(e)]
    errs = _v(doc, ALL[kind])
    if errs: return errs
    return {"decision": decision_semantics, "policy": policy_semantics, "event": event_semantics}.get(kind, lambda d: [])(doc)


def event_semantics(e: dict) -> list[str]:
    errs = []
    if e["phase"] == "before_call" and e["principal_source"] in ("agent_claimed", "unknown"):
        errs.append("before_call event with untrusted principal_source cannot support a protected-effect decision")
    if e["phase"] == "before_call" and "args_digest" not in e:
        errs.append("before_call event requires args_digest (use bound digests, not raw arguments)")
    return errs


def decision_semantics(d: dict) -> list[str]:
    errs = []
    if d["verdict"] == "ALLOW" and d["mode"] == "enforce":
        for f in ("expires_at", "bound_target_digest", "bound_args_digest", "approved_principal"):
            if f not in d: errs.append(f"ALLOW decision must be bound: missing {f}")
    if d["verdict"] == "SHADOW_ALLOW" and d["mode"] != "shadow":
        errs.append("SHADOW_ALLOW is only valid in explicit shadow mode (no protection claim)")
    if d["verdict"] in ("DENY", "REVIEW", "QUARANTINE", "UNKNOWN") and not d["reason_codes"]:
        errs.append(f"{d['verdict']} decision requires at least one reason code")
    return errs


def policy_semantics(p: dict) -> list[str]:
    errs, seen, whens = [], set(), {}
    for r in p["rules"]:
        if r["id"] in seen: errs.append(f"duplicate rule id {r['id']}")
        seen.add(r["id"])
        key = json.dumps(r["when"], sort_keys=True)
        if key in whens and whens[key] != r["decision"]:
            errs.append(f"ambiguous precedence: rules with identical conditions give {whens[key]} and {r['decision']}")
        whens[key] = r["decision"]
        if not r["when"]: errs.append(f"rule {r['id']} has an empty condition (matches everything)")
        w = r["when"]
        if "input_label_at_least" in w and "maximum_input_label" in w and _RANK[w["input_label_at_least"]] > _RANK[w["maximum_input_label"]]:
            errs.append(f"rule {r['id']} has unsatisfiable label bounds")
        if r["decision"] == "ALLOW" and w.get("lineage_complete") is not True and "maximum_input_label" not in w:
            errs.append(f"rule {r['id']}: ALLOW must require complete lineage or a maximum_input_label")
    for sec in ("rules", "principals", "resources", "metadata"):
        if re.search(r"\$\{|\{\{|<%|eval\(|exec\(", json.dumps(p.get(sec))):
            errs.append(f"{sec}: template/expression syntax is not permitted in policies")
    return errs


def lineage_complete(artifact_id: str, artifacts: dict[str, dict]) -> bool:
    """Incomplete-lineage semantics: missing parent, partial_lineage flag, or a cycle => incomplete (not clean)."""
    seen, stack = set(), [artifact_id]
    while stack:
        a = stack.pop()
        if a in seen: continue
        seen.add(a)
        art = artifacts.get(a)
        if art is None or art["partial_lineage"]: return False
        stack.extend(art["parents"])
    return True


def effective_confidentiality(artifact_id: str, artifacts: dict[str, dict]) -> str:
    """Opaque transforms conservatively inherit the max parent label; an unknown ancestor => SECRET."""
    best, seen, stack = "PUBLIC", set(), [artifact_id]
    while stack:
        a = stack.pop()
        if a in seen: continue
        seen.add(a)
        art = artifacts.get(a)
        if art is None: return "SECRET"
        if _RANK[art["confidentiality"]] > _RANK[best]: best = art["confidentiality"]
        stack.extend(art["parents"])
    return best
