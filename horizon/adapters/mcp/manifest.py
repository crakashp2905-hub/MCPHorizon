"""Tool manifest digests, change tracking, rug-pull and collision detection (P4-05, P4-19). Tool descriptions are untrusted data."""
from __future__ import annotations
import hashlib, json, re, unicodedata
from .schema import check_schema_document

INJECT = re.compile(r"(?i)(ignore (all |any |the )?(previous|prior|above)|disregard .{0,30}(instruction|rule)|you are now|<\s*/?\s*(important|system|assistant)\s*>|"
                    r"do not (tell|inform|mention).{0,30}user|before using this tool.{0,40}(read|send|call)|send .{0,40}(to|via) .{0,40}(http|@)|~/\.ssh|id_rsa)")
ZW = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)


class ManifestError(Exception):
    def __init__(self, code: str, msg: str): super().__init__(msg); self.code = code


def _sha(o) -> str: return hashlib.sha256(json.dumps(o, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def confusable_key(name: str) -> str:
    """Names that look identical to a human/LLM collapse to one key: NFKC, casefold, zero-width stripped, separators unified."""
    return re.sub(r"[-_.\s]+", "_", unicodedata.normalize("NFKC", name).translate(ZW).casefold())


def tool_record(server_id: str, tool: dict) -> dict:
    name = tool.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}", name): raise ManifestError("BAD_TOOL_NAME", f"unacceptable tool name {str(name)[:60]!r}")
    desc = tool.get("description") or ""
    body = {"name": name, "description": desc, "inputSchema": tool.get("inputSchema"), "outputSchema": tool.get("outputSchema"), "annotations": tool.get("annotations")}
    return {"tool_id": f"{server_id}/{name}", "name": name, "digest": _sha(body), "schema_problems": check_schema_document(tool.get("inputSchema") or {"type": "object"}),
            "description_flagged": bool(INJECT.search(desc)) or any(ord(c) in ZW for c in desc), "input_schema": tool.get("inputSchema") or {"type": "object"}}


class ManifestTracker:
    def __init__(self): self.observed: dict[str, dict[str, dict]] = {}; self.approved: dict[str, dict[str, str]] = {}; self.stale: set[str] = set()

    def observe(self, server_id: str, tools: list) -> dict:
        """Record a tools/list result. Returns {added, removed, changed, collisions, flagged, schema_problems}; never raises for a hostile list (it is reported)."""
        if not isinstance(tools, list) or len(tools) > 2000: raise ManifestError("BAD_MANIFEST", "tools must be a list of at most 2000 entries")
        recs, coll, seen, keys = {}, [], set(), {}
        for t in tools:
            try: r = tool_record(server_id, t if isinstance(t, dict) else {})
            except ManifestError as e: coll.append({"kind": "bad_name", "detail": str(e)}); continue
            if r["name"] in seen: coll.append({"kind": "duplicate_name", "name": r["name"]}); continue
            seen.add(r["name"]); k = confusable_key(r["name"])
            if k in keys: coll.append({"kind": "confusable_names", "names": sorted([keys[k], r["name"]])})
            keys[k] = r["name"]; recs[r["name"]] = r
        prev = self.observed.get(server_id, {}); self.observed[server_id] = recs; self.stale.discard(server_id)
        return {"added": sorted(set(recs) - set(prev)), "removed": sorted(set(prev) - set(recs)),
                "changed": sorted(n for n in recs if n in prev and recs[n]["digest"] != prev[n]["digest"]), "collisions": coll,
                "flagged": sorted(n for n, r in recs.items() if r["description_flagged"]), "schema_problems": {n: r["schema_problems"] for n, r in recs.items() if r["schema_problems"]},
                "manifest_digest": _sha({n: r["digest"] for n, r in sorted(recs.items())})}

    def mark_stale(self, server_id: str) -> None: self.stale.add(server_id)            # e.g. on notifications/tools/list_changed

    def approve(self, server_id: str, names: list[str], by: str) -> None:
        if not by: raise ManifestError("NO_APPROVER", "approval needs an approver identity")
        for n in names:
            if n not in self.observed.get(server_id, {}): raise ManifestError("UNKNOWN_TOOL", f"cannot approve unobserved tool {n}")
            self.approved.setdefault(server_id, {})[n] = self.observed[server_id][n]["digest"]

    def resolve(self, server_id: str, name: str) -> dict:
        """The ONLY way a call becomes eligible: tool observed, approved at its CURRENT digest, manifest fresh, no unresolved collisions."""
        if server_id in self.stale: raise ManifestError("MANIFEST_STALE", "tool list changed; refresh tools/list before calling")
        rec = self.observed.get(server_id, {}).get(name)
        if rec is None: raise ManifestError("UNKNOWN_TOOL", f"{server_id}/{name} is not in the observed manifest")
        ap = self.approved.get(server_id, {}).get(name)
        if ap is None: raise ManifestError("NOT_APPROVED", f"{server_id}/{name} has not been approved")
        if ap != rec["digest"]: raise ManifestError("MANIFEST_CHANGED", f"{server_id}/{name} changed after approval (rug pull); re-approval required")
        if rec["schema_problems"]: raise ManifestError("BAD_SCHEMA", "; ".join(rec["schema_problems"]))
        k = confusable_key(name)
        if sum(1 for n in self.observed[server_id] if confusable_key(n) == k) > 1: raise ManifestError("CONFUSABLE_NAME", f"{name} is confusable with another tool")
        return rec
