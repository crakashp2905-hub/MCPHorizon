"""Trusted lineage sidecar (P7-01, P7-05..P7-09, P7-21, P7-22). The sidecar, not the agent, assigns identity, labels, parents and provenance.
Agents get opaque handle ids. An agent-supplied artifact dict that claims labels/lineage/provenance is a forgery and is rejected + audited."""
from __future__ import annotations
import copy, hashlib, json, time
from ..core import labels as L
from .. import schemas

C, T = L.C, L.T
FORGEABLE = {"confidentiality", "trust", "parents", "partial_lineage", "producer_event_id", "purpose_tags", "retention_class", "tenant_id", "content_digest", "declassified_by", "validation", "verified", "provenance", "lineage"}


class LineageError(Exception):
    def __init__(self, code, msg): super().__init__(msg); self.code = code


def digest(content) -> str:
    b = content if isinstance(content, bytes) else json.dumps(content, sort_keys=True, separators=(",", ":"), default=str).encode()
    return "sha256:" + hashlib.sha256(b).hexdigest()


class Sidecar:
    def __init__(self, tenant: str, *, sources: dict, default=("INTERNAL", "UNTRUSTED"), declassifier_keys: dict | None = None, clock=time.time, store=None):
        """sources: operator-configured {source_id: (confidentiality, trust)}. Caller-supplied labels are never accepted."""
        self.tenant, self.sources, self.default, self.keys, self.clock, self.store = tenant, dict(sources), default, dict(declassifier_keys or {}), clock, store
        self.art: dict[str, dict] = {}; self.meta: dict[str, dict] = {}; self.audit: list[dict] = []; self.used_nonces: set[str] = set(); self.sensitive: dict[str, dict] = {}; self._n = 0

    # ---- creation (the only ways an artifact comes to exist)
    def _put(self, a: dict, meta: dict) -> str:
        errs = schemas.validate("artifact", a)
        if errs: raise LineageError("ARTIFACT_INVALID", "; ".join(errs[:3]))
        self.art[a["id"]] = a; self.meta[a["id"]] = meta
        if self.store: self.store(copy.deepcopy(a))
        return a["id"]

    def _id(self, kind: str, d: str) -> str:
        self._n += 1; return f"{kind}-" + hashlib.sha256(f"{self.tenant}|{kind}|{d}|{self._n}".encode()).hexdigest()[:28]

    def ingest(self, source_id: str, content, *, principal: str, event_id: str, protocol: str = "mcp") -> str:
        """New data entering from an MCP result, UTCP response or Code Mode value. Label = operator config for that source (unknown source => default)."""
        conf, trust = self.sources.get(source_id, self.default); d = digest(content)
        h = self._id("a", d)
        self._put({"id": h, "producer_event_id": _safe(event_id), "parents": [], "confidentiality": conf, "trust": trust, "tenant_id": self.tenant, "partial_lineage": False, "content_digest": d},
                  {"kind": "ingest", "source": source_id, "protocol": protocol, "principal": principal, "digest": d})
        if C[conf] >= C["CONFIDENTIAL"]: self._register_sensitive(h, content)
        return h

    def derive(self, parents: list[str], output, *, op: str, principal: str, event_id: str, opaque: bool = False, protocol: str = "codemode") -> str:
        """A value computed from parents. Conservative: confidentiality = max, trust = min. A parent this sidecar does not know (lost event, another tenant,
        truncated provenance) => SECRET, UNTRUSTED and partial_lineage. `opaque` (model paraphrase, unknown code) is recorded but labels are the same."""
        ps = sorted(set(parents)); missing = [p for p in ps if p not in self.art]
        conf = L.join_conf([self.art[p]["confidentiality"] for p in ps if p in self.art]); trust = L.meet_trust([self.art[p]["trust"] for p in ps if p in self.art])
        if missing: conf, trust = "SECRET", "UNTRUSTED"; self.audit.append({"event": "unknown_parent", "parents": [_safe(m) for m in missing][:10], "principal": principal})
        d = digest(output); h = self._id("d", d)
        self._put({"id": h, "producer_event_id": _safe(event_id), "parents": [p for p in ps if p in self.art], "confidentiality": conf, "trust": trust, "tenant_id": self.tenant, "partial_lineage": bool(missing), "content_digest": d},
                  {"kind": "derive", "op": op, "opaque": opaque, "protocol": protocol, "principal": principal, "digest": d, "missing_parents": len(missing)})
        if C[conf] >= C["CONFIDENTIAL"]: self._register_sensitive(h, output)
        return h

    def get(self, h: str) -> dict:
        if h not in self.art: raise LineageError("UNKNOWN_HANDLE", "unknown handle")
        return copy.deepcopy(self.art[h])                                           # a copy: mutating it changes nothing

    # ---- forgery
    def accept_agent_artifact(self, d: dict, *, principal: str):
        """Agents may not submit artifacts. Any dict is rejected; if it claims label/lineage/provenance fields that is recorded as a forgery attempt."""
        claimed = sorted(set(d) & FORGEABLE) if isinstance(d, dict) else []
        self.audit.append({"event": "forgery_attempt" if claimed else "agent_artifact_rejected", "fields": claimed, "principal": principal})
        raise LineageError("FORGED_PROVENANCE" if claimed else "NOT_ALLOWED", "artifacts and provenance fields are assigned by the trusted sidecar only")

    # ---- declassification
    def declassify(self, h: str, to_conf: str, *, purpose: str, sink_zones: list[str], declassifier: str, nonce: str, reason: str, sig: str, ttl_s: float = 3600) -> str:
        """Purpose- and zone-bound, signed, one-time, expiring. The result is a NEW artifact with no parents (otherwise parent-max would undo it); the
        link to the original is kept in sidecar metadata and the audit log."""
        a = self.art.get(h)
        if a is None: raise LineageError("UNKNOWN_HANDLE", "unknown handle")
        if not purpose or not sink_zones: raise LineageError("UNBOUND", "declassification must name a purpose and sink zones")
        if a["partial_lineage"] or any(not schemas.lineage_complete(p, self.art) for p in a["parents"]): raise LineageError("PARTIAL_LINEAGE", "cannot declassify a value with incomplete lineage")
        req = {"artifact_id": h, "from": a["confidentiality"], "to": to_conf, "nonce": nonce, "declassifier": declassifier, "reason": reason}
        try: L.declassify(a, to_conf, req, sig, self.keys, self.used_nonces)
        except PermissionError as e: self.audit.append({"event": "declassify_refused", "artifact": h, "why": str(e)[:80]}); raise LineageError("DECLASSIFY_REFUSED", str(e))
        d = self._id("x", h)
        self._put({"id": d, "producer_event_id": _safe(f"declass:{nonce}"), "parents": [], "confidentiality": to_conf, "trust": a["trust"], "tenant_id": self.tenant, "partial_lineage": False,
                   "content_digest": a.get("content_digest", digest(h)), "purpose_tags": [purpose[:64]]},
                  {"kind": "declassified", "from": h, "purpose": purpose, "zones": sorted(sink_zones), "declassifier": declassifier, "reason": reason[:200], "expires": self.clock() + ttl_s, "digest": self.meta[h]["digest"]})
        self.audit.append({"event": "declassified", "from": h, "to": d, "purpose": purpose, "zones": sorted(sink_zones), "declassifier": declassifier})
        return d

    def use_allowed(self, h: str, purpose: str | None, sink_zone: str | None) -> bool:
        """Declassified artifacts are usable only for their purpose, in their zones, before expiry. Ordinary artifacts: always (policy decides)."""
        m = self.meta.get(h)
        if m is None: return False
        if m["kind"] != "declassified": return True
        return purpose == m["purpose"] and sink_zone in m["zones"] and self.clock() < m["expires"]

    # ---- sensitive value registry (feeds the outgoing-boundary detector)
    def _register_sensitive(self, h: str, content) -> None:
        for s in _leaves(content):
            if len(s) >= 8: self.sensitive[hashlib.sha256(s.encode()).hexdigest()] = {"handle": h, "len": len(s), "s": s}

    def ancestors(self, h: str) -> set[str]:
        seen, st = set(), [h]
        while st:
            x = st.pop()
            if x in seen: continue
            seen.add(x)
            if x in self.art: st.extend(self.art[x]["parents"])
        return seen


def _safe(s) -> str:
    import re
    s = re.sub(r"[^A-Za-z0-9_.:@/-]", "_", str(s))[:100]
    return s if s and s[0].isalnum() else "e" + s


def _leaves(o, depth=0):
    if depth > 8: return
    if isinstance(o, str): yield o
    elif isinstance(o, bytes): yield o.decode("utf-8", "replace")
    elif isinstance(o, dict):
        for v in o.values(): yield from _leaves(v, depth + 1)
    elif isinstance(o, (list, tuple)):
        for v in o: yield from _leaves(v, depth + 1)


class Hub:
    """Tenant isolation and intentional sharing (P7-07). Sidecars never see each other's handles; sharing needs an admin-issued grant that is
    scoped (handle, purposes, expiry) and yields a NEW artifact in the receiving tenant with partial lineage and untrusted trust."""
    def __init__(self, admins: set, clock=time.time): self.defaults: dict = {}; self.sc: dict[str, Sidecar] = {}; self.grants: dict[str, dict] = {}; self.admins, self.clock, self._n = set(admins), clock, 0
    def sidecar(self, tenant: str, **kw) -> Sidecar:
        if tenant not in self.sc:
            if not kw and "sources" not in self.defaults: raise LineageError("NO_SIDECAR", "tenant has no sidecar configured")
            self.defaults = self.defaults or kw; self.sc[tenant] = Sidecar(tenant, clock=self.clock, **(kw or self.defaults))
        return self.sc[tenant]
    def grant(self, frm: str, to: str, h: str, *, by: str, purposes: list[str], ttl_s: float = 3600) -> str:
        if by not in self.admins: raise LineageError("NOT_ADMIN", "only an admin may share across tenants")
        if frm == to or h not in self.sc[frm].art or not purposes: raise LineageError("BAD_GRANT", "invalid grant")
        self._n += 1; g = "g-" + hashlib.sha256(f"{frm}|{to}|{h}|{self._n}".encode()).hexdigest()[:24]
        self.grants[g] = {"from": frm, "to": to, "handle": h, "purposes": sorted(purposes), "exp": self.clock() + ttl_s, "by": by, "revoked": False, "accepted": False}; return g
    def revoke(self, g: str, by: str) -> None:
        if by not in self.admins: raise LineageError("NOT_ADMIN", "only an admin may revoke")
        self.grants[g]["revoked"] = True
    def accept(self, g: str, tenant: str, *, principal: str, purpose: str) -> str:
        gr = self.grants.get(g)
        if gr is None or gr["to"] != tenant or gr["revoked"] or self.clock() > gr["exp"] or gr["accepted"] or purpose not in gr["purposes"]: raise LineageError("GRANT_INVALID", "grant not usable")
        gr["accepted"] = True; src = self.sc[gr["from"]]; a = src.art[gr["handle"]]; dst = self.sidecar(tenant)
        h = dst._id("s", g)
        dst._put({"id": h, "producer_event_id": _safe(f"grant:{g}"), "parents": [], "confidentiality": a["confidentiality"], "trust": "UNTRUSTED", "tenant_id": tenant, "partial_lineage": True,
                  "content_digest": a.get("content_digest", digest(g)), "purpose_tags": [purpose[:64]]}, {"kind": "shared", "grant": g, "principal": principal, "digest": src.meta[gr["handle"]]["digest"]})
        if C[a["confidentiality"]] >= C["CONFIDENTIAL"]:
            for k, v in src.sensitive.items():
                if v["handle"] == gr["handle"]: dst.sensitive[k] = {**v, "handle": h}
        return h


class Delegations:
    """Delegation attenuation (P7-21): a delegate receives a SUBSET of handles and purposes, never more than the delegator holds, and may re-delegate only
    if allowed, only a subset of that, and never past the parent's expiry."""
    def __init__(self, clock=time.time): self.d: dict[str, dict] = {}; self.clock, self._n = clock, 0
    def root(self, agent: str, handles: set, purposes: set, ttl_s: float = 3600, can_redelegate=True) -> str:
        self._n += 1; k = f"dl-{self._n}"; self.d[k] = {"agent": agent, "handles": set(handles), "purposes": set(purposes), "exp": self.clock() + ttl_s, "redeleg": can_redelegate, "parent": None}; return k
    def delegate(self, parent: str, to_agent: str, handles: set, purposes: set, ttl_s: float = 3600, can_redelegate=False) -> str:
        p = self.d.get(parent)
        if p is None or self.clock() > p["exp"]: raise LineageError("DELEGATION_INVALID", "parent delegation missing or expired")
        if not p["redeleg"]: raise LineageError("NO_REDELEGATION", "this delegation may not be passed on")
        if not set(handles) <= p["handles"] or not set(purposes) <= p["purposes"]: raise LineageError("ESCALATION", "delegation may only narrow handles and purposes")
        if can_redelegate and not p["redeleg"]: raise LineageError("ESCALATION", "cannot grant re-delegation that the parent lacks")
        self._n += 1; k = f"dl-{self._n}"; self.d[k] = {"agent": to_agent, "handles": set(handles), "purposes": set(purposes), "exp": min(p["exp"], self.clock() + ttl_s), "redeleg": can_redelegate, "parent": parent}; return k
    def allows(self, k: str, agent: str, handle: str, purpose: str) -> bool:
        x = self.d.get(k)
        while x:
            if self.clock() > x["exp"]: return False
            x = self.d.get(x["parent"]) if x["parent"] else None
        x = self.d.get(k); return bool(x and x["agent"] == agent and handle in x["handles"] and purpose in x["purposes"])
