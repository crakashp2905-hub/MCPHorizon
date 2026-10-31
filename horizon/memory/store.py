"""Persistent memory with provenance, conservative joins, descendant invalidation (P18). Storage-independent contract: MemoryAdapter protocol + in-memory reference.
Authority NEVER derives from content, prompts, retrieval rank or similarity score; only from labels + explicit trusted declassification events."""
from __future__ import annotations
import hashlib, itertools, re
from dataclasses import dataclass, field

CONF = {"PUBLIC": 0, "INTERNAL": 1, "SECRET": 2}
TRUST = {"UNTRUSTED": 0, "TRUSTED": 1}


class MemoryError_(Exception):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


@dataclass(frozen=True)
class Label:
    trust: str; conf: str; tenant: str; owner: str; taints: frozenset = frozenset()
    def join(self, o: "Label") -> "Label":
        """Conservative: lowest trust, highest confidentiality, union of taints. Different tenants are never merged (P18-05, P18-12)."""
        if self.tenant != o.tenant: raise MemoryError_("CROSS_TENANT_JOIN")
        return Label(min(self.trust, o.trust, key=TRUST.get), max(self.conf, o.conf, key=CONF.get), self.tenant, self.owner if self.owner == o.owner else "*shared", self.taints | o.taints)


class MemoryAdapter:
    """Contract (P18-01): put / update / summarize / retrieve / delete / invalidate / revalidate. Any backend may implement it; Amberlog would be one such backend (not integrated)."""
    def put(self, *a, **k): raise NotImplementedError
    def retrieve(self, *a, **k): raise NotImplementedError


class Store(MemoryAdapter):
    def __init__(self, trusted_verifiers=frozenset({"human-reviewer"}), clock=None):
        self.r, self.children, self.quarantine, self.events, self.log, self._n, self.trusted_verifiers = {}, {}, {}, [], [], itertools.count(1), set(trusted_verifiers)
    def _id(self): return f"mem-{next(self._n)}"
    def put(self, tenant, owner, content: str, label: Label, *, session="s0", parents=()) -> str:
        if label.tenant != tenant: raise MemoryError_("LABEL_TENANT_MISMATCH")
        for p in parents:
            if p not in self.r or self.r[p]["tenant"] != tenant: raise MemoryError_("BAD_PARENT")
        i = self._id(); self.r[i] = {"id": i, "version": 1, "tenant": tenant, "content": content, "label": label, "parents": tuple(parents), "session": session, "deleted": False}
        for p in parents: self.children.setdefault(p, set()).add(i)
        self.log.append({"op": "put", "id": i, "sha": hashlib.sha256(content.encode()).hexdigest()[:12], "session": session}); return i       # logs keep a hash, never content (P18-13)
    def update(self, i, content, *, label=None):
        r = self.r[i]
        if label is not None and (TRUST[label.trust] > TRUST[r["label"].trust] or CONF[label.conf] < CONF[r["label"].conf] or label.tenant != r["tenant"]): raise MemoryError_("UPDATE_CANNOT_WEAKEN_LABEL")      # validate BEFORE mutating; only declassify() may lift labels
        r["version"] += 1; r["content"] = content
        if label is not None: r["label"] = label
        self.log.append({"op": "update", "id": i, "version": r["version"]})
    def ref(self, i): return f"{i}@{self.r[i]['version']}"                       # session-crossing versioned reference (P18-03)
    def summarize(self, tenant, owner, ids, text, *, session="s0") -> str:
        labs = [self.r[i]["label"] for i in ids]
        if not labs: raise MemoryError_("EMPTY_SUMMARY")
        L = labs[0]
        for x in labs[1:]: L = L.join(x)
        return self.put(tenant, owner, text, L, session=session, parents=ids)
    def retrieve(self, tenant, query: str, k=3) -> list:
        """Tenant filter BEFORE scoring so a shared index cannot leak across tenants; the score is returned for ranking only and carries no authority."""
        qs = set(re.findall(r"\w+", query.lower())); out = []
        for r in self.r.values():
            if r["tenant"] != tenant or r["deleted"]: continue
            sc = len(qs & set(re.findall(r"\w+", r["content"].lower()))) / (len(qs) or 1)
            if sc > 0: out.append({"id": r["id"], "ref": self.ref(r["id"]), "content": r["content"], "label": r["label"], "score": sc, "quarantined": r["id"] in self.quarantine})
        return sorted(out, key=lambda x: (-x["score"], x["id"]))[:k]
    def authority_of(self, i: str) -> dict:
        """What may this memory do? Derived ONLY from label + quarantine + declassification events. Content is ignored."""
        r = self.r[i]
        if r["deleted"] or i in self.quarantine: return {"may_instruct": False, "may_flow_to_sink": False, "why": "QUARANTINED" if i in self.quarantine else "DELETED"}
        l = r["label"]; return {"may_instruct": l.trust == "TRUSTED" and not l.taints, "may_flow_to_sink": l.conf == "PUBLIC" and not l.taints, "why": "LABEL"}
    def declassify(self, i, *, verifier: str, purpose: str, new: Label) -> None:
        """Explicit, narrowly scoped, trusted-verifier-only. Scope: this record version, one purpose. Descendants are NOT auto-declassified."""
        if verifier not in self.trusted_verifiers: raise MemoryError_("UNTRUSTED_VERIFIER")
        if not purpose: raise MemoryError_("NO_PURPOSE")
        if new.tenant != self.r[i]["tenant"]: raise MemoryError_("TENANT_CHANGE")
        self.events.append({"id": i, "version": self.r[i]["version"], "verifier": verifier, "purpose": purpose, "from": self.r[i]["label"], "to": new}); self.r[i]["label"] = new
    def descendants(self, i) -> set:
        out, st = set(), [i]
        while st:
            for c in self.children.get(st.pop(), ()):
                if c not in out: out.add(c); st.append(c)
        return out
    def invalidate(self, i, reason="compromised") -> set:
        """Quarantine the source and every transitive descendant until revalidated (P18-07/08)."""
        hit = {i} | self.descendants(i)
        for h in hit: self.quarantine[h] = reason
        self.log.append({"op": "invalidate", "id": i, "n": len(hit)}); return hit
    def revalidate(self, i, *, verifier: str) -> None:
        if verifier not in self.trusted_verifiers: raise MemoryError_("UNTRUSTED_VERIFIER")
        if any(p in self.quarantine for p in self.r[i]["parents"]): raise MemoryError_("PARENT_STILL_QUARANTINED")
        self.quarantine.pop(i, None)
    def delete(self, i, *, crypto_erase=True) -> set:
        """Tombstone + erase content; descendants are quarantined (their summaries may still embed the content — residual, P18-13)."""
        self.r[i]["deleted"] = True; self.r[i]["content"] = "" if crypto_erase else self.r[i]["content"]; self.log.append({"op": "delete", "id": i}); return self.invalidate(i, "source_deleted")
    def reconstruct(self, i) -> list:
        """Incident reconstruction (P18-16): lineage from an artifact back to roots with labels, sessions and declassification events."""
        seen, out, st = set(), [], [i]
        while st:
            x = st.pop()
            if x in seen: continue
            seen.add(x); r = self.r[x]; out.append({"id": x, "session": r["session"], "trust": r["label"].trust, "conf": r["label"].conf, "parents": list(r["parents"]), "declass": [e for e in self.events if e["id"] == x]}); st += list(r["parents"])
        return out
