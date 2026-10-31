"""Transaction-aware prevention (P17). Synthetic fixtures only. Prevention is counted ONLY when the independent oracle ledger shows the prohibited effect absent (GX7)."""
from __future__ import annotations
import copy, hashlib, itertools
from dataclasses import dataclass

CLASSES = ("REVERSIBLE", "COMPENSABLE", "IRREVERSIBLE", "UNKNOWN", "DELAYED", "EXTERNAL_VISIBLE")
NEEDS_APPROVAL = {"IRREVERSIBLE", "UNKNOWN", "EXTERNAL_VISIBLE", "DELAYED"}       # cannot be staged and rolled back: human approval before commit (P17-11)


class Fault(Exception): pass


@dataclass(frozen=True)
class Contract:
    effect_class: str
    dry_run: bool = True
    idempotent: bool = False
    compensation: str | None = None          # name of compensating operation; None = none exists

    def __post_init__(self):
        if self.effect_class not in CLASSES: raise ValueError("bad effect class")
        if self.effect_class == "COMPENSABLE" and not self.compensation: raise ValueError("COMPENSABLE requires a compensation")


class Ledger:
    """Independent oracle: append-only hash chain of effects that ACTUALLY reached the synthetic resource, written by the resource, not by the engine."""
    def __init__(self): self.rows, self.head = [], "0" * 64
    def append(self, row): self.head = hashlib.sha256((self.head + repr(sorted(row.items()))).encode()).hexdigest(); self.rows.append(dict(row, h=self.head))
    def verify(self):
        h = "0" * 64
        for r in self.rows:
            row = {k: v for k, v in r.items() if k != "h"}; h = hashlib.sha256((h + repr(sorted(row.items()))).encode()).hexdigest()
            if h != r["h"]: return False
        return True
    def effects(self, key): return [r for r in self.rows if r["key"] == key and r["op"] != "read"]


class Resource:
    """Versioned KV with CAS and fault injection. faults: {'crash_before_apply','timeout_after_apply','partial','double_apply'}"""
    def __init__(self, init=None): self.d = {k: (v, 1) for k, v in (init or {}).items()}; self.ledger = Ledger(); self.faults = set(); self.seen_tokens = {}; self.published = []
    def read(self, k): return self.d.get(k, (None, 0))
    def apply(self, k, v, expect_version=None, token=None, publish=False):
        if "crash_before_apply" in self.faults: self.faults.discard("crash_before_apply"); raise Fault("crash")
        if token is not None and token in self.seen_tokens: return self.seen_tokens[token]
        cur, ver = self.read(k)
        if expect_version is not None and ver != expect_version: raise Fault("CAS_CONFLICT")
        times = 2 if "double_apply" in self.faults else 1; self.faults.discard("double_apply")
        for _ in range(times):
            cur, ver = self.read(k); self.d[k] = (v, ver + 1); self.ledger.append({"op": "write", "key": k, "value": v})
            if publish: self.published.append((k, v))
        if token is not None: self.seen_tokens[token] = ver + times
        if "timeout_after_apply" in self.faults: self.faults.discard("timeout_after_apply"); raise Fault("timeout")      # applied, but caller sees an error
        return self.d[k][1]


class Txn:
    def __init__(self, res: Resource, policy, authz, approvals=None, *, policy_version=lambda: 1):
        self.res, self.policy, self.authz, self.approvals, self.pv, self.n = res, policy, authz, approvals or set(), policy_version, itertools.count(1)
    def prepare(self, principal, key, value, contract: Contract) -> dict:
        v = self.policy(principal, key, value)
        h = {"id": next(self.n), "principal": principal, "key": key, "value": value, "contract": contract, "policy_version": self.pv(), "read_version": self.res.read(key)[1], "pre": self.res.read(key), "prepared_ok": v is None, "deny": v, "token": f"tok-{principal}-{key}-{hashlib.sha256(repr(value).encode()).hexdigest()[:8]}"}
        return h
    def commit(self, h: dict) -> dict:
        """Re-binds authorization and policy version at COMMIT, not just prepare (P17-04), CAS on resource version (P17-05)."""
        if not h["prepared_ok"]: return {"status": "REFUSED", "why": h["deny"]}
        if self.pv() != h["policy_version"]: return {"status": "REFUSED", "why": "POLICY_CHANGED"}
        if not self.authz(h["principal"], h["key"]): return {"status": "REFUSED", "why": "AUTHZ_REVOKED"}
        re = self.policy(h["principal"], h["key"], h["value"])
        if re is not None: return {"status": "REFUSED", "why": re}
        if h["contract"].effect_class in NEEDS_APPROVAL and h["id"] not in self.approvals: return {"status": "NEEDS_APPROVAL"}
        try:
            self.res.apply(h["key"], h["value"], expect_version=h["read_version"], token=h["token"] if h["contract"].idempotent else None, publish=h["contract"].effect_class in ("IRREVERSIBLE", "EXTERNAL_VISIBLE")); err = None
        except Fault as e: err = str(e)
        return {"status": "COMMITTED_OR_UNKNOWN", "transport_error": err, "outcome": self.verify(h)}
    def verify(self, h) -> str:
        """Outcome from the RESOURCE's own state/ledger, independent of exceptions (P17-07)."""
        n = len(self.res.ledger.effects(h["key"])) - h.get("ledger_before", 0); cur = self.res.read(h["key"])
        if cur[0] == h["value"]: return "APPLIED" if n <= 1 else "DUPLICATED"
        return "NOT_APPLIED" if cur == h["pre"] else "PARTIAL_OR_CONFLICT"
    def retry(self, h, *, max_tries=3) -> dict:
        """Safe retry: only if idempotent (token) — non-idempotent APIs are never blindly retried (P17-06)."""
        r = self.commit(h)
        for _ in range(max_tries - 1):
            if r.get("outcome") in ("APPLIED", "DUPLICATED") or r["status"] != "COMMITTED_OR_UNKNOWN": break
            if not h["contract"].idempotent: return dict(r, retry="REFUSED_NON_IDEMPOTENT")
            h = dict(h, read_version=self.res.read(h["key"])[1]); r = self.commit(h)
        return r
    def compensate(self, h) -> str:
        """Run the compensation, then VERIFY the restored state equals the pre-image; never assume rollback (P17-08)."""
        c = h["contract"]
        if c.effect_class in ("IRREVERSIBLE", "EXTERNAL_VISIBLE"): return "CANNOT_COMPENSATE"
        if not c.compensation: return "NO_COMPENSATION"
        pre_v, _ = h["pre"]
        if pre_v is None: self.res.d.pop(h["key"], None); self.res.ledger.append({"op": "delete", "key": h["key"], "value": None})
        else: self.res.apply(h["key"], pre_v)
        return "RESTORED" if self.res.read(h["key"])[0] == pre_v else "RESTORE_FAILED"
