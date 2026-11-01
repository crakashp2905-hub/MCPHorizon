"""Monitored-automata obligation engine (P40-03/04/06/07/08). Each (task, branch) is a small deterministic automaton over events: EVIDENCE, REQUEST, TICK, CANCEL.
The engine holds a public-key-only Verifier: it cannot mint evidence."""
from __future__ import annotations
import copy, hashlib, json
from dataclasses import dataclass, field
from ..authz.effect import args_digest as _ad
from ..hpolicy.authority import EvidenceError
from .terms import Obligation, parse as _parse


@dataclass
class Decision:
    verdict: str                 # ALLOW | DENY
    reasons: list = field(default_factory=list)
    guarded: bool = True
    def __bool__(self): return self.verdict == "ALLOW"


@dataclass
class Task:
    task: str; branch: str; requester: str; artifact: str; object_version: int
    satisfied: dict = field(default_factory=dict)      # oid -> (seq, token)
    rejected: list = field(default_factory=list)
    ops: dict = field(default_factory=dict)            # op_id -> Decision (idempotent retries)
    pending_post: dict = field(default_factory=dict)   # oid -> deadline
    committed_at: dict = field(default_factory=dict)   # action -> time
    seq: int = 0; cancelled: bool = False; frozen: bool = False


class Engine:
    def __init__(self, authority, obligations, clock, unguarded=("read_logs", "status")):
        self.auth, self.clock, self.unguarded = authority, clock, frozenset(unguarded); self.ver = authority.verifier(); self.obs: dict[str, list] = {}
        for o in obligations: self.obs.setdefault(o.action, []).append(o)
        self.by_id = {o.id: o for o in obligations}; self.log = []

    # ---- events --------------------------------------------------------------------------------------------------------------------------------------------------
    def new_task(self, task, requester, artifact, object_version=1, branch="main"): return Task(task, branch, requester, artifact, object_version)

    def fork(self, t: Task, branch: str) -> Task:
        """Concurrent branch: inherits what has been PRESENTED (tokens are re-verified at action time) but never inherits consumed approvals, op results, or commits."""
        c = copy.deepcopy(t); c.branch = branch; c.ops = {}; c.committed_at = {}; c.pending_post = {}; return c

    def cancel(self, t: Task): t.cancelled = True; t.pending_post.clear()

    def evidence(self, t: Task, token: str) -> list:
        """Present evidence; returns the list of obligation ids it satisfied (empty + reasons logged on rejection)."""
        now = int(self.clock()); t.seq += 1
        try: p = self.ver.verify(token, now=now)
        except EvidenceError as e: t.rejected.append(("EVIDENCE_" + e.code, token[:12])); return []
        hit = []
        for o in self.by_id.values():
            if o.evidence_kind != p["kind"] or p["role"] not in o.roles: continue
            if p["artifact"] != t.artifact: t.rejected.append(("ARTIFACT_MISMATCH", o.id)); continue
            if not (o.valid_from <= now < o.valid_until): t.rejected.append(("OBLIGATION_WINDOW", o.id)); continue
            if any(p["claim"].get(k_) != v for k_, v in o.claim_equals): t.rejected.append(("CLAIM_MISMATCH", o.id)); continue
            if o.distinct_from_requester and p["iss"] == t.requester: t.rejected.append(("SELF_APPROVAL", o.id)); continue
            if any(not self._valid_now(t, a, now) for a in o.order_after): t.rejected.append(("ORDER_VIOLATION", o.id)); continue
            if o.kind == "POST" and o.id not in t.pending_post: t.rejected.append(("POST_NOT_OPEN", o.id)); continue
            t.satisfied[o.id] = (t.seq, token); t.pending_post.pop(o.id, None); hit.append(o.id)
        return hit

    def _valid_now(self, t, oid, now):
        """A prerequisite counts for ORDER only while its own evidence is still valid (an approval cannot be granted against an expired test result)."""
        if oid not in t.satisfied: return False
        try: self.ver.verify(t.satisfied[oid][1], now=now); return True
        except EvidenceError: return False

    def request(self, t: Task, action: str, args, *, op_id: str, object_version: int | None = None) -> Decision:
        now = int(self.clock())
        if op_id in t.ops: d = copy.copy(t.ops[op_id]); d.reasons = d.reasons + ["IDEMPOTENT_REPLAY"]; return d      # retry: same decision, never a second commit
        pre = [o for o in self.obs.get(action, []) if o.kind == "PRE"]
        if action not in self.obs:
            # only actions the policy owner explicitly lists as non-consequential pass without evidence; an unknown action is NOT assumed harmless
            return Decision("ALLOW", ["UNGUARDED_BY_POLICY"], guarded=False) if action in self.unguarded else Decision("DENY", ["UNKNOWN_ACTION"], guarded=False)
        reasons = []
        if t.cancelled: reasons.append("CANCELLED")
        if t.frozen: reasons.append("FROZEN_POST_OBLIGATION")
        ov = t.object_version if object_version is None else object_version
        if ov != t.object_version: reasons.append("STALE_VERSION")
        ad = _ad(args); consumed = []
        for o in pre:
            if not (o.valid_from <= now < o.valid_until): reasons.append("OBLIGATION_WINDOW:" + o.id); continue
            if o.id not in t.satisfied: reasons.append("MISSING:" + o.id); continue
            try: p = self.ver.verify(t.satisfied[o.id][1], now=now)          # re-verified NOW: expiry/revocation is checked at action time
            except EvidenceError as e: reasons.append("EVIDENCE_%s:%s" % (e.code, o.id)); continue
            if p["artifact"] != t.artifact: reasons.append("ARTIFACT_MISMATCH:" + o.id)
            if o.bind_args and p["args_digest"] != ad: reasons.append("ARGS_MISMATCH:" + o.id)
            if p["object_version"] != ov: reasons.append("STALE_EVIDENCE:" + o.id)
            if o.consume: consumed.append((o.id, p["nonce"]))
        for _, n in consumed:
            if n in self.ver.seen: reasons.append("REPLAY")
        if reasons: d = Decision("DENY", sorted(set(reasons) | {"REJECTED:%s:%s" % (c, x) for c, x in t.rejected if c in ("SELF_APPROVAL", "ORDER_VIOLATION", "CLAIM_MISMATCH", "ARTIFACT_MISMATCH", "EVIDENCE_UNTRUSTED_ISSUER", "EVIDENCE_BAD_SIGNATURE", "EVIDENCE_EXPIRED")}))
        else:
            for _, n in consumed: self.ver.seen.add(n)
            d = Decision("ALLOW", []); t.committed_at[action] = now
            for o in self.obs[action]:
                if o.kind == "POST": t.pending_post[o.id] = now + o.deadline_s
        t.ops[op_id] = d; self.log.append((t.task, t.branch, action, op_id, d.verdict, d.reasons)); return d

    def tick(self, t: Task) -> list:
        """Deadline monitor: unmet POST obligations past their deadline freeze the task for guarded actions."""
        now = int(self.clock()); v = [oid for oid, dl in t.pending_post.items() if now > dl]
        for oid in v: t.frozen = True
        return sorted(v)

    # ---- handoff / cross-protocol (P40-06) -----------------------------------------------------------------------------------------------------------------------
    def export(self, t: Task) -> str:
        st = {"task": t.task, "branch": t.branch, "requester": t.requester, "artifact": t.artifact, "object_version": t.object_version, "policy_version": self.auth.version,
              "obligations": [o.d() for a in sorted(self.obs) for o in self.obs[a]], "satisfied": {k: [s, tok] for k, (s, tok) in t.satisfied.items()}, "pending_post": t.pending_post, "frozen": t.frozen, "cancelled": t.cancelled,
              "committed_at": t.committed_at, "seq": t.seq}
        return self.auth.seal(st)

    def import_(self, sealed: str) -> Task:
        st = self.auth.open(sealed)
        if st["policy_version"] != self.auth.version: raise EvidenceError("POLICY_VERSION", "handoff bound to another policy version")
        mine = sorted(o.digest() for a in self.obs for o in self.obs[a]); theirs = sorted(_parse(d, policy_version=self.auth.version, now=int(self.clock())).digest() for d in st["obligations"])
        if mine != theirs: raise EvidenceError("OBLIGATION_SET_MISMATCH", "carried obligations differ from this engine's catalog")
        t = Task(st["task"], st["branch"], st["requester"], st["artifact"], st["object_version"]); t.satisfied = {k: (v[0], v[1]) for k, v in st["satisfied"].items()}; t.pending_post = st["pending_post"]
        t.frozen, t.cancelled, t.committed_at, t.seq = st["frozen"], st["cancelled"], st["committed_at"], st["seq"]; return t


def to_mcp_meta(sealed: str) -> dict: return {"_meta": {"io.horizon/obligations": sealed}}
def from_mcp_meta(msg: dict) -> str | None: return (msg.get("_meta") or {}).get("io.horizon/obligations")
def to_http_headers(sealed: str) -> dict: return {"X-Horizon-Obligations": sealed}
def from_http_headers(h: dict) -> str | None:
    for k, v in h.items():
        if k.lower() == "x-horizon-obligations": return v
    return None
