"""Fallback admission engine (P46-04, 05, 06, 11, 15). Independent of any generated code: it sees only a candidate action (endpoint, tool, operation, argument digest, requested credential scope), the task's bound floor, and the attested profile registry.

Floor: the task's mandatory guarantee vector, bound at authorization time by an evidence service (ATTESTATION, claim.type = task-floor, args_digest = floor digest). A delegated context may only TIGHTEN it; a context whose floor is weaker than the bound one is refused (FLOOR_WEAKENED).
Outcomes: ADMIT | REVIEW | BLOCK. Weaker (DOWNGRADE), unknown and incomparable profiles are never auto-admitted: REVIEW if every failing dimension is waivable, BLOCK if one is not or the policy says so. An approval authorizes exactly one action digest, once, by a different principal.
"""
import hashlib, itertools, time
from dataclasses import dataclass, field
from ..authz.effect import canonical
from ..authz.keys import Signer
from ..hpolicy.authority import EvidenceError
from . import order as O, manifest as MF


def digest(o) -> str: return "sha256:" + hashlib.sha256(canonical(o)).hexdigest()
def floor_digest(floor: dict, nonwaivable=()) -> str: return digest({"floor": O.to_json(floor), "nonwaivable": sorted(nonwaivable)})


@dataclass(frozen=True)
class Config:
    attestation: bool = True; cache_invalidation: bool = True; floor_binding: bool = True; credential_clamp: bool = True; unknown_blocks: bool = True; partial_order: bool = True; incomparable_review: bool = True; approval_binding: bool = True


@dataclass
class Ctx:
    task: str; floor: dict; nonwaivable: frozenset; token: str; principal: str; chain: tuple = (); root_floor: dict | None = None


@dataclass
class Candidate:
    id: str; endpoint: str; tool: str; op: str; args: dict; scope: tuple = (); origin: str = "planner"
    def action(self): return {"endpoint": self.endpoint, "tool": self.tool, "op": self.op, "args": digest(self.args), "scope": sorted(self.scope)}


@dataclass
class Decision:
    outcome: str; classification: str; per: dict; reasons: list; action_digest: str; candidate: Candidate; cached: bool = False
    def d(self): return {"outcome": self.outcome, "class": self.classification, "per": self.per, "reasons": self.reasons, "candidate": self.candidate.id}


class CredentialBroker:
    """Issues short-lived bearer tokens whose scope is the INTERSECTION of the candidate's request and the task floor's permitted scope."""
    def __init__(self, signer: Signer, clock=time.time, clamp=True): self.s, self.clock, self.clamp, self.n = signer, clock, clamp, 0
    def pub_hex(self): return self.s.public_raw().hex()
    def issue(self, ctx: Ctx, cand: Candidate) -> str:
        import base64, json
        allowed = set(ctx.floor.get("scope", ())); want = set(cand.scope) if cand.scope else set(allowed); scope = want & allowed if self.clamp else want
        self.n += 1; c = {"aud": cand.endpoint, "scope": sorted(scope), "sub": ctx.task, "exp": self.clock() + 60, "jti": self.n}
        b = base64.urlsafe_b64encode(json.dumps(c, sort_keys=True).encode()).rstrip(b"=").decode(); return b + "." + base64.urlsafe_b64encode(self.s.sign(b.encode())).rstrip(b"=").decode()


class Engine:
    def __init__(self, registry: MF.Registry, verifier, clock=time.time, policy_version="pol-1", cfg: Config = Config(), incomparable="REVIEW"):
        self.reg, self.v, self.clock, self.pv, self.cfg, self.incomparable = registry, verifier, clock, policy_version, cfg, incomparable
        self.cache = MF.Cache(registry, policy_version); self.consumed = set(); self.audit = []
    # ---- floor binding --------------------------------------------------------------------------------------------------------------------------------------------
    def bind(self, task, floor, nonwaivable, token, principal) -> Ctx:
        p = self.v.verify(token, now=self.clock())
        if p["kind"] != "ATTESTATION" or p["claim"].get("type") != "task-floor" or p["artifact"] != task or p["args_digest"] != floor_digest(floor, nonwaivable): raise EvidenceError("MALFORMED", "token does not bind this floor")
        return Ctx(task, dict(floor), frozenset(nonwaivable), token, principal, (principal,), dict(floor))
    def delegate(self, ctx: Ctx, child: str, extra: dict | None = None, claimed_floor: dict | None = None) -> Ctx:
        f = O.join(ctx.floor, extra) if extra else dict(ctx.floor)
        if claimed_floor is not None:
            if self.cfg.floor_binding and not O.at_least_as_strict(claimed_floor, ctx.root_floor): raise EvidenceError("FLOOR_WEAKENED", "delegated floor is weaker than the bound task floor")
            f = claimed_floor if not self.cfg.floor_binding else O.join(ctx.floor, claimed_floor)
        return Ctx(ctx.task, f, ctx.nonwaivable, ctx.token, child, ctx.chain + (child,), ctx.root_floor)
    def _floor_ok(self, ctx):
        try:
            self.v.verify(ctx.token, now=self.clock())
        except EvidenceError as e: return "FLOOR_TOKEN_" + e.code
        if self.cfg.floor_binding and not O.at_least_as_strict(ctx.floor, ctx.root_floor): return "FLOOR_WEAKENED"
        return None
    # ---- evaluation --------------------------------------------------------------------------------------------------------------------------------------------------
    def _vector(self, ep): return self.reg.vector(ep) if self.cfg.attestation else self.reg.claimed(ep)
    def action_digest(self, ctx, cand):
        return digest({"task": ctx.task, "floor": floor_digest(ctx.floor, ctx.nonwaivable), "profile": self.reg.digest(cand.endpoint), "action": cand.action()})
    def evaluate(self, ctx: Ctx, cand: Candidate) -> Decision:
        bad = self._floor_ok(ctx); ad = self.action_digest(ctx, cand)
        if bad: return Decision("BLOCK", "FLOOR", {}, [bad], ad, cand)
        def compute():
            vec = dict(self._vector(cand.endpoint)); floor = ctx.floor
            if cand.endpoint not in self.reg.p: return ("BLOCK", "UNKNOWN_ENDPOINT", {}, ["ENDPOINT_HAS_NO_PROFILE"])
            if self.reg.status(cand.endpoint) == "REVOKED": return ("BLOCK", "REVOKED", {}, ["PROFILE_REVOKED"])
            if "scope" in floor and cand.scope and vec.get("scope") is not None: vec["scope"] = frozenset(vec["scope"]) | frozenset(cand.scope)          # the candidate asks for more privilege than the endpoint profile alone implies
            if not self.cfg.unknown_blocks: vec = {d: (vec[d] if vec.get(d) is not None else floor.get(d)) for d in O.DIMS}
            if self.cfg.partial_order: cls, per = O.classify(floor, vec)
            else:
                fp = {d: (list(r)[0] if O.kind(d) == "member" and not isinstance(r, str) else r) for d, r in floor.items()}; ok = O.scalar_score({d: vec.get(d) for d in floor}) >= O.scalar_score(fp) and all(vec.get(d) is not None for d in floor)
                cls, per = ("ADMIT", {d: "SAT" for d in floor}) if ok else ("DOWNGRADE", {d: O.satisfies(d, floor[d], vec.get(d)) for d in floor})
            if cls == "ADMIT": return ("ADMIT", cls, per, [])
            bad_dims = [d for d, s in per.items() if s != "SAT"]; reasons = ["%s:%s" % (d, per[d]) for d in bad_dims]
            if any(d in ctx.nonwaivable for d in bad_dims): return ("BLOCK", cls, per, reasons + ["NON_WAIVABLE"])
            if cls == "INCOMPARABLE": return (("REVIEW" if self.incomparable == "REVIEW" else "BLOCK") if self.cfg.incomparable_review else "ADMIT", cls, per, reasons + ["INCOMPARABLE_TRADEOFF"])
            return ("REVIEW", cls, per, reasons)
        key = (cand.endpoint, self.reg.digest(cand.endpoint), self.pv, floor_digest(ctx.floor, ctx.nonwaivable), tuple(sorted(cand.scope)))
        self.reg.status(cand.endpoint)                                                                                             # applies attestation expiry (bumps the registry epoch) BEFORE the cache is consulted
        if self.cfg.cache_invalidation: r = self.cache.get(key, compute, self.pv)
        else:
            stale = self.cache.d.get(key[:1] + key[2:5]); r = stale if stale is not None else compute(); self.cache.d[key[:1] + key[2:5]] = r          # ABLATION: cached under endpoint+floor only, never invalidated
        return Decision(r[0], r[1], r[2], r[3], ad, cand)
    def choose(self, ctx: Ctx, cands: list) -> dict:
        evs = [self.evaluate(ctx, c) for c in cands]; adm = [e for e in evs if e.outcome == "ADMIT"]
        if adm: return {"action": "USE", "decision": adm[0], "evaluations": evs}                                           # candidate order is the planner's preference; the first admissible wins (deterministic)
        rev = [e for e in evs if e.outcome == "REVIEW"]
        if rev: best = min(rev, key=lambda e: (sum(1 for s in e.per.values() if s != "SAT"), cands.index(e.candidate))); return {"action": "REVIEW", "decision": best, "evaluations": evs}
        return {"action": "BLOCK", "decision": evs[0] if evs else None, "evaluations": evs}
    # ---- approvals ---------------------------------------------------------------------------------------------------------------------------------------------------
    def approval_request(self, ctx: Ctx, dec: Decision, original: str | None) -> dict:
        vec = self._vector(dec.candidate.endpoint); orig = self._vector(original) if original else {}
        rows = [{"dimension": d, "required": O.ser(ctx.floor[d]), "original": O.ser(orig.get(d)), "candidate": O.ser(vec.get(d)), "status": dec.per.get(d, "SAT")} for d in sorted(ctx.floor)]
        return {"task": ctx.task, "requester": ctx.principal, "action": dec.candidate.action(), "action_digest": dec.action_digest, "rows": rows, "classification": dec.classification, "reasons": dec.reasons, "valid_for_s": 300}
    def check_approval(self, token, req, requester) -> tuple:
        try: p = self.v.verify(token, now=self.clock())
        except EvidenceError as e: return False, "APPROVAL_" + e.code
        if p["kind"] != "APPROVAL" or p["artifact"] != req["task"]: return False, "APPROVAL_NOT_FOR_THIS_TASK"
        if self.cfg.approval_binding and p["args_digest"] != req["action_digest"]: return False, "APPROVAL_NOT_BOUND_TO_THIS_ACTION"
        if p["principal"] == requester: return False, "SELF_APPROVAL"
        if p["nonce"] in self.consumed: return False, "APPROVAL_ALREADY_USED"
        self.consumed.add(p["nonce"]); return True, ""


def render_ux(req: dict) -> str:
    """Plain-text approval screen. Shows exactly what changes, dimension by dimension, and what is being authorized."""
    a = req["action"]; L = ["APPROVAL NEEDED — fallback would lower a mandatory guarantee", "", "Task: %s    Requested by: %s" % (req["task"], req["requester"]), "Action: %s on %s via tool %s (credential scope: %s)" % (a["op"], a["endpoint"], a["tool"], ", ".join(a["scope"]) or "none"), "Action id: %s" % req["action_digest"][:23], "",
                            "%-12s %-24s %-24s %-24s %s" % ("guarantee", "required", "original endpoint", "this fallback", "result")]
    fmt = lambda v: "unknown" if v is None else ("/".join(v) if isinstance(v, list) else str(v))
    for r in req["rows"]: L.append("%-12s %-24s %-24s %-24s %s" % (r["dimension"], fmt(r["required"]), fmt(r["original"]), fmt(r["candidate"]), {"SAT": "ok", "UNSAT": "WEAKER THAN REQUIRED", "UNKNOWN": "NOT VERIFIED"}[r["status"]]))
    L += ["", "Why it needs you: " + ("; ".join(req["reasons"]) or "n/a"), "Approving authorizes THIS action once, for %d seconds. It does not lower the task's floor, and it cannot be reused for another endpoint, tool, argument or credential scope." % req["valid_for_s"], "You cannot approve a request you made yourself."]
    return "\n".join(L)
