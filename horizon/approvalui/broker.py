"""P88: server-side approval broker for streamed agent UIs. CANDIDATE, local, stdlib only.
The browser/agent are untrusted: approvals bind approver + exact operation digest + destination + policy revision + expiry,
are server-signed, single-use, revocable, and re-checked against the effect actually about to happen."""
import hashlib, hmac, json, os

STATES = ("NEEDS_APPROVAL", "APPROVED", "DENIED", "UNKNOWN", "INCOMPLETE")
def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def op_digest(op): return hashlib.sha256(canon(op)).hexdigest()

def effect_summary(op):
    """Server-generated from structured fields only; any agent-written description is ignored. Shows every arg key=value."""
    args = ", ".join("%s=%r" % (k, op["args"][k]) for k in sorted(op.get("args", {})))
    return "%s on %s with %s" % (op["tool"], op["target"], args or "no arguments")

def summary_mismatch(agent_text, op):
    """True if the agent-supplied text hides any target or arg value that the server summary would show."""
    t = agent_text or ""
    need = [str(op["target"])] + [str(v) for v in op.get("args", {}).values()]
    return any(n not in t for n in need)

class Broker:
    def __init__(self, clock, secret=None, origins=("https://ui.test",), policy_rev=1):
        self.clock, self._k, self.origins, self.rev = clock, secret or os.urandom(32), set(origins), policy_rev
        self.approvers = {}      # approver_id -> session token
        self.agents = set()
        self.pending = {}; self.used = set(); self.revoked = set(); self.csrf = {}
    def register_approver(self, aid, session): self.approvers[aid] = session
    def register_agent(self, aid): self.agents.add(aid)
    def new_csrf(self, aid):
        n = os.urandom(8).hex(); self.csrf[n] = aid; return n
    def request(self, op, dest, ttl=60):
        d = op_digest(op); rid = hashlib.sha256(d.encode() + dest.encode() + str(self.clock()).encode() + os.urandom(4)).hexdigest()[:16]
        self.pending[rid] = {"digest": d, "dest": dest, "exp": self.clock() + ttl, "rev": self.rev, "state": "NEEDS_APPROVAL", "summary": effect_summary(op)}
        return rid, self.pending[rid]["summary"]
    def _sign(self, rec): return hmac.new(self._k, canon(rec), hashlib.sha256).hexdigest()
    def decide(self, rid, principal, session, origin, csrf, approve):
        """Only a registered approver (never an agent) with the right session, an allowed origin and a fresh csrf nonce."""
        p = self.pending.get(rid)
        if p is None or p["state"] != "NEEDS_APPROVAL": return "REJECT", "unknown or already decided"
        if principal in self.agents: return "REJECT", "agents cannot approve"
        if self.approvers.get(principal) is None or self.approvers[principal] != session: return "REJECT", "unauthenticated approver"
        if origin not in self.origins: return "REJECT", "bad origin"
        if self.csrf.pop(csrf, None) != principal: return "REJECT", "bad or reused csrf"
        if self.clock() >= p["exp"]: return "REJECT", "expired"
        if p["rev"] != self.rev: return "REJECT", "stale policy revision"
        p["state"] = "APPROVED" if approve else "DENIED"; p["approver"] = principal
        if not approve: return "DENIED", ""
        rec = {"rid": rid, "digest": p["digest"], "dest": p["dest"], "exp": p["exp"], "rev": p["rev"], "approver": principal}
        return "APPROVED", dict(rec, sig=self._sign(rec))
    def revoke(self, rid): self.revoked.add(rid)
    def consume(self, token, op, dest):
        """Called by the enforcement point immediately before the side effect with the REAL operation."""
        rec = {k: token.get(k) for k in ("rid", "digest", "dest", "exp", "rev", "approver")}
        if not hmac.compare_digest(token.get("sig", ""), self._sign(rec)): return "DENIED", "bad signature"
        if rec["rid"] in self.revoked: return "DENIED", "revoked"
        if rec["rid"] in self.used: return "DENIED", "replay"
        if self.clock() >= rec["exp"]: return "DENIED", "expired"
        if rec["rev"] != self.rev: return "DENIED", "stale policy revision"
        if op_digest(op) != rec["digest"]: return "DENIED", "operation changed since approval"
        if dest != rec["dest"]: return "DENIED", "destination changed"
        self.used.add(rec["rid"]); return "APPROVED", ""

def ui_decision(ui_state, token=None):
    """Optimistic UI state is never a security decision; only a verified broker token counts."""
    if token is None: return "UNKNOWN"
    return "APPROVED" if ui_state == "approved" and token else "UNKNOWN"

class StreamVerifier:
    """Per-run event ordering: seq strictly increasing from 0, no duplicates, nothing after CANCELLED/DONE; missing DONE -> INCOMPLETE."""
    def __init__(self): self.runs = {}
    def feed(self, run, seq, kind):
        r = self.runs.setdefault(run, {"next": 0, "closed": None, "seen": set()})
        if seq in r["seen"]: return "DUPLICATE"
        if r["closed"]: return "AFTER_CLOSE"
        if seq != r["next"]: return "GAP_OR_REORDER"
        r["seen"].add(seq); r["next"] += 1
        if kind in ("CANCELLED", "DONE"): r["closed"] = kind
        return "OK"
    def state(self, run):
        r = self.runs.get(run)
        if r is None: return "UNKNOWN"
        return "COMPLETE" if r["closed"] == "DONE" else ("CANCELLED" if r["closed"] else "INCOMPLETE")
