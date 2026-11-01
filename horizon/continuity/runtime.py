"""Runtime model (P53-06, 07): what a runtime can enforce, what it enforces by default, and the operations an agent performs through it. Everything that leaves the runtime is written to the independent receiver."""
from . import core as C
STRICT = dict(C.CONTROLS)                                               # maximum each control can be enforced at
NORMAL = {"egress": 1, "secret_export": 1, "label": 1, "budget": 1, "obligation": 1, "approval": 1, "revocation": 1}       # what a sandbox enforces when running a task
LIB = {
    "sandbox-a": dict(vendor="acme", supports=STRICT, defaults=NORMAL, carrier="mcp", sinks_mediated=True, attestable=True),
    "sandbox-a2": dict(vendor="acme", supports=STRICT, defaults=NORMAL, carrier="mcp", sinks_mediated=True, attestable=True),
    "sandbox-b": dict(vendor="other", supports=STRICT, defaults=NORMAL, carrier="mcp", sinks_mediated=True, attestable=True),
    "stronger": dict(vendor="other", supports={**STRICT, "attest_logs": 1}, defaults={**NORMAL, "attest_logs": 1}, carrier="mcp", sinks_mediated=True, attestable=True),
    "lenient": dict(vendor="other", supports={"egress": 1, "secret_export": 1, "label": 1, "budget": 1, "obligation": 1, "approval": 1, "revocation": 1}, defaults={"egress": 1, "secret_export": 1, "label": 1, "budget": 1, "obligation": 1, "approval": 1, "revocation": 1}, carrier="mcp", sinks_mediated=True, attestable=True),
    "utcp-sandbox": dict(vendor="other", supports=STRICT, defaults=NORMAL, carrier="utcp", sinks_mediated=True, attestable=True),
    "cloud-broad": dict(vendor="cloudco", supports={"label": 1, "budget": 1, "obligation": 1, "approval": 1, "revocation": 1}, defaults={}, carrier="mcp", sinks_mediated=True, attestable=True),
    "cloud-nosecret": dict(vendor="cloudco", supports={"egress": 2, "label": 1, "budget": 1, "obligation": 1, "approval": 1, "revocation": 1}, defaults={}, carrier="mcp", sinks_mediated=True, attestable=True),
    "cloud-nolabel": dict(vendor="cloudco", supports={"egress": 2, "secret_export": 1, "budget": 1, "obligation": 1, "approval": 1, "revocation": 1}, defaults={}, carrier="mcp", sinks_mediated=True, attestable=True),
    "unknown-provider": dict(vendor="mystery", supports={}, defaults={}, carrier="mcp", sinks_mediated=True, attestable=False),
    "unmediated-sink": dict(vendor="other", supports=STRICT, defaults={}, carrier="mcp", sinks_mediated=False, attestable=True)}
TOOLS = ("egress", "send", "spend", "act", "audit", "finish", "export_secret")

class Runtime:
    def __init__(self, rid, kind):
        d = LIB[kind]; self.id, self.kind, self.vendor, self.supports, self.defaults, self.carrier, self.sinks_mediated, self.attestable = rid, kind, d["vendor"], dict(d["supports"]), dict(d["defaults"]), d["carrier"], d["sinks_mediated"], d["attestable"]
        self.tools = TOOLS; self.frozen = False; self.dead = False; self.eff = dict(self.defaults); self.state = self.blank(); self.pending = []; self.n = 0
    def blank(self): return {"perms": [], "labels": None, "obligations": None, "approvals": {}, "spent": 0, "ledger": False, "cred": None, "raw_secret": None, "rev": None, "done": set(), "task": None, "caps": {}}
    def freeze(self): self.frozen = True
    def unfreeze(self): self.frozen = False
    def op(self, w, o):
        k = o["op"]; self.n += 1; rid = o.get("rid") or "%s-%d" % (self.id, self.n); S = self.state
        eff = self.eff if self.sinks_mediated else {}                       # a sink that is not mediated is not subject to the runtime's controls
        if self.dead: return "DENIED", "DEAD"
        if self.frozen: return "DENIED", "FROZEN"
        if S["cred"] is not None and not w.broker.valid(S["cred"], self.id) and w.broker_enforced: return "DENIED", "CREDENTIAL_INVALID"
        if eff.get("revocation") and S["rev"]:
            st = w.rev.status(S["rev"])
            if st != "LIVE": return "DENIED", "REVOKED" if st == "REVOKED" else "REVOCATION_UNKNOWN"
        if rid in S["done"]: return "OK", "DEDUP"
        base = dict(rt=self.id, op=k, rid=rid)
        if k == "egress":
            if o["host"] not in C.ALLOWED[eff.get("egress", 0)]: return "DENIED", "EGRESS"
            w.recv.record(**base, host=o["host"], data=o.get("data", ""))
        elif k == "export_secret":
            if eff.get("secret_export"): return "DENIED", "SECRET_EXPORT"
            w.recv.record(**base, host=o["host"], data=S["raw_secret"] or S["cred"] or "")
        elif k == "send":
            lab = (S["labels"] or {}).get(o["doc"])
            if eff.get("label") and lab is not None and C.rank(lab) >= 2 and C.HOSTS[o["host"]] != "internal": return "DENIED", "LABEL"
            w.recv.record(**base, host=o["host"], doc=o["doc"])
        elif k == "spend":
            n = o["n"]
            if eff.get("budget"):
                if S["ledger"]:
                    if not w.ledger.charge("api", n): return "DENIED", "BUDGET"
                else:
                    if S["spent"] + n > S["caps"].get("api", 0): return "DENIED", "BUDGET"
            S["spent"] += n; w.recv.record(**base, amount=n, budget="api")
        elif k == "act":
            if o["action"] not in S["perms"]: return "DENIED", "PERMISSION"
            if eff.get("approval") and o["action"] == "delete":
                ap = S["approvals"].get(o.get("approval"))
                if not ap or (ap.get("exp") is not None and ap["exp"] <= w.clock()): return "DENIED", "APPROVAL"
            w.recv.record(**base, action=o["action"], approval=o.get("approval"))
        elif k == "audit":
            w.recv.record(**base, ob=o["ob"])
            for ob in S["obligations"] or []:
                if ob["id"] == o["ob"]: ob["status"] = "done"
        elif k == "finish":
            if eff.get("obligation") and any(ob["status"] != "done" for ob in S["obligations"] or []): return "DENIED", "OBLIGATION_PENDING"
            w.recv.record(**base)
        else: return "DENIED", "UNKNOWN_OP"
        S["done"].add(rid); return "OK", ""
