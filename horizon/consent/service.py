"""Approval service (trusted): builds what the approver is shown, records the immutable approval ledger, and issues signed APPROVAL tokens bound to the action, the effect envelope, tenant, task, agent and policy (P48-01, 02, 05)."""
from . import core as K
from ..hpolicy.authority import EvidenceError


class ApprovalService:
    def __init__(self, issuer, platform, clock, policy=K.POLICY):
        self.i, self.p, self.clock, self.policy = issuer, platform, clock, policy; self.ledger = []
    def present(self, mode, action, ctx, previous=None, agent_fields=None):
        if mode in ("effect", "diff"): return K.derive_view(self.p.effect_of(action, ctx["tenant"], ctx["task"]), previous if mode == "diff" else None)
        if mode == "args":
            f = {"op": action["op"], "resource_id": action.get("artifact"), "amount": action.get("amount"), "scope": action.get("audience")}
            f["destination_names"] = [action["destination"]] if action["op"] == "publish" else list(action.get("recipients", [])) if action["op"] == "send" else [action["payee"]]            # hidden parameters (mirrors, cc) are not shown
            return {"fields": f, "text": "TOOL %s %s" % (action["op"], {k: v for k, v in f.items() if v is not None and k != "op"})}
        if mode == "prose": return {"fields": dict(agent_fields or {}), "text": "AGENT SUMMARY: " + (ctx.get("agent_summary") or "(none)")}
        return {"fields": {}, "text": "Approve the pending action?"}
    def grant(self, ctx, action, envelope, approver, mode, ttl=900, style="full"):
        """style: 'full' = bound to action, effect envelope, tenant, task, agent, policy; 'args' = signed operation arguments only; 'task' = a bare approval for the task (button / free-form)."""
        eff = K.digest(envelope)[:23]; claim = {"eff": eff, "ten": ctx["tenant"], "task": ctx["task"], "ag": ctx["agent"], "pol": K.policy_digest(self.policy)} if style == "full" else {}
        tok = self.i.issue("APPROVAL", principal=approver, artifact=ctx["task"], args_digest="*" if (style == "full" and envelope.get("bounds")) or style == "task" else K.digest(action), ttl=ttl, claim=claim, now=self.clock.now())
        self.ledger.append({"id": len(self.ledger), "approver": approver, "owner": ctx["owner"], "tenant": ctx["tenant"], "task": ctx["task"], "agent": ctx["agent"], "envelope": envelope, "policy": K.policy_digest(self.policy), "mode": mode, "t": self.clock.now(), "ttl": ttl})
        return tok
