"""One migration run (P53-08..10): source runtime, target(s), authoritative services, the scripted agent, hooks for time passing / tampering between freeze and resume. Deterministic."""
import base64, json
from ..hpolicy.authority import HorizonPolicy
from . import core as C
from .runtime import Runtime
from .services import Receiver, Grants, Ledger, Revocation, Broker, Attestor
K0 = {"egress": 1, "secret_export": 1, "label": 1, "budget": 1, "obligation": 1, "approval": 1, "revocation": 1}
PERMS = ["read", "write", "egress", "spend", "delete", "audit"]

def eg(host, rid=None, data=""): return {"op": "egress", "host": host, "rid": rid, "data": data}
def sd(doc, host): return {"op": "send", "doc": doc, "host": host}
def sp(n): return {"op": "spend", "n": n}
def act(action, ap=None): return {"op": "act", "action": action, "approval": ap}
def au(ob="ob1"): return {"op": "audit", "ob": ob}
def fin(): return {"op": "finish"}
def xs(host): return {"op": "export_secret", "host": host}

class World:
    def __init__(self, ex, sc):
        self.sc, self.ex = sc, ex; self.t = [1000.0]; self.clock = lambda: self.t[0]; self.nonce = 0; self.used_nonces = set(); self.bundle = None; self.model = sc.get("model", "model-1"); self.source_alive = sc.get("source_alive", True)
        self.A = HorizonPolicy("pol-1", clock=self.clock); self.att_iss = self.A.register_issuer("attestor", {"ATTESTATION"}); self.checkpointer = self.A.register_issuer("source-runtime", {"ATTESTATION"}); self.verifier = self.A.verifier()
        self.K = dict(sc.get("K", K0)); self.recv = Receiver(self.clock); self.rev = Revocation(self.clock); self.broker = Broker(); self.ledger = Ledger({"api": 100}); self.broker_enforced = ex.broker_enforced
        obl = sc.get("obligations", [{"id": "ob1", "kind": "audit_after_write", "status": "open"}]); self.grants = Grants("t1", ["owner", "agentA"], PERMS, {"docC": "CONFIDENTIAL", "docP": "PUBLIC"}, {"api": 100}, obl)
        self.approvals = {i: {"action": "delete", "exp": self.t[0] + d, "revoked": False} for i, d in sc.get("approvals", {}).items()}
        self.runtimes = {"src": Runtime("src", sc.get("source", "sandbox-a")), "tgt": Runtime("tgt", sc["target"]), "tgt2": Runtime("tgt2", sc.get("target2", sc["target"])), "ref": Runtime("ref", "sandbox-b")}
        self.src, self.tgt, self.tgt2 = self.runtimes["src"], self.runtimes["tgt"], self.runtimes["tgt2"]; self.attestor = Attestor(self.att_iss, self.clock, self.runtimes)
        if sc.get("deceive"): self.attestor.deceived["tgt"] = dict(C.CONTROLS)
        S = self.src.state; S.update(perms=list(PERMS), labels=dict(self.grants.labels), obligations=[dict(o) for o in obl], approvals={i: {"action": a["action"], "exp": a["exp"]} for i, a in self.approvals.items()}, ledger=ex.uses_ledger, caps={"api": 100}, rev="rev-t1", task="t1", raw_secret=self.broker.secret, cred=self.broker.issue("t1", "src", "read"))
        self.hooks = {"mid": sc.get("mid")}; self.results = []; self.status = None
    def peek(self, tok): return json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4)))
    def hook(self, name, bundle):
        if self.hooks.get(name): self.hooks[name](self, bundle)
    def drain(self, rt):
        """Complete the calls that were already in flight at the (frozen) source; each is applied once and recorded as done."""
        f, rt.frozen = rt.frozen, False
        for o in list(rt.pending): rt.op(self, o)
        rt.pending = []; rt.frozen = f
    def run(self, rt, ops):
        for o in ops: self.results.append((rt.id, o["op"], *rt.op(self, o)))
    def sign(self, env, nonce=None):
        return self.checkpointer.issue("ATTESTATION", principal=self.src.id, artifact=env.get("task", "t1"), args_digest=C.digest(env), claim={"k": "envelope"}, ttl=300, nonce=nonce or env.get("resume_nonce", "n-x"), now=int(self.clock()))
    def execute(self):
        sc, ex = self.sc, self.ex; self.run(self.src, sc.get("pre", [])); self.src.pending = [dict(o) for o in sc.get("inflight", [])]
        res = ex.migrate(self); self.status = res; active = self.tgt if res["status"] == "MIGRATED" else (self.src if res["status"] == "ROLLED_BACK" else None)
        for o in list(self.src.pending):                                         # an unacknowledged call that was already on the wire still lands at the receiver, whatever the source is told afterwards
            self.recv.record(rt=self.src.id, op=o["op"], rid=o["rid"], host=o.get("host"), data=o.get("data", ""))
        self.src.pending = []
        if active is not None: self.run(active, sc.get("post", []))
        if sc.get("replay") and self.bundle:
            r2 = ex.migrate(self, bundle=self.bundle, tgt=self.tgt2); self.status2 = r2
            if r2["status"] == "MIGRATED": self.run(self.tgt2, sc.get("post2", []))
        if sc.get("src_post"): self.run(self.src, sc["src_post"])
        return res
