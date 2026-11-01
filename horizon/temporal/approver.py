"""Approval service (an EVIDENCE service: holds the approver Issuer; P52-03). It issues a short-lived, single-use APPROVAL token that carries the state vector the approval was granted in and is bound, through args_digest, to the exact
action (operation, actor, object, destination host) and that vector. The reviewer is a mechanical ideal-attentive proxy: it approves iff the policy function permits the action in the CURRENT state."""
import json
from . import core as C

class Approver:
    def __init__(self, issuer, store, net, clock): self.iss, self.s, self.net, self.clock, self.n = issuer, store, net, clock, 0
    def request(self, actor, obj_id, host, ttl=60):
        with self.s.tx():
            ips = self.net.resolve(host); v = self.s.view(actor, obj_id, host, ips); o = v["obj"]
            ok, why = C.permits(v["rules"], v["scopes"], o["cls"], host, ips)
            if not ok: return None
            self.n += 1; aid = "ap-%d" % self.n; claim = dict(v["vec"])
            tok = self.iss.issue("APPROVAL", principal=actor, artifact=obj_id, args_digest=C.digest(C.envelope("export", actor, obj_id, host, claim)), object_version=o["version"], ttl=ttl, claim=claim, nonce=aid, now=int(self.clock()))
            self.s.db.execute("INSERT INTO approvals(id,actor,claim,issued_seq,iat,exp) VALUES(?,?,?,?,?,?)", (aid, actor, json.dumps({**claim, "ips": ips}, sort_keys=True), self.s.rev_seq(), self.clock(), self.clock() + ttl)); return tok
