from __future__ import annotations
import time
from ..hpolicy import HorizonPolicy
from ..authz.effect import args_digest
from .engine import Engine
from .catalog import catalog
from .ref import ref_decisions, all_sequences

ARGS = {"env": "prod", "region": "r1"}; ART = "sha256:" + "ab" * 32


def engine_decisions(seq, issuers=None):
    clk = [1000]; a = HorizonPolicy("pol-1", clock=lambda: clk[0]); ci = a.register_issuer("ci", {"TEST_STATUS", "SMOKE_TEST"}); ap = a.register_issuer("approver", {"APPROVAL"}, issuer_id="bob"); sg = a.register_issuer("signer", {"SIGNATURE"})
    eng = Engine(a, catalog("pol-1"), lambda: clk[0]); t = eng.new_task("t", "alice", ART); out = []; ad = args_digest(ARGS)
    for i, e in enumerate(seq):
        if e == "T": eng.evidence(t, ci.issue("TEST_STATUS", principal="alice", artifact=ART, object_version=1, ttl=100, claim={"result": "pass"}, now=clk[0]))
        elif e == "A": eng.evidence(t, ap.issue("APPROVAL", principal="alice", artifact=ART, args_digest=ad, object_version=1, ttl=100, now=clk[0]))
        elif e == "S": eng.evidence(t, sg.issue("SIGNATURE", principal="alice", artifact=ART, object_version=1, ttl=100, now=clk[0]))
        elif e == "K": clk[0] += 101
        elif e == "C": eng.cancel(t)
        elif e == "X": out.append(bool(eng.request(t, "deploy_prod", ARGS, op_id="x%d" % i)))
        clk[0] += 0
    return out


def differential(n):
    bad, total, allows = [], 0, 0
    for s in all_sequences(n):
        total += 1; r, g = ref_decisions(s), engine_decisions(s); allows += sum(r)
        if r != g: bad.append((s, r, g))
    return {"max_len": n, "sequences": total, "allow_decisions_in_reference": allows, "mismatches": len(bad), "examples": bad[:5]}
