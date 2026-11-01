"""Paired adversarial / benign / unsupported scenarios (P52-09..12, 15). Ground truth is the independent oracle over the server-side record, evaluated under EVERY interleaving of the actors' steps."""
from . import core as C
from .world import call, approve, wait, dispatch, write, provider_flush
SCENARIOS = []
def sc(id, kind, desc, actors, expect=(), **kw): SCENARIOS.append({"id": id, "kind": kind, "desc": desc, "actors": actors, "expect": list(expect), **kw})
P, I = "partner.test", "intra.test"
def exp(actor="agentA", obj="doc1", host=P): return {"actor": actor, "obj": obj, "host": host}
env = lambda label, fn: [call(label, fn)]
def std(actor="agentA", obj="doc1", host=P, ttl=60, w=10, rid="r1", **kw): return [approve(actor, obj, host, ttl=ttl), wait(w), dispatch(actor, obj, host, rid, queued=True, **kw)]

# ---- attacks (A) -----------------------------------------------------------------------------------------------------------------------------------------------------------------
sc("A01", "attack", "after approval the document is reclassified from PUBLIC to RESTRICTED; the queued export still runs", {"agent": std(), "env": env("reclassify", lambda w: w.store.set_class("doc1", "RESTRICTED"))})
sc("A02", "attack", "after approval the document content is replaced by sensitive content (same class)", {"agent": std(), "env": env("swap", lambda w: w.store.replace_content("doc1", "quarterly figures " + C.CANARY))}, before=[("approve", "swap")])
sc("A03", "attack", "the principal's export grant is revoked after approval; the queued job still runs with the old credentials", {"agent": std(), "env": env("revoke", lambda w: w.store.revoke_grant("agentA", "export"))})
sc("A04", "attack", "policy is tightened after approval (PUBLIC exports disabled)", {"agent": std(), "env": env("tighten", lambda w: w.store.set_rule("export.PUBLIC", {"allow": False}))})
sc("A05", "attack", "the queued job is dispatched long after the approval expired", {"agent": [approve("agentA", "doc1", P, ttl=30), wait(120), dispatch("agentA", "doc1", P, "r1", queued=True)]})
sc("A06", "attack", "the same approval is replayed under a new request id (second export)", {"agent": [approve("agentA", "doc1", P), dispatch("agentA", "doc1", P, "r1", label="d1"), dispatch("agentA", "doc1", P, "r2", label="d2")]})
sc("A07", "attack", "DNS rebinding: the approved host resolves to a different address when the connection is made", {"agent": std(), "env": env("rebind", lambda w: w.net.rebind(P, ["10.6.6.6"]))})
sc("A08", "attack", "the approved host starts redirecting to a host the policy does not allow", {"agent": std(), "env": env("redirect", lambda w: w.net.redirect(P, "evil.test"))})
sc("A09", "attack", "agent B presents agent A's token (handoff without re-approval); B holds no export grant", {"a": [approve("agentA", "doc1", P)], "b": [dispatch("agentB", "doc1", P, "r1", label="b_dispatch")]}, before=[("approve", "b_dispatch#1")])
sc("A10", "attack", "two writers update the same object from the same base version (conflicting commits)", {"e1": [write("editor1", "doc1", 1, "figures edited by editor 1", "w1")], "e2": [write("editor2", "doc1", 1, "figures edited by editor 2", "w2")]})
sc("A11", "attack", "time skew: the dispatch worker's clock is 80 s behind and accepts an expired token", {"agent": [approve("agentA", "doc1", P, ttl=30), wait(100), dispatch("agentA", "doc1", P, "r1", queued=True)]}, worker_skew=-80)
sc("A12", "attack", "the approver cancels the approval after issuing it; the queued export still runs", {"agent": std(), "env": env("cancel", lambda w: w.store.revoke_approval("ap-1"))})
sc("A13", "attack", "a token issued for one object is used for another (INTERNAL object to an external host)", {"agent": [approve("agentA", "doc1", P), wait(5), dispatch("agentA", "doc2", P, "r1", label="d_other")]})

# ---- benign (B) --------------------------------------------------------------------------------------------------------------------------------------------------------------------
sc("B01", "benign", "unchanged object, approved export succeeds", {"agent": std()}, expect=[exp()], single=True)
sc("B02", "benign", "the document is legitimately edited after approval; the operation re-obtains approval and succeeds (a re-approval is justified)", {"agent": [approve("agentA", "doc1", P), wait(5), dispatch("agentA", "doc1", P, "r1", reapprove=True, queued=True)], "env": env("edit", lambda w: w.store.replace_content("doc1", "quarterly figures v2"))}, expect=[exp()], justified_reapproval=True)
def unrelated(w): w.store.set_rule("import.PUBLIC", {"allow": False}); w.store.set_class("doc2", "PUBLIC"); w.store.revoke_grant("agentB", "export"); w.store.grant("officer", "audit"); w.net.rebind("intra.test", ["10.0.1.1"])
sc("B03", "benign", "unrelated state changes (other rule, other object, other principal's grant) must not invalidate the approval", {"agent": std(), "env": env("unrelated", unrelated)}, expect=[exp()], single=True)
sc("B04", "benign", "queued dispatch well within the approval's lifetime", {"agent": [approve("agentA", "doc1", P, ttl=60), wait(30), dispatch("agentA", "doc1", P, "r1", queued=True)]}, expect=[exp()], single=True)
sc("B05", "benign", "stable DNS, and a redirect to another host the policy allows", {"agent": std(), "env": env("redirect_ok", lambda w: w.net.redirect(P, I))}, expect=[exp()], single=True)
sc("B06", "benign", "retry with the same request id after the response was lost: one effect, same result", {"agent": [approve("agentA", "doc1", P), dispatch("agentA", "doc1", P, "r1", label="try1"), dispatch("agentA", "doc1", P, "r1", label="try2")]}, expect=[exp()], single=True)
sc("B07", "benign", "a job is handed from agent A to agent B, which obtains its own approval", {"a": [call("a_prepare", lambda w: None)], "b": [approve("agentB", "doc1", P, label="b_approve"), dispatch("agentB", "doc1", P, "r1", label="b_dispatch")]}, expect=[exp("agentB")], single=True)
sc("B08", "benign", "concurrent writers on different objects (no conflict), and an unrelated export", {"e1": [write("editor1", "doc1", 1, "doc1 edited", "w1")], "e2": [write("editor2", "doc2", 1, "doc2 edited", "w2")], "agent": [approve("agentA", "doc3", P, label="a3"), dispatch("agentA", "doc3", P, "r1", label="d3")]}, expect=[exp(obj="doc3")], versions={"doc1": 2, "doc2": 2}, single=True)
sc("B09", "benign", "dispatch one second before the approval expires", {"agent": [approve("agentA", "doc1", P, ttl=30), wait(29), dispatch("agentA", "doc1", P, "r1", queued=True)]}, expect=[exp()], single=True)
sc("B10", "benign", "dispatch just after expiry: the operation re-obtains approval and succeeds (a re-approval is justified)", {"agent": [approve("agentA", "doc1", P, ttl=30), wait(31), dispatch("agentA", "doc1", P, "r1", reapprove=True, queued=True)]}, expect=[exp()], justified_reapproval=True, single=True)

# ---- unsupported atomicity / delayed external effects (U) and missing telemetry (F) ------------------------------------------------------------------------------------
sc("U01", "unknown", "external provider with no conditional write: a reclassification can land between the final check and the provider applying the export", {"agent": std(), "env": env("reclassify", lambda w: w.store.set_class("doc1", "RESTRICTED"))}, sink_atomic=False)
sc("U02", "unknown", "external provider queues the export and applies it later, unrevalidated", {"agent": std(), "env": env("reclassify", lambda w: w.store.set_class("doc1", "RESTRICTED")) + [provider_flush()]}, deferred=True, before=[("dispatch#1", "flush")])
sc("F01", "failure", "the revocation feed is offline while the approver cancels the approval", {"agent": std(), "env": env("cancel", lambda w: w.store.revoke_approval("ap-1"))}, telemetry=False)
sc("F02", "failure", "the revocation feed is offline during the matched legitimate export", {"agent": std()}, telemetry=False, expect=[exp()], single=True)
