"""Spectra -> Forge -> Zero pipeline (CANDIDATE, research, fixtures only; no real agents or network).
An effect that Spectra OBSERVES on an instrumented sink but the integration did not declare becomes a Forge Task; Forge's independent checker must accept the chosen plan (or the pipeline re-verifies a
negative certificate); only then is a new, scoped Zero claim issued, bound by digest to the observed graph, the plan, and every control/witness the plan needs. The old claim is suspended the moment the observed
graph differs from the one it was issued against, so permits are refused until a checked replacement exists. Fails closed: unknown label -> SECRET, unknown sink -> remote, missing control -> no claim.
What it does NOT do: install any control, observe uninstrumented sinks, or claim anything about probes not run. The claim scope states the probes and sinks actually covered."""
from __future__ import annotations
import hashlib, json
from horizon.forge.ir import Task, Plan
from horizon.forge import synth, checker
from horizon.assurance.registry import AssuranceClaim, Registry
from . import tomography as T

LOCAL_SINKS = frozenset({"fs"})        # sinks inside the local trust boundary; everything else (incl. unknown names) counts as leaving it


def _dg(x) -> str: return hashlib.sha256(json.dumps(x, sort_keys=True, default=list).encode()).hexdigest()


def graph_digest(declared: dict) -> str: return _dg({p: sorted(s) for p, s in sorted(declared.items())})


def effect_task(probe, sink, env) -> Task:
    """Owner-declared facts come from env; absent facts fail closed (label SECRET, no aggregate, opaque remote)."""
    return Task(env.get("labels", {}).get(probe, "SECRET"), bool(env.get("aggregate_ok", {}).get(probe, False)), env.get("remote_trust", {}).get(sink, "opaque"),
                tuple(sorted(env.get("controls", ()))), tuple(sorted(env.get("witnesses", ()))), need_effect_witness=True)


def plan_for(probe, sink, env) -> dict:
    """Returns {task, plan|None, result, rechecked}. Local sinks need the installed local_sandbox; remote sinks go through Forge synthesis. Every verdict is re-checked by the independent checker."""
    t = effect_task(probe, sink, env)
    if sink in LOCAL_SINKS:
        p = Plan("local_sandbox", "raw", ("local_sandbox",), ()); ok = checker.check(t, p)
        return {"task": t, "plan": p if ok else None, "result": "CERTIFIED_LOCAL" if ok else "NOT_CERTIFIABLE_WITHIN_MODEL", "rechecked": True, "violations": checker.violations(t, p)}
    # The effect ALREADY happens on a remote sink, so only plans that keep that placement can describe it. A plan that needs relocation is a recommendation for the owner, not an enforceable claim.
    feas = [q for q in synth.enumerate_plans(t) if q.placement != "local_sandbox" and checker.check(t, q)]
    if feas:
        best = min(feas, key=lambda q: (q.cost(), synth.utility_loss(t, q), repr(q))); return {"task": t, "plan": best, "result": "CERTIFIED_IN_PLACE", "rechecked": checker.check(t, best), "utility_loss": synth.utility_loss(t, best)}
    r = synth.synthesize(t)
    if r["result"] == "NOT_CERTIFIABLE_WITHIN_MODEL": return {"task": t, "plan": None, "result": r["result"], "rechecked": synth.verify_negative_certificate(t, r), "bounds": r["bounds"]}
    return {"task": t, "plan": None, "result": "REQUIRES_RELOCATION", "rechecked": checker.check(t, r["plan"]), "suggested": repr(r["plan"])}


def issue(reg: Registry, claim_id, scope, epoch, expires_at, deps: dict):
    reg.add(AssuranceClaim(claim_id, tuple(scope), epoch, expires_at, tuple(sorted(deps)), tuple(sorted(deps.items()))))


def _install(reg, env):
    for c, d in env.get("installed", {}).items(): reg.set_node(f"control:{c}", d)
    for w, d in env.get("installed_witnesses", {}).items(): reg.set_node(f"witness:{w}", d)


def run(system, probes, hyps, declared, instrumented, reg: Registry, claim_id: str, env: dict, *, budget=50, max_rounds=6, seed=0, expires_at=10**9):
    """Initial claim `claim_id` must already be issued against node 'graph:<claim_id>' = graph_digest(declared). Returns a report; mutates reg."""
    declared = {p: tuple(sorted(declared.get(p, ()))) for p in probes}; node = f"graph:{claim_id}"; _install(reg, env)
    epoch = reg.claims[claim_id].epoch; cur = claim_id; rounds = []; verdict = None
    for _ in range(max_rounds):
        v, d = T.infer(system, probes, hyps, declared, instrumented, budget=budget, strategy="active", seed=seed); verdict = v
        if v != "DISCOVERED": rounds.append({"verdict": v, "detail": d}); break
        probe = d["probe"]; plans = {s: plan_for(probe, s, env) for s in d["undeclared_sinks"]}
        declared[probe] = tuple(sorted(set(declared[probe]) | set(d["undeclared_sinks"])))
        reg.set_node(node, graph_digest(declared))                 # old claim is now SUSPENDED: its digest no longer matches the observed graph
        good = all(x["plan"] is not None and x["rechecked"] for x in plans.values()); rec = {"verdict": v, "probe": probe, "sinks": d["undeclared_sinks"], "plans": {s: repr(x["plan"]) for s, x in plans.items()}, "results": {s: x["result"] for s, x in plans.items()}}
        if good:
            deps = {node: graph_digest(declared)}
            for s, x in plans.items():
                deps[f"plan:{probe}:{s}"] = _dg(repr(x["plan"]))
                for c in x["plan"].controls: deps[f"control:{c}"] = env.get("installed", {}).get(c, "NOT_INSTALLED")
                for w in x["plan"].witnesses: deps[f"witness:{w}"] = env.get("installed_witnesses", {}).get(w, "NOT_INSTALLED")
            epoch += 1; nid = f"{claim_id}.r{epoch}"
            for k, dg in deps.items():
                if k.startswith("plan:"): reg.set_node(k, dg)
            # a plan whose control is not installed cannot be enforced: refuse to issue
            if any(dg == "NOT_INSTALLED" for dg in deps.values()): rec["claim"] = None; rec["why"] = "plan needs a control/witness that is not installed"
            else:
                issue(reg, nid, (("probes", tuple(sorted(declared))), ("sinks", tuple(sorted(instrumented))), ("covers", "effects observed so far only")), epoch, expires_at, deps); rec["claim"] = nid; cur = nid
        else:
            rec["claim"] = None; res = {x["result"] for x in plans.values()}
            rec["why"] = ("a plan exists only after relocating the computation: owner action needed, nothing enforceable yet" if "REQUIRES_RELOCATION" in res else
                          "no plan within the model (negative certificate re-verified)" if res <= {"NOT_CERTIFIABLE_WITHIN_MODEL"} and all(x["rechecked"] for x in plans.values()) else "verification failed")
        rounds.append(rec)
    if verdict in ("UNIDENTIFIABLE", "UNKNOWN"): reg.invalidate(cur, f"spectra:{verdict}")      # coverage not established -> fail closed
    st = reg.status(cur, epoch)
    return {"final_verdict": verdict, "rounds": rounds, "current_claim": cur, "status": st, "permit_allowed": reg.may_issue_permit(cur, epoch), "epoch": epoch,
            "original_claim_status": reg.status(claim_id, epoch), "limits": "instrumented sinks only; effects not exercised by a probe are not covered; controls are assumed installed as declared in env"}
