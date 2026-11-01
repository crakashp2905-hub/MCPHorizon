"""Scenarios, systems and the independent oracle (P45-09..13). Oracle: the harness records every response an adversary could observe (including answers that escape through a 'timeout' side channel) at the transport boundary; the reference accountant (separate Decimal implementation, no imports from the ledger) recomposes the privacy cost from those observations plus the DECLARED sensitivities, and compares it with the budget. Nothing is read from the ledger tables."""
import os, tempfile, threading, time
from ..hpolicy.authority import HorizonPolicy
from . import ledger as LG, service as SV, baselines as BL, units as U, reference as REF, carriers as CA

EPS_B, DELTA_B, Q_EPS = "2", "1e-6", "0.25"
SYSTEMS = ("per-agent-limit", "per-principal-accountant", "dlp", "token-limit", "non-transactional", "horizon-basic", "horizon-advanced", "horizon-zcdp",
           "horizon-no-transaction", "horizon-no-idempotency", "horizon-no-abandon", "horizon-no-ledger-derivation", "horizon-no-declared-bounds", "horizon-no-diff-guard", "horizon-no-min-cell")
REPS = 3
TARGET_WHERE = [["id", "==", "target"]]


class Env:
    def __init__(self, system, rep, tmp):
        self.system, self.rep = system, rep; self.auth = HorizonPolicy("pol-1"); self.owner = self.auth.register_issuer("privacy-owner", {"ATTESTATION"}); self.approver = self.auth.register_issuer("data-approver", {"APPROVAL"})
        acc = {"horizon-advanced": "advanced", "horizon-zcdp": "zcdp"}.get(system, "basic"); self.acc = acc
        flags = {"horizon-no-transaction": dict(atomic=False, gap=0.003), "horizon-no-abandon": dict(refund_after_start=True)}.get(system, {})
        self.led = LG.Ledger(os.path.join(tmp, "ledger.db"), self.auth.verifier(), self.auth.clock, **flags)
        self.datasets = [SV.Dataset("hr", seed=rep + 1), SV.Dataset("pub", public=True, seed=rep + 7)] + [SV.Dataset("res%d" % i, seed=rep + 20 + i) for i in range(4)]
        base = system.startswith("horizon-")
        sflags = {"horizon-no-idempotency": dict(idempotent=False), "horizon-no-ledger-derivation": dict(derive_ledger=False), "horizon-no-declared-bounds": dict(declared_bounds=False), "horizon-no-diff-guard": dict(diff_guard=False), "horizon-no-min-cell": dict(min_cell_on=False)}.get(system, {})
        if not base: sflags = dict(diff_guard=False, min_cell_on=False)          # baselines have access control and purpose checks only
        self.sv = SV.Service(self.datasets, self.led, self.auth.verifier(), secret=("secret-%d" % rep).encode(), **sflags)
        for d in self.datasets:
            if not d.public: self.budget(self.led, d.name)
        self.agents = []; self.observed = []; self.lock = threading.Lock(); self.rid = 0
        self.sys = self._wrap(system)
    def budget(self, led, dataset, eps=EPS_B, delta=DELTA_B, acc=None, version=1):
        c = {"type": "privacy-budget", "dataset": dataset, "eps": eps, "delta": delta, "accountant": acc or self.acc}
        led.open_budget(self.owner.issue("ATTESTATION", principal="owner", artifact=U.ledger_id(dataset), args_digest=LG.digest(c), object_version=version, ttl=10 ** 8, claim=c))
    def _wrap(self, s):
        if s == "per-agent-limit": return BL.PerAgentLimit(self.sv, 6)
        if s == "per-principal-accountant":
            def mk(led, ds, pr): self.budget(led, ds, acc="basic")
            return BL.PerPrincipalAccountant(self.sv, mk)
        if s == "dlp": return BL.DLP(self.sv)
        if s == "token-limit": return BL.TokenLimit(self.sv, 120)
        if s == "non-transactional": return BL.NonTransactional(self.sv, {"eps": EPS_B, "delta": DELTA_B})
        return BL.Wrapped(self.sv)
    def agent(self, name=None, raw=False):
        name = name or "ag%d" % len(self.agents); self.agents.append(name)
        self.sv.add_principal(name, "t1", dp=[d.name for d in self.datasets if not d.public], raw=["hr"] if raw else [], purposes=["audit"] if raw else []); return name
    def newid(self): 
        with self.lock: self.rid += 1; return "r%d-%d-%s" % (self.rep, self.rid, self.system[:6])
    def q(self, principal, where, agg="count", eps=Q_EPS, rid=None, dataset="hr", ctx=None, **kw):
        qq = {"dataset": dataset, "agg": agg, "where": where, "eps": eps, "request_id": rid or self.newid(), **kw}
        t0 = time.perf_counter(); r = self.sys.query(principal, qq, ctx); ms = (time.perf_counter() - t0) * 1000
        with self.lock: self.observed.append({"q": qq, "r": r, "ms": ms, "principal": principal})
        return r
    def close(self): self.led.close()


# ---- oracle ----------------------------------------------------------------------------------------------------------------------------------------------------------
def dp_observations(env, dataset):
    """-> list of (client request id, eps, observed answer) for every distinct DP answer an adversary saw (OK answers, plus answers that leaked through TIMEOUT)."""
    seen, out = {}, []
    for o in env.observed:
        q, r = o["q"], o["r"]
        if q["dataset"] != dataset or q.get("mode", "dp") != "dp": continue
        a = r.get("answer") if r.get("status") == "OK" else r.get("leaked_answer") if r.get("status") == "TIMEOUT" else None
        if a is None: continue
        seen.setdefault((q["request_id"], a), (q, a))
    return list(seen.values())


def oracle_dp(env, dataset="hr"):
    """Composed privacy cost of everything the adversary observed, recomputed independently with DECLARED sensitivities. A request id answered with two different values counts twice (fresh noise)."""
    d = env.sv.ds[dataset]; obs = dp_observations(env, dataset); ev = []
    for i, (q, a) in enumerate(obs):
        true_s = 1 if q["agg"] == "count" else max(abs(x) for x in d.bounds[q["column"]])
        used = _used_sens(env, q, d)                                                                       # sensitivity the noise was actually calibrated to (from the released-mechanism log)
        eps_eff = float(q["eps"]) * true_s / used if used else float("inf")
        ev.append({"op": "charge", "id": str(i), "mech": "laplace", "eps": repr(eps_eff) if eps_eff != float("inf") else "1e12", "delta": "0", "sens": true_s, "sigma": None})
    over = not REF.within(ev, {"eps": EPS_B, "delta": DELTA_B}, "basic") if ev else False
    cost = REF.costs(ev, DELTA_B)["basic"]["eps"] if ev else 0
    resampled = len({a for (q, a) in obs if q["request_id"] == obs[0][0]["request_id"]}) > 1 if obs else False
    by = {}
    for q, a in obs: by.setdefault(q["request_id"], set()).add(a)
    return {"n_observed": len(obs), "cost_eps": float(cost), "over_budget": over, "resampled_request": any(len(v) > 1 for v in by.values())}


def _used_sens(env, q, d):
    for e in env.sv.release_log:
        if e.get("kind") == "dp" and e["request_id"].split("#")[0] == q["request_id"] and e["dataset"] == q["dataset"]: return e["sens"]
    return 1 if q["agg"] == "count" else max(abs(x) for x in d.bounds[q["column"]])          # leaked-but-uncommitted answers use the declared sensitivity of the honest path


def llr_target(env):
    """Log-likelihood ratio, computed from observed answers on count(id==target), for 'target present' (count=1) vs 'absent' (count=0). Under eps_B-DP it cannot exceed eps_B in magnitude."""
    llr = 0.0
    for q, a in dp_observations(env, "hr"):
        if q["where"] == TARGET_WHERE and q["agg"] == "count": llr += float(q["eps"]) * (abs(a) - abs(a - 1))
    return llr


def mae(env):
    errs = []
    for o in env.observed:
        q, r = o["q"], o["r"]; d = env.sv.ds.get(q["dataset"])
        if r.get("status") != "OK" or q.get("mode", "dp") != "dp" or d is None or d.public or q["agg"] != "count": continue
        errs.append(abs(r["answer"] - len(d.match(q["where"]))))
    return round(sum(errs) / len(errs), 3) if errs else None


def finish(env, out):
    o = oracle_dp(env); out.update(over_budget=o["over_budget"], cost_eps=o["cost_eps"], n_observed=o["n_observed"], resampled=o["resampled_request"], llr=round(llr_target(env), 3)); return out


# ---- scenarios -------------------------------------------------------------------------------------------------------------------------------------------------------
def a01_split_agents(env):
    ags = [env.agent() for _ in range(8)]
    for a in ags:
        for _ in range(4): env.q(a, TARGET_WHERE)
    return finish(env, {})
def a02_identity_splitting(env):
    for i in range(32): env.q(env.agent("id-%d" % i), TARGET_WHERE)
    return finish(env, {})
def a03_concurrent_race(env):
    ags = [env.agent() for _ in range(32)]; th = [threading.Thread(target=env.q, args=(a, TARGET_WHERE)) for a in ags]
    [t.start() for t in th]; [t.join() for t in th]; return finish(env, {})
def a04_delegation_ledger_forgery(env):
    root = env.agent("root"); ctx = CA.make("hr", "task-1")
    for i in range(32):
        sub = env.agent("sub%d" % i); c = CA.delegate(ctx, sub); c["ledger"] = U.ledger_id("res%d" % (i % 4))          # sub-agent claims some other dataset's ledger
        env.q(sub, TARGET_WHERE, ctx=c)
    return finish(env, {})
def a05_replay_same_id(env):
    a = env.agent(); answers = {r.get("answer") for r in (env.q(a, TARGET_WHERE, rid="fixed-1") for _ in range(30)) if r.get("answer") is not None}
    return finish(env, {"distinct_answers_one_id": len(answers)})
def a05b_retry_storm_new_ids(env):
    a = env.agent()
    for i in range(32): env.q(a, TARGET_WHERE, rid="try-%d" % i)
    return finish(env, {})
def a06_cancel_after_mechanism(env):
    a = env.agent()
    for i in range(32):
        rid = "cx-%d" % i; r = env.q(a, TARGET_WHERE, rid=rid, _fail_after_mechanism=True)
        if r.get("status") == "OK": continue
        env.led.cancel(U.ledger_id("hr"), rid + ("" if env.system != "horizon-no-idempotency" else ""))                   # the client treats the timeout as a failure and cancels to get its budget back
    return finish(env, {})
def a07_raw_differencing(env):
    a = env.agent(raw=True); r1 = env.q(a, [["dept", "==", "legal"]], agg="sum", column="salary", mode="raw", purpose="audit"); r2 = env.q(a, [["dept", "==", "legal"], ["salary", "<", 199999]], agg="sum", column="salary", mode="raw", purpose="audit")
    got = r1.get("answer") is not None and r2.get("answer") is not None and r1["answer"] - r2["answer"] == 199999
    return {"over_budget": got, "cost_eps": 0, "n_observed": 2, "resampled": False, "llr": 0, "target_salary_recovered": got}
def a08_caller_bounds(env):
    a = env.agent(); r1 = env.q(a, [["dept", "==", "legal"]], agg="sum", column="salary", bounds=[0, 1]); r2 = env.q(a, [["dept", "==", "legal"], ["salary", "<", 199999]], agg="sum", column="salary", bounds=[0, 1])
    return finish(env, {"salary_error": abs((r1.get("answer", 0) - r2.get("answer", 0)) - 199999) if r1.get("answer") is not None and r2.get("answer") is not None else None})
def a09_ledger_forgery_single(env):
    a = env.agent()
    for i in range(32): env.q(a, TARGET_WHERE, ctx={"ledger": U.ledger_id("res%d" % (i % 4)), "task": "t", "chain": []})
    return finish(env, {})

def a10_raw_small_cell(env):
    a = env.agent(raw=True); r = env.q(a, TARGET_WHERE, agg="sum", column="salary", mode="raw", purpose="audit"); got = r.get("answer") == 199999
    return {"over_budget": got, "cost_eps": 0, "n_observed": 1, "resampled": False, "llr": 0, "target_salary_recovered": got}

def b01_public(env):
    a = env.agent(); ok = sum(env.q(a, [["dept", "==", "eng"]], dataset="pub").get("status") == "OK" for _ in range(60)); return {"completed": ok, "total": 60, "fidelity_err": 0.0}
def b02_dp_within_budget(env):
    ags = [env.agent() for _ in range(4)]; res = [env.q(a, [["dept", "==", "legal"]]) for a in ags for _ in range(2)]; return _bn(env, res, 8)
def b03_export_with_approval(env):
    a = env.agent(raw=True); c = {"purpose": "audit"}; tok = env.approver.issue("APPROVAL", principal=a, artifact="hr", args_digest=LG.digest({"op": "export", "dataset": "hr", "purpose": "audit"}), ttl=600, claim=c)
    r = env.sv.export_rows(a, "hr", "audit", tok); return {"completed": int(r.get("status") == "OK"), "total": 1, "fidelity_err": 0.0, "not_dp": r.get("dp") is False}
def b04_benign_retries(env):
    a = env.agent(); rs = [env.q(a, [["dept", "==", "ops"]], rid="net-retry-1") for _ in range(5)]; later = [env.q(a, [["dept", "==", "eng"]]) for _ in range(4)]
    return _bn(env, rs + later, 9)
def b05_separate_datasets(env):
    a = env.agent(); res = [env.q(a, [["dept", "==", "eng"]], dataset=ds) for ds in ("hr", "res0") for _ in range(8)]; return _bn(env, res, 16)
def b06_raw_aggregate(env):
    a = env.agent(raw=True); res = [env.q(a, [["dept", "==", "eng"]], mode="raw", purpose="audit"), env.q(a, [["dept", "==", "ops"]], mode="raw", purpose="audit")]; return _bn(env, res, 2)
def b07_matched_structure_public(env):
    a = env.agent(); res = [env.q(a, TARGET_WHERE, dataset="pub") for _ in range(32)]; return {"completed": sum(r.get("status") == "OK" for r in res), "total": 32, "fidelity_err": 0.0}
def _bn(env, res, total):
    ok = [r for r in res if r.get("status") == "OK"]; return {"completed": len(ok), "total": total, "fidelity_err": 0.0}


SCENARIOS = [("A01", "attack", a01_split_agents, "8 agents x 4 queries on one target count; each agent is under any per-agent limit"), ("A02", "attack", a02_identity_splitting, "one attacker, 32 fresh identities"),
             ("A03", "attack", a03_concurrent_race, "32 simultaneous requests race the budget check"), ("A04", "attack", a04_delegation_ledger_forgery, "delegated sub-agents name other datasets' ledgers"),
             ("A05", "attack", a05_replay_same_id, "same request id replayed 30 times (extra noise samples?)"), ("A05b", "attack", a05b_retry_storm_new_ids, "retry storm with fresh request ids"),
             ("A06", "attack", a06_cancel_after_mechanism, "answer escapes via timeout, client cancels to recover budget"), ("A07", "attack", a07_raw_differencing, "two authorized raw aggregates whose difference is one person"),
             ("A08", "attack", a08_caller_bounds, "caller-supplied tiny bounds shrink the noise"), ("A09", "attack", a09_ledger_forgery_single, "one agent names other datasets' ledgers"), ("A10", "attack", a10_raw_small_cell, "authorized raw aggregate whose cell is a single person"),
             ("B01", "benign", b01_public, "60 queries over public data"), ("B02", "benign", b02_dp_within_budget, "DP queries within the shared budget"), ("B03", "benign", b03_export_with_approval, "raw export with bound approval (not DP)"),
             ("B04", "benign", b04_benign_retries, "network retries of one request id, then normal queries"), ("B05", "benign", b05_separate_datasets, "two datasets, each within its own budget"),
             ("B06", "benign", b06_raw_aggregate, "authorized raw aggregates with large cells"), ("B07", "benign", b07_matched_structure_public, "attack-shaped queries over a public dataset")]


def run_one(sid, system, rep):
    sc = {s[0]: s for s in SCENARIOS}[sid]; tmp = tempfile.mkdtemp(prefix="p45-"); env = Env(system, rep, tmp)
    try:
        t0 = time.perf_counter(); out = sc[2](env); out.update(id=sid, kind=sc[1], system=system, rep=rep, ms=round((time.perf_counter() - t0) * 1000, 1), lat_ms=sorted(o["ms"] for o in env.observed)[len(env.observed) // 2] if env.observed else 0.0)
        out["answered"] = sum(1 for o in env.observed if o["r"].get("status") == "OK"); out["mae"] = mae(env); out["denied"] = sum(1 for o in env.observed if o["r"].get("status") == "DENY"); out["chain_ok"] = env.led.verify_chain(); out["audit"] = env.led.audit(U.ledger_id("hr")) if system.startswith("horizon-") else None; return out
    finally: env.close(); import shutil; shutil.rmtree(tmp, ignore_errors=True)


def run_all(systems=SYSTEMS, reps=REPS):
    return [run_one(s[0], sy, r) for s in SCENARIOS for sy in systems for r in range(reps)]
