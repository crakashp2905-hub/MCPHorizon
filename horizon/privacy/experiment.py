"""P45 experiments: system comparison, accountant comparison, differential test against the independent accountant, concurrency stress, cross-agent composition."""
import json, math, multiprocessing as mp, os, random, shutil, statistics, tempfile, time
from ..emergence.experiment import wilson
from ..hpolicy.authority import HorizonPolicy
from . import scenarios as SC, ledger as LG, units as U, mechanisms as MX, accountant as AC, reference as REF


def rate(k, n): return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci": wilson(k, n) if n else None}
def pct(xs, p): xs = sorted(xs); return round(xs[min(len(xs) - 1, int(p * len(xs)))], 3) if xs else None


def summarize(rows):
    out = {}
    for sy in SC.SYSTEMS:
        at = [r for r in rows if r["system"] == sy and r["kind"] == "attack"]; bn = [r for r in rows if r["system"] == sy and r["kind"] == "benign"]; lat = [r["lat_ms"] for r in rows if r["system"] == sy and r["lat_ms"]]
        maes = [r["mae"] for r in rows if r["system"] == sy and r.get("mae") is not None]
        out[sy] = {"attacks_over_budget": rate(sum(1 for r in at if r["over_budget"]), len(at)), "benign_completed": rate(sum(r["completed"] for r in bn), sum(r["total"] for r in bn)),
                   "benign_scenarios_fully_completed": rate(sum(1 for r in bn if r["completed"] == r["total"]), len(bn)), "mean_abs_error_count_queries": round(statistics.mean(maes), 3) if maes else None,
                   "median_query_ms": pct(lat, 0.5), "p95_query_ms": pct(lat, 0.95), "chain_ok_all": all(r["chain_ok"] for r in rows if r["system"] == sy),
                   "audit_mismatches": sum(len(r["audit"] or []) for r in rows if r["system"] == sy)}
    return out


def per_scenario(rows):
    out = {}
    for r in rows:
        d = out.setdefault(r["id"], {"kind": r["kind"], "systems": {}})
        d["systems"].setdefault(r["system"], []).append(("V" if r.get("over_budget") else "-") if r["kind"] == "attack" else "%d/%d" % (r["completed"], r["total"]))
    for d in out.values(): d["systems"] = {k: ",".join(v) for k, v in d["systems"].items()}
    return out


# ---- accountant comparison (P45-14) ---------------------------------------------------------------------------------------------------------------------------
def _answered_before_denial(acc, make_charge, budget, cap=5000):
    ch = []
    for _ in range(cap):
        c = make_charge()
        if not AC.fits(acc, budget, ch + [c])[0]: break
        ch.append(c)
    return len(ch)


def accountant_comparison():
    B = {"eps": SC.EPS_B, "delta": SC.DELTA_B}; out = {"budget": B, "laplace_queries_answered": {}, "gaussian_queries_answered": {}, "fixed_task": {}}
    for e in ("0.5", "0.25", "0.1", "0.05", "0.01"):
        out["laplace_queries_answered"][e] = {a: _answered_before_denial(a, lambda: MX.laplace_charge(e, 1), B) for a in AC.ACCOUNTANTS}
    for e, d in (("0.5", "1e-8"), ("0.1", "1e-8"), ("0.02", "1e-8")):
        out["gaussian_queries_answered"]["eps=%s,delta=%s" % (e, d)] = {a: _answered_before_denial(a, lambda: MX.gaussian_charge(e, d, 1), B) for a in AC.ACCOUNTANTS}
    for k in (5, 20, 100, 400):                       # a fixed task of k count queries: largest per-query eps that still fits, and the resulting expected error of a discrete-Laplace count (~ 1/eps)
        row = {}
        for a in AC.ACCOUNTANTS:
            lo, hi = 1e-6, 2.0
            for _ in range(60):
                mid = (lo + hi) / 2
                if AC.fits(a, B, [MX.laplace_charge(repr(mid), 1) for _ in range(k)])[0]: lo = mid
                else: hi = mid
            row[a] = {"eps_per_query": round(lo, 5), "expected_abs_error": round(1.0 / lo, 2)}
        out["fixed_task"][str(k)] = row
    # latency of one reserve+begin+commit through the ledger
    auth = HorizonPolicy("pol-1"); owner = auth.register_issuer("privacy-owner", {"ATTESTATION"}); lat = {}
    for a in AC.ACCOUNTANTS:
        led = LG.Ledger(":memory:", auth.verifier(), auth.clock); c = {"type": "privacy-budget", "dataset": "d", "eps": "1000", "delta": "1e-6", "accountant": a}; lid = U.ledger_id("d")
        led.open_budget(owner.issue("ATTESTATION", principal="o", artifact=lid, args_digest=LG.digest(c), object_version=1, ttl=10 ** 8, claim=c)); ts = []
        for i in range(300):
            t0 = time.perf_counter(); led.reserve(lid, "r%d" % i, "q", MX.laplace_charge("0.01", 1)); led.begin(lid, "r%d" % i); led.commit(lid, "r%d" % i, 1, "x"); ts.append((time.perf_counter() - t0) * 1000)
        lat[a] = {"p50_ms": pct(ts, 0.5), "p95_ms": pct(ts, 0.95), "note": "cost grows with ledger size: every reservation recomputes composition over all charges"}
        led.close()
    out["ledger_latency_300_requests"] = lat; return out


# ---- differential test vs the independent accountant (P45-12) ------------------------------------------------------------------------------------
def differential(n_seq=300, steps=60, seed=45):
    rng = random.Random(seed); auth = HorizonPolicy("pol-1"); owner = auth.register_issuer("privacy-owner", {"ATTESTATION"}); stats = {"decisions": 0, "ledger_allow_ref_allow": 0, "ledger_deny_ref_deny": 0, "ledger_deny_ref_allow_boundary": 0, "ledger_deny_ref_allow_other": 0, "ledger_allow_ref_deny": 0, "per_accountant": {}}
    for si in range(n_seq):
        acc = rng.choice(AC.ACCOUNTANTS); now = [1000.0]; led = LG.Ledger(":memory:", auth.verifier(), lambda: now[0]); eps = rng.choice(["0.5", "1", "2", "5"]); delta = rng.choice(["1e-6", "1e-9"]) if acc != "basic" else rng.choice(["0", "1e-6"]); lid = U.ledger_id("d%d" % si)
        c = {"type": "privacy-budget", "dataset": "d%d" % si, "eps": eps, "delta": delta, "accountant": acc}; led.open_budget(owner.issue("ATTESTATION", principal="o", artifact=lid, args_digest=LG.digest(c), object_version=1, ttl=10 ** 8, claim=c, now=1000))
        pa = stats["per_accountant"].setdefault(acc, {"allow": 0, "deny": 0, "boundary": 0, "mismatch": 0}); live = {}; budget = {"eps": eps, "delta": delta}; started = set()
        for st in range(steps):
            op = rng.choices(["reserve", "cancel", "begin", "tick"], [6, 2, 2, 1])[0]
            if op == "reserve":
                ch = MX.laplace_charge(rng.choice(["0.01", "0.05", "0.1", "0.25", "0.5"]), 1) if rng.random() < 0.7 else MX.gaussian_charge(rng.choice(["0.1", "0.5", "0.9"]), rng.choice(["1e-8", "1e-6"]), 1); rid = "r%d" % st
                ref_ev = [{"op": "charge", "id": k, **v} for k, v in live.items()] + [{"op": "charge", "id": rid, **ch}]
                try: ref_ok = REF.within(ref_ev, budget, acc)
                except Exception: continue
                r = led.reserve(lid, rid, "q%d" % st, ch, ttl=10.0); stats["decisions"] += 1
                if r["ok"]: live[rid] = ch; pa["allow"] += 1
                else: pa["deny"] += 1
                if r["ok"] and ref_ok: stats["ledger_allow_ref_allow"] += 1
                elif not r["ok"] and not ref_ok: stats["ledger_deny_ref_deny"] += 1
                elif r["ok"] and not ref_ok: stats["ledger_allow_ref_deny"] += 1; pa["mismatch"] += 1
                else:
                    cost = REF.costs(ref_ev, delta); key = {"basic": "basic", "advanced": "advanced", "zcdp": "zcdp"}[acc]; ce = cost[key]["eps"]; eb = REF.Decimal(eps)
                    if ce <= eb * REF.Decimal("1.0000001") + REF.Decimal("1e-12") and r.get("reason") == "BUDGET_EXCEEDED": stats["ledger_deny_ref_allow_boundary"] += 1; pa["boundary"] += 1
                    else: stats["ledger_deny_ref_allow_other"] += 1; pa["mismatch"] += 1
            elif op == "cancel" and live:
                rid = rng.choice(sorted(live)); res = led.cancel(lid, rid)
                if res.get("refunded"): live.pop(rid, None)
            elif op == "begin" and live:
                rid = rng.choice(sorted(live)); led.begin(lid, rid)
            else: now[0] += rng.choice([1.0, 5.0, 20.0]); led.begin(lid, "none")          # any ledger call sweeps expired, never-started reservations
            ev = led.charged_events(lid)                                                                          # also recompute from the hash-chained log with refunds/expiries
            states = led.states(lid); live = {k: v for k, v in live.items() if states.get(k) in ("RESERVED", "STARTED", "COMMITTED", "ABANDONED")}
            ref_live = {e["id"] for e in REF._live(ev)}; led_live = {k for k, v in states.items() if v in ("RESERVED", "STARTED", "COMMITTED", "ABANDONED")}
            if ref_live != led_live: stats["ledger_allow_ref_deny"] += 1; pa["mismatch"] += 1
        led.close()
    stats["agreement"] = stats["ledger_allow_ref_deny"] == 0 and stats["ledger_deny_ref_allow_other"] == 0; return stats


# ---- concurrency (P45-06) --------------------------------------------------------------------------------------------------------------------------------
def concurrency(procs=8, per=40, trials=3, budget_eps="3", q_eps="0.25"):
    import threading
    out = {"budget_eps": budget_eps, "q_eps": q_eps, "max_allowed": int(float(budget_eps) / float(q_eps)), "trials": []}
    for atomic in (True, False):
        for t in range(trials):
            tmp = tempfile.mkdtemp(prefix="p45c-"); auth = HorizonPolicy("pol-1"); owner = auth.register_issuer("privacy-owner", {"ATTESTATION"}); lid = U.ledger_id("d")
            led0 = LG.Ledger(os.path.join(tmp, "l.db"), auth.verifier(), auth.clock); c = {"type": "privacy-budget", "dataset": "d", "eps": budget_eps, "delta": "1e-6", "accountant": "basic"}
            led0.open_budget(owner.issue("ATTESTATION", principal="o", artifact=lid, args_digest=LG.digest(c), object_version=1, ttl=10 ** 8, claim=c)); ok = [0]; lk = threading.Lock()
            def work(w):
                led = LG.Ledger(os.path.join(tmp, "l.db"), auth.verifier(), auth.clock, atomic=atomic, gap=0.002 if not atomic else 0.0)
                for i in range(per):
                    r = led.reserve(lid, "w%d-%d" % (w, i), "q", MX.laplace_charge(q_eps, 1))
                    if r["ok"]:
                        with lk: ok[0] += 1
            th = [threading.Thread(target=work, args=(w,)) for w in range(procs)]; [x.start() for x in th]; [x.join() for x in th]
            out["trials"].append({"atomic": atomic, "granted": ok[0], "overcommit": max(0, ok[0] - out["max_allowed"]), "audit": led0.audit(lid), "chain_ok": led0.verify_chain()}); led0.close(); shutil.rmtree(tmp, ignore_errors=True)
    return out


# ---- cross-agent composition experiment (P45-16) -------------------------------------------------------------------------------------------------------
def composition(seed=45, agents=8, per_agent=4, eps="0.25", system="horizon-basic", trials=40):
    """Membership inference on one target by pooling answers from several agents. Reports answers released, composed cost (independent accountant) and attack accuracy (decision = mean of answers > 0.5), over seeded trials."""
    rows = []
    for t in range(trials):
        tmp = tempfile.mkdtemp(prefix="p45x-"); env = SC.Env(system, seed * 1000 + t, tmp)
        try:
            present = t % 2 == 0; env.sv.ds["hr"].rows = [r for r in env.sv.ds["hr"].rows if present or r["id"] != "target"]
            for a in range(agents):
                ag = env.agent()
                for _ in range(per_agent): env.q(ag, SC.TARGET_WHERE, eps=eps)
            obs = [x for q, x in SC.dp_observations(env, "hr")]; o = SC.oracle_dp(env)
            guess = (sum(obs) / len(obs) > 0.5) if obs else False
            rows.append({"present": present, "n": len(obs), "cost": o["cost_eps"], "over": o["over_budget"], "correct": guess == present})
        finally: env.close(); shutil.rmtree(tmp, ignore_errors=True)
    return {"seed": seed, "agents": agents, "per_agent": per_agent, "eps": eps, "system": system, "trials": trials, "mean_answers_released": round(statistics.mean(r["n"] for r in rows), 2), "max_cost": max(r["cost"] for r in rows),
            "runs_over_budget": sum(r["over"] for r in rows), "attack_accuracy": rate(sum(r["correct"] for r in rows), len(rows))}


def run(reps=SC.REPS):
    rows = SC.run_all(reps=reps)
    comp = {s: composition(system=s) for s in ("per-agent-limit", "per-principal-accountant", "horizon-basic")}
    return {"reps": reps, "systems": list(SC.SYSTEMS), "scenarios": [{"id": s[0], "kind": s[1], "note": s[3]} for s in SC.SCENARIOS], "runs": len(rows), "summary": summarize(rows), "per_scenario": per_scenario(rows), "raw": [{k: v for k, v in r.items() if k not in ("audit",)} for r in rows],
            "accountants": accountant_comparison(), "differential": differential(), "concurrency": concurrency(), "composition": comp, "limits": LIMITS}


LIMITS = ["synthetic datasets, one author's service, policy and oracle; the noise PRF is HMAC-SHA256 and the Gaussian sampler is a double-precision Box-Muller that is not claimed to be exactly DP",
          "DP guarantees hold only for released answers of the supported mechanisms under add/remove-one-individual adjacency with the declared per-individual cap; they say nothing about raw aggregates, exports, row counts, timing, error messages or model outputs",
          "the raw-query differencing guard is a heuristic over sets of answered cells (symmetric difference smaller than the minimum cell); linear combinations of three or more queries are not detected",
          "ledger tamper-evidence: the hash chain and the owner-signed budget detect edits made without the owner key, not a database administrator who rewrites the whole file; the service and its secret are trusted",
          "accounting is per dataset; a person whose data appears in several datasets is not accounted across them",
          "the LLR column is supporting evidence from single noisy realizations, not a statistic; the over-budget decision is the accountant's composed cost",
          "concurrency was exercised with threads on one machine using one SQLite file; multi-host databases are untested",
          "MCP/UTCP/Code Mode are represented by carrier-level codecs, not wired into the real adapters"]
