"""P13-14: signing / verification / nonce / gateway overhead, p50/p95/p99. Writes results/v2/p13-overhead/{result.json,manifest.json} (write-once: refuses to overwrite)."""
import json, os, platform, subprocess, sys, tempfile, time
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from horizon.authz import effect as E, keys as K, authority as AU, gateway as G
from horizon.service.core import Service
from bench.secbench.world import POLICY

N = 2000; URL = "https://api.example.com/v1/notes"


def pct(xs, q): xs = sorted(xs); return xs[min(len(xs) - 1, int(q * len(xs)))]
def stats(xs): return {"n": len(xs), "p50_us": round(pct(xs, .5) * 1e6, 1), "p95_us": round(pct(xs, .95) * 1e6, 1), "p99_us": round(pct(xs, .99) * 1e6, 1), "max_us": round(max(xs) * 1e6, 1)}


def main():
    out = REPO / "results/v2/p13-overhead"
    if out.exists(): raise SystemExit("results/v2/p13-overhead exists: write-once; create a new experiment directory for a re-run")
    d = tempfile.mkdtemp(); signer = K.Signer.generate("k1", "a"); trust = K.TrustStore(); trust.add("k1", "a", signer.public_raw(), not_before=0, not_after=2 ** 40)
    svc = Service({"ta": {"tenant": "T1", "principal": "agent1", "role": "adapter"}, "adm": {"tenant": "T1", "principal": "adm", "role": "admin"}}, os.path.join(d, "s.jsonl"), b"k" * 32, rate=1e9, burst=10 ** 9); svc.handle("POST", "/v2/policies", "adm", {"policy": POLICY})
    auth = AU.CallAuthority(signer, lambda b: svc.handle("POST", "/v2/decisions", "ta", b)[1], audiences={"g"}, contract_version="c", rate=1e9, burst=10 ** 9); nonces = G.NonceStore(os.path.join(d, "n.db"))
    ver = G.Verifier(trust, nonces, issuer="a", audience="g", contract_version="c", policy_version=lambda: svc.tenant("T1").policy_digest); who = {"principal": "agent1", "tenant": "T1"}
    def req(i):
        args = {"text": f"msg{i}"}; ad = E.args_digest(args); return args, ad, {"effect": "send", "target": {"kind": "url", "raw": URL}, "args_digest": ad, "aud": "g", "decision_body": {"protocol": "utcp", "native_operation": "http:POST", "tool_id": "m/post", "effect": "send", "args_digest": ad, "target": {"kind": "url", "raw": URL}, "sink_zone": "partner", "purpose": "p", "input_artifacts": [], "idempotency_key": f"k{i}".ljust(20, "x"), "event_id": f"e{i}"}}
    t_decide, t_issue, t_verify, t_nonce, t_sign, t_gw = [], [], [], [], [], []
    eff = E.parse(auth.issue(who, req(-1)[2])["token"])[1]
    for i in range(N):
        t = time.perf_counter(); E.sign(signer, "k1", dict(eff, nonce=f"s{i}")); t_sign.append(time.perf_counter() - t)
        args, ad, r = req(i); t = time.perf_counter(); svc.handle("POST", "/v2/decisions", "ta", r["decision_body"]); t_decide.append(time.perf_counter() - t)
        args, ad, r = req(N + i); t = time.perf_counter(); o = auth.issue(who, r); t_issue.append(time.perf_counter() - t)
        t = time.perf_counter(); ver.verify(o["token"], principal="agent1", tenant="T1", effect="send", target={"kind": "url", "raw": URL}, args_digest=ad); t_verify.append(time.perf_counter() - t)
        t = time.perf_counter(); nonces.consume(f"n{i}", 2 ** 40); t_nonce.append(time.perf_counter() - t)
        args, ad, r = req(2 * N + i); o = auth.issue(who, r); sink = G.guard(ver, lambda a: {"token": a[1], "principal": "agent1", "tenant": "T1", "effect": "send", "target": {"kind": "url", "raw": URL}, "args": a[0]})(lambda a: None)
        t = time.perf_counter(); sink((args, o["token"])); t_gw.append(time.perf_counter() - t)
    res = {"experiment": "p13-overhead", "iterations": N, "components": {"policy_decision_only": stats(t_decide), "authority_issue_incl_decision_and_sign": stats(t_issue), "sign_only": stats(t_sign), "verify_incl_nonce": stats(t_verify), "nonce_consume_only": stats(t_nonce), "guarded_gateway_call": stats(t_gw)},
           "environment": {"python": platform.python_version(), "platform": platform.platform(), "cpu_count": os.cpu_count(), "machine": platform.machine(), "note": "development sandbox VM; single process, in-process service (no network), sqlite nonce store on local disk; not a production benchmark"}}
    out.mkdir(parents=True); (out / "result.json").write_text(json.dumps(res, indent=1)); sha = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    (out / "manifest.json").write_text(json.dumps({"experiment_id": "p13-overhead", "git_sha": sha, "command": "python3 bench/p13/overhead.py", "iterations": N, "status": "measurement only; no pass/fail threshold"}, indent=1)); print(json.dumps(res["components"], indent=1))


if __name__ == "__main__": main()
