#!/usr/bin/env python3
"""P42 runner. Needs root (real sandbox). Writes results/v2/p42-coverage/ ONCE. `--check` verifies the recorded definitions (inventory, regressions, claims) still match the code."""
import json, os, sys, platform, hashlib, subprocess
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.coverage import harness as H, engine as EN, regress as RG
OUT = os.path.join(ROOT, "results/v2/p42-coverage")
CLAIMS = os.path.join(ROOT, "spec/protection_claims.json")


def defs():
    return {"inventory": [(s["id"], s["family"], s["interface"], s["enforcement_point"], s["observation_channel"]) for s in H.INVENTORY], "families": list(H.FAMILIES), "claims_sha256": hashlib.sha256(open(CLAIMS, "rb").read()).hexdigest(), "reps": H.N, "ttl_s": EN.TTL_S,
            "regressions": ["R1", "R2", "R3", "R4", "R5-delete", "R5-reorder", "R5-forge", "R6", "R7", "R8", "R9"]}


def main():
    if "--check" in sys.argv:
        rec = json.load(open(os.path.join(OUT, "manifest.json")))["definitions"]; cur = json.loads(json.dumps(defs())); bad = [k for k in cur if rec.get(k) != cur[k]]
        print("definitions match recorded run" if not bad else "MISMATCH " + ",".join(bad)); sys.exit(1 if bad else 0)
    ok, why = H.sandbox_available()
    if not ok: print("UNSUPPORTED:", why); sys.exit(3)
    if os.path.exists(os.path.join(OUT, "result.json")): print("write-once: refusing to overwrite"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); env = H.Env()
    try:
        bundle = EN.collect(env=env); rows = RG.run_regressions(env, bundle); ctrl = RG.healthy_control(env, bundle)
    finally: env.close()
    claims = json.load(open(CLAIMS)); rep = EN.evaluate(bundle, EN.components(), bundle["issued_at"] + 10); cs = EN.claims_status({k: v for k, v in claims.items() if k != "unsupported_do_not_claim"}, rep)
    res = {"ratios": bundle["ratios"], "claims": cs, "regressions": rows, "benchmark": RG.benchmark(rows), "healthy_control": ctrl, "unsupported_do_not_claim": claims["unsupported_do_not_claim"],
           "limits": ["one Linux VM, root, Landlock ABI %s; the confined payload is Python so native-code and kernel-exploit sinks are not covered" % H.SB.landlock_abi(), "sink inventory is hand-built from this repository's enforcement code, not discovered by tracing a real deployment", "observers are separate processes but run by the same harness on the same host; a host compromise defeats them",
                      "the process sampler's sensitivity for short-lived children is probabilistic: that sink's observation state varies run to run", "regressions are authored by the same person as the coverage engine; the benchmark measures whether a reporter notices them, and the baselines (tool logging, all-safe) are structurally unable to",
                      "enforcement of CRED-READ is only self-reported by the confined process (no independent observation exists), so it is never VERIFIED", "TTL (1 h) and the invalidation component list are design choices, not derived from a threat analysis"]}
    json.dump(res, open(os.path.join(OUT, "result.json"), "w"), indent=1, sort_keys=True); json.dump(bundle, open(os.path.join(OUT, "bundle.json"), "w"), indent=1, sort_keys=True)
    json.dump({"definitions": defs(), "python": platform.python_version(), "machine": platform.platform(), "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
               "result_sha256": hashlib.sha256(open(os.path.join(OUT, "result.json"), "rb").read()).hexdigest(), "bundle_digest": bundle["bundle_digest"]}, open(os.path.join(OUT, "manifest.json"), "w"), indent=1); print("written")


main()
