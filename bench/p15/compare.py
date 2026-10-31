"""P15-13: attenuating grants vs static RBAC vs no-delegation on a generated task set. Baselines are MY simple models (documented), not products. Write-once results/v2/p15-delegation/."""
import json, random, subprocess, sys, time
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from horizon.authz import keys as K
from horizon.deleg import authority as A, grants as G

U = "https://api.example.com/v1"; N = 400; SEED = 15


def scenarios():
    r = random.Random(SEED); out = []
    for i in range(N):
        kind = r.choice(["legit_narrow", "escalate_action", "escalate_resource", "cross_tenant", "revoked_before_effect", "legit_narrow"])
        out.append({"id": i, "kind": kind, "res": r.choice(["notes", "alerts"])})
    return out


def run_grants(sc):
    rs, ds = K.Signer.generate("r", "root"), K.Signer.generate("d", "delegator"); tr = K.TrustStore(); tr.add("r", "root", rs.public_raw(), not_before=0, not_after=2 ** 40); tr.add("d", "delegator", ds.public_raw(), not_before=0, not_after=2 ** 40)
    v = G.Verifier(tr, audience="gw", clock=lambda: 100); d = G.Delegator(ds, v); out = {}
    root = G.issue_root(rs, tenant="T", sub="orch", aud="gw", auth=A.Authority.make({"read", "send"}, resources=[U], arg_max={"text": 100}, exp=1000), now=0)
    for s in sc:
        want_res = f"{U}/{s['res']}"; act = "read"
        try:
            if s["kind"] == "escalate_action": act = "delete"; ch = d.delegate([root], [root["grant"]["id"]], requester="orch", child_sub="w", auth=A.Authority.make({"delete"}, resources=[want_res], exp=900))
            elif s["kind"] == "escalate_resource": ch = d.delegate([root], [root["grant"]["id"]], requester="orch", child_sub="w", auth=A.Authority.make({"read"}, resources=["https://other.example.org/"], exp=900))
            else: ch = d.delegate([root], [root["grant"]["id"]], requester="orch", child_sub="w", auth=A.Authority.make({"read"}, resources=[f"{U}/notes"], arg_max={"text": 10}, exp=900))
        except G.GrantError: out[s["id"]] = False; continue
        if s["kind"] == "revoked_before_effect": v.rev.revoke(ch["grant"]["id"])
        res = want_res if s["kind"] != "escalate_resource" else "https://other.example.org/x"
        out[s["id"]] = v.authorize([root, ch], ch["grant"]["id"], principal="w", tenant="T2" if s["kind"] == "cross_tenant" else "T", action=act, tool="t", resource=res)["allow"]
    return out


def run_rbac(sc):
    """Role 'worker' = {read,send} on the API prefix; any agent holding the role gets all of it; no per-task narrowing; role not tenant-scoped; no per-grant revocation."""
    role = {"read", "send"}; out = {}
    for s in sc:
        act = "delete" if s["kind"] == "escalate_action" else "read"; res = "https://other.example.org/x" if s["kind"] == "escalate_resource" else f"{U}/{s['res']}"
        out[s["id"]] = act in role and res.startswith(U)
    return out


def run_nodeleg(sc): return {s["id"]: False for s in sc}


def ground_truth(s): return s["kind"] in ("legit_narrow",) and s["res"] == "notes"      # a narrow task that needs notes only; alerts is outside the delegated scope by design


def main():
    out = REPO / "results/v2/p15-delegation"
    if (out / "result.json").exists(): raise SystemExit("write-once")
    sc = scenarios(); res = {}
    for name, fn in (("attenuating_grants", run_grants), ("static_rbac", run_rbac), ("no_delegation", run_nodeleg)):
        t = time.perf_counter(); o = fn(sc); dt = time.perf_counter() - t
        # scenarios where the worker legitimately needs 'alerts' read are counted legit_but_out_of_scope: a correct system denies them (task was scoped to notes)
        legit = [s for s in sc if s["kind"] == "legit_narrow" and s["res"] == "notes"]; bad = [s for s in sc if s["kind"] != "legit_narrow" or s["res"] != "notes"]
        res[name] = {"legit_completed": sum(o[s["id"]] for s in legit), "legit_total": len(legit), "unauthorized_allowed": sum(o[s["id"]] for s in bad), "unauthorized_total": len(bad), "seconds": round(dt, 3)}
    out.mkdir(parents=True, exist_ok=True); (out / "result.json").write_text(json.dumps(res, indent=1))
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    (out / "manifest.json").write_text(json.dumps({"experiment_id": "p15-delegation", "git_sha": sha, "command": "python3 bench/p15/compare.py", "seed": SEED, "n": N, "status": "candidate; baselines are author-written models, scenarios synthetic"}, indent=1)); print(json.dumps(res, indent=1))


if __name__ == "__main__": main()
