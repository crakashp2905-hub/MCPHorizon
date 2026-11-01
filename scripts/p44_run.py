#!/usr/bin/env python3
"""P44 runner: write-once results/v2/p44-reach/. `--check` verifies definitions (scenarios, systems, policy table, URL corpus, oracle table) match the recorded run."""
import json, os, sys, platform, hashlib, subprocess
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.reach import experiment as EX, scenarios as SC, broker as B, corpus as CO, network as N
OUT = os.path.join(ROOT, "results/v2/p44-reach")
dig = lambda x: hashlib.sha256(json.dumps(x, sort_keys=True, default=str).encode()).hexdigest()


def defs():
    return {"scenarios": [(s["id"], s["kind"], s["op"], s["target"], s["artifact"], s["src"], s["to"], s["claimed"], sorted(s["services"].items()), sorted(s["ctl"].items()), sorted(s["ext"].items()), s["rebind"], s["followup"]) for s in SC.scenarios()], "systems": list(SC.SYSTEMS), "reps": SC.REPS,
            "configs": {k: dict(vars(v)) for k, v in SC.CFG.items()}, "policy": {"clearance": B.default_policy(N.Resolver()).clearance, "grants": {k: sorted(v) for k, v in B.default_policy(N.Resolver()).grants.items()}, "service_clearance": B.default_policy(N.Resolver()).service_clearance},
            "oracle_secret_ok": sorted(SC.ORACLE_SECRET_OK), "hosts": N.HOSTS, "url_corpus_digest": dig(CO.CASES), "allow_hosts": list(SC.ALLOW_HOSTS)}


def main():
    if "--check" in sys.argv:
        rec = json.load(open(os.path.join(OUT, "manifest.json")))["definitions"]; cur = json.loads(json.dumps(defs(), default=str)); bad = [k for k in cur if rec.get(k) != cur[k]]
        print("definitions match recorded run" if not bad else "MISMATCH " + ",".join(bad)); sys.exit(1 if bad else 0)
    if os.path.exists(os.path.join(OUT, "result.json")): print("write-once: refusing to overwrite"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); res = EX.run()
    json.dump(res, open(os.path.join(OUT, "result.json"), "w"), indent=1, sort_keys=True)
    json.dump({"definitions": json.loads(json.dumps(defs(), default=str)), "python": platform.python_version(), "machine": platform.platform(), "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
               "result_sha256": hashlib.sha256(open(os.path.join(OUT, "result.json"), "rb").read()).hexdigest()}, open(os.path.join(OUT, "manifest.json"), "w"), indent=1); print("written")


main()
