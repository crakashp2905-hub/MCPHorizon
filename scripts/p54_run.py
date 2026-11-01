#!/usr/bin/env python3
"""P54 runner: write-once results/v2/p54-integration/{result,freeze,manifest}.json.
`--check` re-derives everything except the slow reproduction rows and verifies the definitions match the recorded run and that the frozen P0..P53 artifacts are unchanged.
`--freeze-only` writes freeze.json (P54-02) before any other P54 evidence exists."""
import hashlib, json, os, platform, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.integration import experiment as EX, audit as AU, registry as RG, gates as GT, statemachine as SM
OUT = os.path.join(ROOT, "results/v2/p54-integration")

def defs(R):
    return {"modules": [[m["id"], m["pkg"], m["results"], m["oracle"], m["system"]] for m in RG.MODULES], "gates": [[g["id"], g["title"], sorted(g["checks"])] for g in R["gates"]], "state_machine_checks": [x["name"] for x in R["statemachine"]],
            "protocol_paths": R["protocols"]["parity"]["paths"], "parity": [R["protocols"]["parity"]["workflows"], 54], "audit_total": R["audit"]["total"]}
def J(o): return json.loads(json.dumps(o, default=str, sort_keys=True))

def main():
    fp = os.path.join(OUT, "freeze.json")
    if "--freeze-only" in sys.argv:
        if os.path.exists(fp): print("write-once: refusing to overwrite"); sys.exit(2)
        os.makedirs(OUT, exist_ok=True); json.dump(AU.freeze(), open(fp, "w"), indent=1, sort_keys=True); print("freeze written"); return
    fr = json.load(open(fp)) if os.path.exists(fp) else None
    if "--check" in sys.argv:
        rec = json.load(open(os.path.join(OUT, "manifest.json")))["definitions"]; R = EX.collect(reproduce=False, freeze=fr); cur = J(defs(R)); bad = [k for k in cur if rec.get(k) != cur[k]]
        old = json.load(open(os.path.join(OUT, "result.json"))); st = {g["id"]: g["status"] for g in R["gates"]}; ost = {g["id"]: g["status"] for g in old["gates"]}
        if st != ost: bad.append("gate statuses")
        if R["freeze_diff"]: bad.append("frozen artifacts changed: %s" % R["freeze_diff"][:3])
        print("definitions, gate statuses and frozen artifacts match the recorded run" if not bad else "MISMATCH " + ",".join(map(str, bad))); sys.exit(1 if bad else 0)
    if os.path.exists(os.path.join(OUT, "result.json")): print("write-once: refusing to overwrite"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True)
    if fr is None: json.dump(AU.freeze(), open(fp, "w"), indent=1, sort_keys=True); fr = json.load(open(fp))
    R = EX.collect(reproduce=True, freeze=fr); env = R.pop("environment"); R.pop("freeze")
    json.dump(R, open(os.path.join(OUT, "result.json"), "w"), indent=1, sort_keys=True, default=str)
    json.dump({"definitions": J(defs({**R, "gates": R["gates"]})), "environment": env, "python": platform.python_version(), "machine": platform.platform(), "result_sha256": hashlib.sha256(open(os.path.join(OUT, "result.json"), "rb").read()).hexdigest()}, open(os.path.join(OUT, "manifest.json"), "w"), indent=1, sort_keys=True, default=str)
    print("written;", " ".join("%s=%s" % (g["id"], g["status"]) for g in R["gates"]))
main()
