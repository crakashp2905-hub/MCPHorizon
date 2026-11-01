#!/usr/bin/env python3
"""P53 runner: write-once results/v2/p53-continuity/. `--check` verifies the definitions (systems, flags, scenario ids, schema) match the recorded run."""
import hashlib, json, os, platform, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.continuity import experiment as EX, scenarios as SC, core as C, runtime as RT, migrate as M
OUT = os.path.join(ROOT, "results/v2/p53-continuity")

def defs():
    return {"systems": [[e.name, e.kind, sorted(e.cfg.__dict__.items()) if hasattr(e, "cfg") else None] for e in EX.systems()], "scenarios": [[x["id"], x["kind"], x["desc"], x["target"], x["expect"], x.get("single", False), x.get("justified_denial", False)] for x in SC.SCENARIOS],
            "sections": list(C.SECTIONS), "controls": C.CONTROLS, "runtimes": {k: {a: v[a] for a in ("vendor", "supports", "defaults", "carrier", "sinks_mediated", "attestable")} for k, v in RT.LIB.items()}}

def raw_free():
    from horizon.continuity.world import World
    ok = True
    for sc in SC.SCENARIOS:
        if sc["kind"] == "unknown" and sc["id"] == "U01": continue
        w = World(M.Continuity("continuity"), sc); w.execute()
        if w.bundle and C.CANARY in json.dumps(w.bundle["env"]): ok = False
        if w.status["status"] == "MIGRATED" and (w.tgt.state["raw_secret"] is not None or not w.broker.valid(w.tgt.state["cred"], "tgt") or w.broker.valid(w.src.state["cred"], "src")): ok = False
    return ok

def trust_gaps(res):
    sup = {k: {"admitted_for_the_task_contract": not C.covers(dict(__import__("horizon.continuity.world", fromlist=["K0"]).K0), v["supports"]) and v["attestable"] and v["sinks_mediated"], "supports": v["supports"], "attestable": v["attestable"], "sinks_mediated": v["sinks_mediated"], "carrier": v["carrier"]} for k, v in RT.LIB.items()}
    return {"supported_targets": sup, "properties": [
        {"id": "C1", "statement": "a migration is admitted only if the target's fresh, identity-bound attestation covers every mandatory control of the source contract", "holds_on_suite": all(r["covered"] in (True, None) for r in res["rows"] if r["system"] == "continuity" and r["scenario"] != "U02")},
        {"id": "C2", "statement": "no raw credential or secret appears in a serialized envelope; the target receives a broker-issued, runtime-bound credential and the source's is revoked", "holds_on_suite": raw_free()},
        {"id": "C3", "statement": "transferred authority never exceeds the authoritative grant (permissions, principal chain, labels)", "holds_on_suite": all(not r["violations"] for r in res["rows"] if r["system"] == "continuity" and r["scenario"] in ("A06", "A07"))},
        {"id": "C4", "statement": "an envelope resumes at most once; a failed admission leaves the source unchanged or safe-stopped and consumes nothing", "holds_on_suite": all(not r["violations"] for r in res["rows"] if r["system"] == "continuity" and r["scenario"] in ("A08", "A14", "A13"))},
        {"id": "C5", "statement": "expired approvals are not carried; revoked policy handles and an unreadable revocation feed deny admission", "holds_on_suite": all(not r["violations"] for r in res["rows"] if r["system"] == "continuity" and r["scenario"] in ("A09", "A10", "F01"))}],
        "trust_gaps": [
        {"id": "G1", "gap": "the attestor is trusted: if it reports guarantees a runtime does not enforce, the module admits the move and the prohibited effect happens (U02)", "evidence": "U02 violation in results"},
        {"id": "G2", "gap": "attestation says what a runtime supports, not that every sink is mediated at the moment of use; an unmediated sink is detected only if the attestation says so (U03)", "evidence": "U03"},
        {"id": "G3", "gap": "equivalence with an unknown provider cannot be established; such targets are denied and reported UNKNOWN (U01)", "evidence": "U01"},
        {"id": "G4", "gap": "a compromised source can sign a malicious envelope; signature proves origin, not intent, and the no-widening check bounds it only against the authoritative grant", "evidence": "not exercised"},
        {"id": "G5", "gap": "carrier adapters are modelled by a field (mcp/utcp), not wired through the real MCP/UTCP/Code Mode adapters", "evidence": "B06"}]}

def main():
    if "--check" in sys.argv:
        rec = json.load(open(os.path.join(OUT, "manifest.json")))["definitions"]; cur = json.loads(json.dumps(defs(), default=str, sort_keys=True)); bad = [k for k in cur if rec.get(k) != cur[k]]
        print("definitions match recorded run" if not bad else "MISMATCH " + ",".join(bad)); sys.exit(1 if bad else 0)
    if os.path.exists(os.path.join(OUT, "result.json")): print("write-once: refusing to overwrite"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); res = EX.run()
    json.dump(res, open(os.path.join(OUT, "result.json"), "w"), indent=1, sort_keys=True, default=str)
    json.dump(trust_gaps(res), open(os.path.join(OUT, "trust_gaps.json"), "w"), indent=1, sort_keys=True)
    json.dump({"definitions": json.loads(json.dumps(defs(), default=str, sort_keys=True)), "python": platform.python_version(), "machine": platform.platform(), "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
               "result_sha256": hashlib.sha256(open(os.path.join(OUT, "result.json"), "rb").read()).hexdigest()}, open(os.path.join(OUT, "manifest.json"), "w"), indent=1); print("written")

main()
