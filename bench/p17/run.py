"""P17-12/13: txn-aware prevention vs detect-and-alert vs stop-after-breach on fault-injected scenarios. Write-once."""
import json, random, subprocess, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from horizon.txn.engine import Contract, Fault, Resource, Txn

SEED, N = 17, 300
C_REV = Contract("COMPENSABLE", idempotent=True, compensation="restore"); C_PUB = Contract("IRREVERSIBLE")


def policy(p, k, v): return "PROTECTED" if k.startswith("protected/") else None
def mk(): return Resource({"notes/a": "old", "protected/x": "orig"})


def scenarios():
    r = random.Random(SEED); out = []
    for i in range(N):
        out.append({"i": i, "key": r.choice(["notes/a", "notes/b", "protected/x", "protected/y"]), "pub": r.random() < .15, "fault": r.choice([None, None, "timeout_after_apply", "double_apply", "crash_before_apply"]), "revoke_race": r.random() < .15})
    return out


def run_session(system, scs):
    """One resource per session of 5 sequential operations. stop_after_breach halts the session after the first PROHIBITED effect lands (too late); detect_alert never stops."""
    res = mk(); st = {"revoked": False}; tx = Txn(res, policy if system == "txn" else (lambda *a: None), lambda p, k: not (st["revoked"] and system == "txn"), set()); rows = []; halted = False
    for sc in scs:
        prohibited = sc["key"].startswith("protected/") or sc["revoke_race"]; row = {"prohibited": prohibited, "refused": False, "skipped": halted}
        if halted: rows.append(row); continue
        c = C_PUB if sc["pub"] else C_REV; h = tx.prepare("agent", sc["key"], f"v{sc['i']}", c); h["ledger_before"] = len(res.ledger.effects(sc["key"]))
        if sc["fault"]: res.faults.add(sc["fault"])
        st["revoked"] = sc["revoke_race"]
        if system == "txn":
            if sc["pub"] and not prohibited: tx.approvals.add(h["id"])
            r = tx.retry(h); row["refused"] = r["status"] == "REFUSED"; row["outcome"] = r.get("outcome"); res.faults.clear()
        else:
            try: res.apply(sc["key"], h["value"], publish=sc["pub"])
            except Fault: pass
            res.faults.clear()
        eff = res.ledger.effects(sc["key"])[h["ledger_before"]:]; row.update(landed=bool(eff), dup=len(eff) > 1, final_ok=res.read(sc["key"])[0] == h["value"], pub=sc["pub"])
        if prohibited and eff and system == "stop_after_breach": halted = True
        rows.append(row)
    return rows, res.ledger.verify()


def run(system, sc):
    rows = []; ok = True
    for i in range(0, len(sc), 5): r, v = run_session(system, sc[i:i + 5]); rows += r; ok &= v
    P = [r for r in rows if r["prohibited"]]; L = [r for r in rows if not r["prohibited"]]
    return {"ledger_chain_valid": ok, "prohibited_attempts": len(P), "prevented_verified_absent": sum(r["refused"] and not r["landed"] for r in P if "landed" in r), "residual_damage": sum(r.get("landed", False) for r in P),
            "irreversible_residual": sum(r.get("landed", False) and r.get("pub", False) for r in P), "prohibited_skipped_by_halt": sum(r["skipped"] for r in P), "legit_total": len(L), "legit_final_state_correct": sum(r.get("final_ok", False) and not r["skipped"] for r in L),
            "legit_skipped_by_halt": sum(r["skipped"] for r in L), "legit_duplicate_ledger_effects": sum(r.get("dup", False) for r in L)}


def main():
    out = REPO / "results/v2/p17-transactions"
    if (out / "result.json").exists(): raise SystemExit("write-once")
    sc = scenarios(); res = {s_: run(s_, sc) for s_ in ("txn", "detect_alert", "stop_after_breach")}
    out.mkdir(parents=True, exist_ok=True); (out / "result.json").write_text(json.dumps(res, indent=1))
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    (out / "manifest.json").write_text(json.dumps({"experiment_id": "p17-transactions", "git_sha": sha, "command": "python3 bench/p17/run.py", "seed": SEED, "n": N, "status": "candidate; synthetic KV fixture, author-written baselines"}, indent=1)); print(json.dumps(res, indent=1))


if __name__ == "__main__": main()
