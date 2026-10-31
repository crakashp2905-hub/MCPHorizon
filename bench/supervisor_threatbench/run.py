#!/usr/bin/env python3
"""Run SupervisorThreatBench and print a JSON report (P86-16 subset). Usage: run.py"""
import json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bench.supervisor_threatbench.scenarios import SCENARIOS, NOT_RUN
from orchestrator import deps


def run() -> dict:
    res = {}
    for sid, (task, fn) in SCENARIOS.items():
        t = time.perf_counter()
        try: atk, ben, note = fn(); err = None
        except Exception as e: atk, ben, note, err = None, None, "", f"{type(e).__name__}: {e}"
        res[sid] = {"task": task, "attack_effect_occurred": atk, "benign_ok": ben, "detail_if_attack_succeeded": note if atk else "", "error": err, "ms": round((time.perf_counter() - t) * 1000, 1)}
    lock = deps.parse_lock((Path(__file__).resolve().parents[2] / "third_party_pins/python-requirements.lock.txt").read_text())
    ok = [r for r in res.values() if r["error"] is None]
    return {"scenarios": res, "totals": {"run": len(res), "errored": len(res) - len(ok), "attacks_with_unauthorized_effect": sum(1 for r in ok if r["attack_effect_occurred"]),
            "false_blocks": sum(1 for r in ok if not r["benign_ok"])},
            "open_findings": [{"id": "F-DEPS", "text": f"third_party_pins/python-requirements.lock.txt pins {len(lock)} packages and {len(deps.require_hashes(lock))} have NO checksum; "
                               "the missing-checksum policy would reject this lock file, so dependency substitution is currently undetectable for the real pins."}],
            "not_run": {k: {"task": t, "reason": r} for k, (t, r) in NOT_RUN.items()},
            "caveats": ["Scenarios and defences share an author; no independent review or held-out variants.", "Effect oracles check ledger/verdict/path-acceptance state; they do not observe an OS-level sandbox.",
                        "Telemetry coverage and cost are not measured (no live providers)."]}


if __name__ == "__main__":
    r = run(); print(json.dumps(r, indent=1)); sys.exit(1 if r["totals"]["errored"] or r["totals"]["attacks_with_unauthorized_effect"] or r["totals"]["false_blocks"] else 0)
