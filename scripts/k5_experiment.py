"""Runs the K5 experiment (4 arms x tasks x attacks) and writes docs/evidence/experiment/K5_RESULTS.{json,md}. Scripted agents; CANDIDATE; see horizon/product/experiment.py for limits."""
import json, os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from horizon.assurance import durable as D
from horizon.authz.keys import Signer, TrustStore
from horizon.product import experiment as E
now = time.time(); inst = Signer.generate("in1", D.INSTALLER_ROLE); iss = Signer.generate("ik1", D.CLAIM_ISSUER_ROLE); ts = TrustStore(clock=lambda: now)
for s in (inst, iss): ts.add(s.kid, s.iss, s.public_raw(), not_before=0, not_after=10 ** 10)
r = E.run_all(inst, iss, ts, now); S = r["summary"]
out = os.path.join(os.path.dirname(__file__), "..", "docs", "evidence", "experiment"); os.makedirs(out, exist_ok=True)
json.dump(r, open(os.path.join(out, "K5_RESULTS.json"), "w"), indent=1, sort_keys=True, default=str)
f = lambda k, n, ci: f"{k}/{n} {ci}"
L = ["# K5 experiment results (CANDIDATE; SCRIPTED agents; one kernel; author-written arms/tasks/attacks; not independently verified)", "",
     "| metric | " + " | ".join(S) + " |", "|---|" + "---|" * len(S)]
rows = [("attack success (of attack runs)", lambda a: f(a["attack_success"], a["attack_runs"], a["attack_success_ci"])), ("legit task completed, benign", lambda a: f(a["benign_completed"], a["benign_tasks"], a["benign_completed_ci"])),
        ("legit task completed UNDER attack", lambda a: f(a["task_completed_under_attack"], a["attack_runs"], a["task_completed_under_attack_ci"])), ("SAFE CONTINUATION (completed AND attack failed)", lambda a: f(a["safe_continuation"], a["attack_runs"], a["safe_continuation_ci"])),
        ("runs with missed effects", lambda a: str(a["runs_with_missed_effects"])), ("runs with false confidence", lambda a: str(a["runs_with_false_confidence"])),
        ("human-authored policy elements", lambda a: str(a["policy_cost"]["human_authored"])), ("total policy elements", lambda a: str(a["policy_cost"]["policy_elements"])),
        ("median run latency s (benign)", lambda a: str(a["latency_median_s"])), ("median synthesis s", lambda a: str(a["synthesis_median_s"]))]
for name, fn in rows: L.append(f"| {name} | " + " | ".join(fn(S[a]) for a in S) + " |")
L += ["", "## Attack success by payload (successes / runs)", "| payload | " + " | ".join(S) + " |", "|---|" + "---|" * len(S)]
for at in E.ATTACKS: L.append(f"| {at} | " + " | ".join(f"{S[a]['by_attack'][at]['success']}/{S[a]['by_attack'][at]['n']}" for a in S) + " |")
L += ["", "## Benign task completion", "| task | " + " | ".join(S) + " |", "|---|" + "---|" * len(S)]
for t in E.TASKS: L.append(f"| {t.tid} | " + " | ".join("yes" if S[a]["by_task_benign"].get(t.tid) else "NO" for a in S) + " |")
L += ["", f"One-time baseline discovery for A4: {r['shared']['baseline_discovery_s']}s; baseline-reachable paths: {r['shared']['baseline_reach']}.", "", "Definitions, limits and what these numbers do NOT show are in horizon/product/experiment.py and docs/NEGATIVE_RESULTS.md (N32)."]
open(os.path.join(out, "K5_RESULTS.md"), "w").write("\n".join(L) + "\n"); print("\n".join(L))
