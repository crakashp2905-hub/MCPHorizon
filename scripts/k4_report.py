"""Runs the K4 Loop B demo and writes docs/evidence/product/LOOP_B_REPORT.{json,md}. Scripted probes/agents; CANDIDATE."""
import json, os, sys, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from horizon.assurance import durable as D
from horizon.authz.keys import Signer, TrustStore
from horizon.product import loopb as L
now = time.time(); inst = Signer.generate("in1", D.INSTALLER_ROLE); iss = Signer.generate("ik1", D.CLAIM_ISSUER_ROLE); ts = TrustStore(clock=lambda: now)
for s in (inst, iss): ts.add(s.kid, s.iss, s.public_raw(), not_before=0, not_after=10 ** 10)
r = L.run_loop(tempfile.mkdtemp(), installer=inst, claim_issuer=iss, trust=ts, now=now); r.pop("installed")
o = r["workload"]["outcomes"]; z = r["zero"]["claims"]
out = os.path.join(os.path.dirname(__file__), "..", "docs", "evidence", "product"); os.makedirs(out, exist_ok=True)
json.dump({k: r[k] for k in ("baseline", "baseline_reachable", "proposal", "forge_check_violations", "post", "post_reachable", "zero")} | {"workload": {"task_completed": o["task_completed"], "landed": o["legitimate_edits_landed"], "blocked": o["edits_blocked"]}}, open(os.path.join(out, "LOOP_B_REPORT.json"), "w"), indent=1, sort_keys=True, default=list)
L_ = ["# Loop B on the live environment (CANDIDATE; scripted probes and agent; one kernel; not independently verified)", "",
      "## 1. Spectra: effect paths reachable by an UNCONFINED agent", *[f"- {f['edge']}: {f['outcome']} ({f['grade']}, witness {f['witness']}) {f['note']}" for f in r["baseline"]], "",
      f"## 2. Forge proposal (independent checker violations: {r['forge_check_violations']})", f"- {r['proposal']['rationale']}", f"- controls: {list(r['proposal']['controls'])}", "",
      "## 3. Install + re-discovery under the installed policy", f"- reachable after install: {r['post_reachable']}", f"- workload: task completed = {o['task_completed']}; landed {o['legitimate_edits_landed']}; blocked {[(e['path'], e['code']) for e in o['edits_blocked']]}", "",
      "## 4. HorizonZero verdicts", *[f"- {k}: **{v['verdict']}** — {v['reason']}" for k, v in z.items()], "",
      "Nothing above says 'safe'. SUPPORTED_BY_PROBES covers only the listed probes and the one observed destination/directory; UNKNOWN is explicit where no observer exists."]
open(os.path.join(out, "LOOP_B_REPORT.md"), "w").write("\n".join(L_) + "\n")
