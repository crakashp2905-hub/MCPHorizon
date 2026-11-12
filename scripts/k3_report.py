"""Runs the K3 coding-agent workflow (legit, attack, unconfined control) and writes docs/evidence/product/K3_REPORT.{json,md}. Scripted agents; CANDIDATE."""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from horizon.product import codingagent as C
def scrub(r):
    r = json.loads(json.dumps(r)); r["runner"]["profile"] = {k: v for k, v in r["runner"]["profile"].items()}; return r
reports = {"legit-agent (confined)": C.run_task(C.LEGIT, "legit"), "attacking-agent (confined)": C.run_task(C.ATTACK, "attack"), "attacking-agent (UNCONFINED control)": C.run_task(C.ATTACK, "open", confined=False)}
out = os.path.join(os.path.dirname(__file__), "..", "docs", "evidence", "product"); os.makedirs(out, exist_ok=True)
json.dump({k: scrub(v) for k, v in reports.items()}, open(os.path.join(out, "K3_REPORT.json"), "w"), indent=1, sort_keys=True)
open(os.path.join(out, "K3_REPORT.md"), "w").write(C.render_markdown(reports) + "\nGenerated on one cloud kernel as root; scripted agents; not independently verified.\n")
