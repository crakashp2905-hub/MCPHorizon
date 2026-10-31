"""P14-13: write results/v2/p14-parity/ (write-once)."""
import json, subprocess, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from horizon.equiv import parity as P
from bench.p14.parity_gate import SEED, N

out = REPO / "results/v2/p14-parity"
if (out / "result.json").exists(): raise SystemExit("write-once: use a new experiment directory")
out.mkdir(parents=True, exist_ok=True); wfs = P.generate(SEED, N); m = P.matrix(wfs)
(out / "result.json").write_text(json.dumps({"workflows": len(wfs), "coverage": m["coverage"], "unsupported": m["unsupported"], "discrepancy_traces": m["discrepancies"], "traps": P.trap_results(), "metamorphic_violations": P.metamorphic_mcp()}, indent=1))
sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
(out / "manifest.json").write_text(json.dumps({"experiment_id": "p14-parity", "git_sha": sha, "command": "python3 bench/p14/run.py", "seed": SEED, "workflows": N, "status": "candidate; scripted rig, not production transports"}, indent=1))
