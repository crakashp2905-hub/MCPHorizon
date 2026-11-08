"""Write or check the exhaustive Forge results file kept with the other blueprint evidence (task-space run plus baselines). Usage: --write, or no argument to check."""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.forge import space
OUT = os.path.join(ROOT, "docs", "evidence", "blueprint", "FORGE_EXHAUSTIVE.json")
def main(argv):
    r = space.exhaustive(); r["scope"] = "whole finite Forge task space (768 tasks); checker and planners share an author; no independent world; 'unsafe' = rejected by that checker"
    text = json.dumps(r, indent=1, sort_keys=True) + "\n"
    if "--write" in argv: open(OUT, "w").write(text); print("written"); return 0
    ok = os.path.exists(OUT) and open(OUT).read() == text and not r["failures"]; print("OK" if ok else "STALE_OR_FAILURES"); return 0 if ok else 1
if __name__ == "__main__": sys.exit(main(sys.argv[1:]))
