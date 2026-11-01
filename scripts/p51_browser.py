#!/usr/bin/env python3
"""P51 real-browser run: write-once results/v2/p51-vision-browser/browser.json. Needs python playwright + Chromium; refuses (exit 3, UNSUPPORTED) when they are missing.
`--check` verifies the recorded scenario definitions/flags against the code and needs no browser. Timing is machine-specific and recorded separately from the verdicts."""
import json, os, platform, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.vision import browser as B, browser_run as BR
OUT = os.path.join(ROOT, "results/v2/p51-vision-browser")

def defs():
    L = BR.Lab()
    try: return {"scenarios": [[s["id"], s["kind"], s["desc"], [{k: v for k, v in st.items()} for st in s["steps"]], [{k: v for k, v in a.items() if v is not None and not str(v).startswith("http")} for a in s["authorized"]]] for s in BR.scenarios(L)], "chromium_args": B.chromium_args(), "loopback_hosts": list(B.LOOP), "origins": ["app=127.0.0.1", "evil=localhost", "ads=127.0.0.2"]}
    finally: L.close()

def main():
    if "--check" in sys.argv:
        rec = json.load(open(os.path.join(OUT, "browser.json")))["definitions"]; cur = json.loads(json.dumps(defs(), sort_keys=True)); bad = [k for k in cur if json.loads(json.dumps(rec.get(k), sort_keys=True)) != cur[k]]
        print("browser definitions match recorded run" if not bad else "MISMATCH " + ",".join(bad)); sys.exit(1 if bad else 0)
    if B.available() is None: print("UNSUPPORTED: playwright/Chromium not available"); sys.exit(3)
    if os.path.exists(os.path.join(OUT, "browser.json")): print("write-once: refusing to overwrite"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); r = BR.run_all(); timing = r.pop("timing_ms_machine_specific")
    for row in r["rows"]: row.pop("decision_ms", None)
    json.dump({"definitions": json.loads(json.dumps(defs(), sort_keys=True)), "chromium": r["chromium"], "python": platform.python_version(), "machine": platform.platform(), "rows": r["rows"], "timing_ms_machine_specific": timing,
               "note": "Verdicts are stable; timing is not. Perception is a DOM-side proxy for pixels, not a vision model. The file chooser is answered by the scripted agent."}, open(os.path.join(OUT, "browser.json"), "w"), indent=1, sort_keys=True); print("written")

main()
