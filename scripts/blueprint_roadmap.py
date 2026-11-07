"""Check (or refresh digests for) docs/roadmap/blueprint_status.json against the blueprint document. Usage: --check (default) | --refresh-digests | --report."""
import json, os, sys
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, R)
from security_hardening import roadmap as rm
D = os.path.join(R, "docs", "roadmap")
DOC = os.path.join(D, "BOUNDARY_SYNTHESIS" + "_BLUEPRINT_2026-11-07.md")
ST = os.path.join(D, "blueprint_status.json")
REP = os.path.join(D, "STATUS_REPORT.md")
def load():
    d = rm.parse_doc(open(DOC).read()); s = json.load(open(ST)); return d, s
def main(argv):
    d, s = load()
    if "--refresh-digests" in argv:   # recomputes sha256 of evidence files ONLY; never changes a status
        for r in s["tasks"].values():
            if r["status"] == "CANDIDATE":
                for p in list(r["evidence"]):
                    if os.path.isfile(os.path.join(R, p)): r["evidence"][p] = rm.sha(os.path.join(R, p))
        json.dump(s, open(ST, "w"), indent=1, sort_keys=True); open(ST, "a").write("\n")
    pr = rm.problems(d, s, R, rm.sha(DOC))
    if "--report" in argv or "--refresh-digests" in argv: open(REP, "w").write(rm.report(d, s))
    elif os.path.exists(REP) and open(REP).read() != rm.report(d, s): pr.append("REPORT_STALE")
    for x in pr: print(x)
    print("OK" if not pr else f"{len(pr)} problem(s)"); return 1 if pr else 0
if __name__ == "__main__": sys.exit(main(sys.argv[1:]))
