"""P54-01 / P54-02: audit of the P0..P38 prerequisites and the freeze of the 710 original task IDs and the prior experiment artifacts.
Nothing is re-scored here: a task counts as mapped only if spec/acceptance.json carries a command for it; every other task is reported BLOCKED for new security claims."""
import hashlib, json, os, re
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SPEC = os.path.join(ROOT, "docs/MCPHORIZON_2_0_MASTER_SPEC.md"); ACC = os.path.join(ROOT, "spec/acceptance.json"); RES = os.path.join(ROOT, "results/v2")
ID = re.compile(r"\*\*(P(\d+)-(\d+))\*\*")

def sha(b): return "sha256:" + hashlib.sha256(b).hexdigest()
def spec_ids(maxphase=38):
    seen = {}
    for m in ID.finditer(open(SPEC).read()):
        if int(m.group(2)) <= maxphase: seen[m.group(1)] = int(m.group(2))
    return seen
def mapped(): return set(json.load(open(ACC)))

def phases(maxphase=38):
    ids, acc = spec_ids(maxphase), mapped(); out = []
    for p in range(maxphase + 1):
        tot = sorted(i for i, q in ids.items() if q == p); m = [i for i in tot if i in acc]; b = [i for i in tot if i not in acc]
        out.append({"phase": "P%d" % p, "total": len(tot), "mapped": len(m), "blocked": len(b), "blocked_ids": b, "status": "COMPLETE-MAPPED" if not b else ("BLOCKED-PARTIAL" if m else "BLOCKED")})
    return out

def audit():
    ph = phases(); tot = sum(p["total"] for p in ph); m = sum(p["mapped"] for p in ph)
    return {"phases": ph, "total": tot, "mapped": m, "blocked": tot - m,
            "rule": "a BLOCKED task is one with no spec/acceptance.json command; any new security claim that depends on it must say so",
            "note": "mapped means a command exists and passed when the phase was merged; it does not mean the task is VERIFIED (nothing is)"}

def artifact_files():
    out = []
    for d in sorted(os.listdir(RES)):
        if d.startswith("p54"): continue
        p = os.path.join(RES, d)
        for root, _, fs in os.walk(p) if os.path.isdir(p) else [(RES, [], [d])]:
            for f in sorted(fs): out.append(os.path.relpath(os.path.join(root, f), ROOT))
    return out

def freeze():
    ids = sorted(spec_ids())
    return {"task_ids": {"count": len(ids), "digest": sha("\n".join(ids).encode())},
            "artifacts": {f: sha(open(os.path.join(ROOT, f), "rb").read()) for f in artifact_files()}, "acceptance_ids": {"count": len(mapped()), "digest": sha("\n".join(sorted(mapped())).encode())}}

def check(fr):
    """Compare the current tree to a recorded freeze. Returns the differences (empty = unchanged)."""
    cur = freeze(); d = []
    if cur["task_ids"] != fr["task_ids"]: d.append("task_ids changed")
    for f, h in fr["artifacts"].items():
        p = os.path.join(ROOT, f)
        if not os.path.exists(p): d.append("missing " + f)
        elif sha(open(p, "rb").read()) != h: d.append("modified " + f)
    return d
