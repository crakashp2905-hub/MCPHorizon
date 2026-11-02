#!/usr/bin/env python3
"""P83 mutation check: each mutant must make tests/p83 fail. Baseline must pass first. Files restored afterwards."""
import subprocess, sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); os.chdir(ROOT)
M = [
 ("horizon/plan/spans.py", "e = min(h for h in heads if h > s)\n        out[tid]", "e = len(lines)\n        out[tid]"),
 ("horizon/plan/spans.py", "if m.group(1) in tasks: raise", "if False: raise"),
 ("horizon/plan/spans.py", '"sha256": H("\\n".join(lines[s:e]))}\n    gates', '"sha256": H("")}\n    gates'),
 ("horizon/plan/spans.py", 'if sm["gates"] != cur["gates"]', 'if False'),
 ("horizon/plan/spans.py", "elif a != b:", "elif False:"),
 ("horizon/plan/spans.py", '"present" if glob.glob', '"MISSING" if glob.glob'),
 ("horizon/plan/migrate.py", "if bad: raise", "if False: raise"),
 ("horizon/plan/migrate.py", "if o[t][k] != r[k]: raise", "if False: raise"),
 ("horizon/plan/migrate.py", 'if r["status"] == "PENDING": raise', "if False: raise"),
 ("horizon/plan/migrate.py", 'if o[t]["status"] == "VERIFIED": r["status"] = "NEEDS_REVALIDATION"', 'if False: r["status"] = "NEEDS_REVALIDATION"'),
 ("horizon/plan/migrate.py", "if len(n) != len(new): raise", "if False: raise"),
 ("horizon/plan/migrate.py", "hit = direct | downstream(rows, direct, edges)", "hit = direct"),
 ("horizon/plan/migrate.py", 'if r["task_id"] in hit and r["status"] == "VERIFIED"', 'if r["task_id"] in hit'),
 ("horizon/plan/migrate.py", "if k in rc[\"evidence\"])", "if True)"),
 ("horizon/plan/migrate.py", "for a, b in edges: rev[a].add(b)", "pass"),
 ("horizon/plan/migrate.py", "if y not in seen:", "if True:"),
 ("horizon/plan/profiles.py", 'req.get("network", "none") != "none" and p["network"] == "none"', "False"),
 ("horizon/plan/profiles.py", 'req.get("live_effect") and not p["live_effect"]', "False"),
 ("horizon/plan/profiles.py", 'elif p["approval"] != "none" and req.get("approval") != p["approval"]', "elif False"),
 ("horizon/plan/profiles.py", 'req.get("secrets", "none") != "none" and p["secrets"] == "none"', "False"),
 ("horizon/plan/profiles.py", "if p is None: return False", "if p is None: return True"),
 ("horizon/plan/profiles.py", "rep[\"with_named_oracle\"] += orc", "pass"),
 ("horizon/plan/profiles.py", "if not (cm and orc)", "if not (cm or orc)"),
]
def run():
    try: return subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/p83"], capture_output=True, timeout=60, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1")).returncode
    except subprocess.TimeoutExpired: return 99  # hang counts as killed
if run() != 0: print("baseline fails"); sys.exit(2)
surv = []
for f, a, b in M:
    s = open(f).read()
    assert s.count(a) == 1, (f, a, s.count(a))
    open(f, "w").write(s.replace(a, b))
    try:
        if run() == 0: surv.append((f, a))
    finally: open(f, "w").write(s)
print("mutants %d, survivors %d" % (len(M), len(surv)))
for x in surv: print("SURVIVED", x)
sys.exit(1 if surv else 0)
