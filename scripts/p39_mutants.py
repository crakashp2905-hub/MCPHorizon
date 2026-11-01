#!/usr/bin/env python3
"""Mutation check for P39: each mutant must make tests.p39.test_emergence FAIL (copy of the tree; the working tree is never modified)."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MUT = [("horizon/emergence/model.py", 'if summary.transform == "sanitize": return PUB', 'if summary.transform == "sanitize": return t', "sanitizers stop sanitizing"),
       ("horizon/emergence/model.py", "bad_known = [h for h in hops if h[2] and not eps.by_port[h[0]].secure_sink]", "bad_known = [h for h in hops[:1] if h[2] and not eps.by_port[h[0]].secure_sink]", "ignore delegated hops"),
       ("horizon/emergence/model.py", "if len(nv) > MAX_VARS or frozenset(ne) in seen: continue", "if len(nv) > MAX_VARS: continue", "no cycle/duplicate-state pruning"),
       ("horizon/emergence/model.py", "elif a.unknown and RANK[a.in_taint] > 0:", "elif False:", "drop UNKNOWN reporting"),
       ("horizon/emergence/baselines.py", 'if last.unknown and last.in_taint != PUB: return "UNKNOWN"', 'if last.unknown and last.in_taint != PUB: return "SAFE"', "unknown treated as safe"),
       ("horizon/emergence/oracle.py", 'per["B"]["canary"] > 0', 'per["A"]["canary"] > 0', "oracle reads the wrong endpoint"),
       ("horizon/emergence/model.py", 'out[op] = OpSummary(o.name, o.kind, o.out_taint, "sanitize"', 'out[op] = OpSummary(o.name, o.kind, o.out_taint, "unknown"', "refinement is a no-op"),
       ("horizon/emergence/model.py", 'if n == "post" and "redir" in tg: continue', 'pass', "post to redirect target allowed")]


def main():
    surv = []; ran = 0
    for f, a, b, why in MUT:
        if b is None: continue
        d = tempfile.mkdtemp(prefix="p39m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target"))
        s = open(os.path.join(t, f)).read()
        if a not in s: print("MUTANT NOT APPLICABLE:", why); surv.append(why); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        r = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "tests.p39.test_emergence"], cwd=t, capture_output=True, text=True, timeout=300)
        print(("KILLED  " if r.returncode else "SURVIVED"), why)
        if not r.returncode: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
