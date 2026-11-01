#!/usr/bin/env python3
"""Mutation check for P43: each mutant must make tests.p43.test_mutation fail (run on a copy of the tree)."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); IR, OR, OP, PL, DT, MZ, EX = ["horizon/mutation/%s.py" % x for x in ("ir", "oracle", "operators", "pipeline", "detectors", "minimize", "experiment")]
MUT = [(IR, 'elif i not in run: errs.append', 'elif False: errs.append', "inputs that do not execute accepted"),
       (IR, 'elif order.index(i) >= order.index(n["id"]) or run[i]["t"] > n["t"]:', 'elif False:', "use-before-produce accepted"),
       (IR, 'if n["type"] == "sink" and (n["dest"] not in DESTS or n["protocol"] not in PROTOCOLS)', 'if False', "non-loopback destination/protocol accepted"),
       (IR, 'if len(ids) > MAX_NODES:', 'if len(ids) > 10 ** 6:', "size guardrail removed"),
       (IR, 'all(g["flags"].get(k) == v for k, v in n.get("guard", {}).items())', 'True', "branch guards ignored"),
       (IR, 'if len(ids) != len(set(ids)):', 'if False:', "duplicate ids accepted"),
       (OR, 'elif (L == "SENSITIVE") != obs["seen"]:', 'elif False:', "lineage/bytes disagreement ignored"),
       (OR, 'elif L == "PARTIAL":', 'elif False:', "partial sanitizer scored instead of UNKNOWN"),
       (OR, 'a["issued_t"] <= t < a["issued_t"] + a["ttl"]', 'a["issued_t"] <= t <= a["issued_t"] + a["ttl"]', "approval window off by one"),
       (OR, 'a["dest"] == s["dest"] and a["principal"] == s["principal"] and a["issued_t"] <= t', 'a["issued_t"] <= t', "approval not bound to dest/principal"),
       (OR, 'if b == principal: out |= grants(g, a, seen)', 'if False: out |= grants(g, a, seen)', "delegation ignored"),
       (OR, '"violation": bool(obs["seen"]) and not auth', '"violation": bool(obs["seen"])', "authorization ignored in verdict"),
       (OR, 'if errs: return {"status": "INVALID"', 'if False: return {"status": "INVALID"', "invalid graphs executed"),
       (OR, 'if n["op"] in ir.CLEARS: p = "CLEAN"', 'pass', "lineage ignores clearing transforms"),
       (OR, 'return "PREMATURE"' if False else 'return "premature" if s["t"] < a["issued_t"]', 'return "valid" if s["t"] < a["issued_t"]', "premature approval classed valid"),
       (OP, 'n.setdefault("t_decide", n["t"]); n["t"] += p["delay"]', 'n["t"] += p["delay"]', "delayed effect loses its decision time"),
       (OP, 'return "SAME" if linked else "UNKNOWN"', 'return "SAME"', "role transfer assumed authority-preserving"),
       (OP, 'return "CHANGE" if (p["dest"] in base) != (s["dest"] in base) else "SAME"', 'return "CHANGE" if (p["dest"] in base) == (s["dest"] in base) else "SAME"', "dest-change prediction inverted"),
       (OP, 'if a["issued_t"] - 1 >= src_t:', 'if True:', "sink moved before its own input"),
       (OP, 'if g["flags"].get(k) != v:', 'if True:', "no-op branch flip emitted"),
       (PL, 'if ir.feasibility(g2): rejected.append', 'if False: rejected.append', "infeasible candidates emitted"),
       (PL, 'if sig in seen: exact += 1; continue', 'if False: exact += 1; continue', "exact duplicates kept"),
       (PL, '/ len(f | features(k)) >= sim:', '/ len(f | features(k)) > 2:', "near duplicates kept"),
       (PL, 'approval_state(g, {**s, "t": s.get("t_decide", s["t"])})', 'approval_state(g, s)', "decision-time validity not part of the causal path"),
       (PL, '"dev": [m for m in items if m["family"] in SD.DEV_FAMILIES]', '"dev": [m for m in items if True]', "family split leaks"),
       (PL, 'or tool_multiset(g2) != tool_multiset(m["graph"]): continue', ': continue' if False else 'or False: continue', "pairs with different tool names accepted"),
       (PL, 'if m["oracle"]["status"] != "OK" or not m["oracle"]["V"]: continue', 'if False: continue', "pairs built from non-violations"),
       (DT, 'return _lineage(g, True, True)', 'return _lineage(g, True, False)', "v2 policy checks approval at decision time"),
       (DT, 'return _lineage(g, False, False)', 'return _lineage(g, True, False)', "v1 policy made branch-aware"),
       (DT, 'and s["id"] in ids}', 'and True}', "learned signatures include benign sinks"),
       (MZ, 'if n["type"] == "source" and any(nid in m.get("inputs", []) for m in g["nodes"]): return None', 'if n["type"] == "source": return None', "unconsumed sources cannot be removed"),
       (MZ, 'return not any(predicate(c) for c in candidates(g))', 'return True', "1-minimality unchecked"),
       (MZ, 'assert predicate(g); evals = 1', 'evals = 1', "minimizer accepts a non-failing start"),
       (EX, 'obs = "SAME" if cv["V"] == pv else "CHANGE"', 'obs = "SAME"', "observed relation never CHANGE"),
       (EX, 'fp = sum(1 for r in rows if not r["V"] and r[name] == "BLOCK")', 'fp = 0', "false blocks not counted")]


def main():
    surv, ran = [], 0
    for f, a, b, why in MUT:
        d = tempfile.mkdtemp(prefix="p43m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target")); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        r = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "tests.p43.test_mutation"], cwd=t, capture_output=True, text=True, timeout=900)
        print(("KILLED  " if r.returncode else "SURVIVED"), why, flush=True)
        if not r.returncode: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
