#!/usr/bin/env python3
"""P2-22: differential test. Python oracle (horizon/core) vs Rust core (core/) on seeded random + adversarial cases.
Usage: python3 scripts/run_diff.py [--seed N] [--n N]. Exit 1 on any disagreement."""
import argparse, json, random, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from horizon.core import scope as sc, closure as cl, labels as lb, decide as dc

ap = argparse.ArgumentParser(); ap.add_argument("--seed", type=int, default=7); ap.add_argument("--n", type=int, default=2000)
a = ap.parse_args(); R = random.Random(a.seed)
ALPH = ["a", "b", "/", "é", "*", "?", "t1", "x"]
def rtext(n=8): return "".join(R.choice(ALPH[:4] + ["é"]) for _ in range(R.randint(0, n)))
def rglob():
    base = "".join(R.choice(["a", "b", "/", "*", "**", "?", "é", "t1/"]) for _ in range(R.randint(1, 7)))
    if R.random() < .9: return base.replace("t1/", "a") if base.count("*") + base.count("?") > 7 else base
    return R.choice([base, base, base, "(a+)+$", "[ab]*", "a|b", "*" * R.randint(3, 11), "a" * R.choice([10, 256, 257]), "x\x00y", "a\\b", "***", "a**b**c"])
def rscope():
    k = R.choice(["literal", "glob", "glob", "tenant", "any", "glob"]) if R.random() < .93 else "regex"
    if k == "any": return {"kind": k, **({"value": "x"} if R.random() < .1 else {})}
    if k == "glob": return {"kind": k, "value": rglob()}
    if k == "tenant": return {"kind": k, "value": R.choice(["t1", "t10", "t1", "é", "t2", "t1/x" if R.random() < .1 else "t1"])}
    return {"kind": k, "value": rtext()} if R.random() > .02 else {"kind": k}
ATOMS = [f"cap({c})" for c in "abcdefg"] + ["bad atom", "Cap(x)", "cap()", "cap(é)", "cap(" + "a" * 129 + ")"]
def rrules():
    rs, hostile = [], R.random() < .12
    for i in range(R.randint(0, 9)):
        r = {"id": f"r{i}", "premises": R.sample(ATOMS[:7], R.randint(1, 3)), "head": R.choice(ATOMS[:7]), "code": R.choice(["CODE_A", "CODE_B"])}
        if hostile and R.random() < .3:
            kind = R.choice(["dup", "arity", "head", "code", "extra"])
            if kind == "dup": r["id"] = "r0"
            elif kind == "arity": r["premises"] = R.sample(ATOMS[:7], 5)
            elif kind == "head": r["head"] = R.choice(ATOMS[7:])
            elif kind == "code": r["code"] = "bad"
            else: r["extra"] = 1
        rs.append(r)
    return rs
CONF, TRUST = lb.CONF, lb.TRUST
EFFECTS, ZONES, PURP = ["send", "read", "write"], ["external", "registry", None], ["approved_release", "other", None]
def rwhen():
    w = {}
    for k, gen in (("effect", lambda: R.choice(EFFECTS)), ("sink_zone", lambda: R.choice(ZONES[:2])), ("input_label_at_least", lambda: R.choice(CONF)),
                   ("maximum_input_label", lambda: R.choice(CONF)), ("authorized_flow", lambda: R.random() > .5), ("lineage_complete", lambda: R.random() > .5),
                   ("purpose", lambda: R.choice(PURP[:2])), ("unknown_effect_or_destination", lambda: R.random() > .5)):
        if R.random() < .3: w[k] = gen()
    if R.random() < .03: w["bogus"] = 1
    return w
def rpolicy():
    return {"rules": [{"id": f"p{R.randint(0, 99):02d}-{i}", "when": rwhen(), "decision": R.choice(["DENY", "REVIEW", "ALLOW", "ALLOW", "QUARANTINE", "UNKNOWN"])} for i in range(R.randint(0, 7))],
            "defaults": {"protected_effect": R.choice(["DENY", "DENY", "REVIEW"]), "inspection_only": R.choice(["QUARANTINE", "DENY"]), "evaluation_timeout": "DENY"}}
def rctx():
    return {"identity_valid": R.random() > .1, "mapping_complete": R.random() > .2, "interceptable": R.random() > .1, "protected_effect": R.random() > .3,
            "effect": R.choice(EFFECTS), "sink_zone": R.choice(ZONES), "purpose": R.choice(PURP), "input_label": R.choice(CONF), "lineage_complete": R.random() > .3,
            "authorized_flow": R.random() > .5, "approval": R.choice([None, {"valid": True}, {"valid": False}])}

cases = {"scope_match": [{"scope": rscope(), "value": R.choice([rtext(), rtext(), "a" * 4097, "t1/x", "t10/x", "t1", "x\x00"])} for _ in range(a.n)],
         "scope_subsumes": [{"a": rscope(), "b": rscope()} for _ in range(a.n)],
         "closure": [{"atoms": R.sample(ATOMS[:7], R.randint(0, 6)) + (R.sample(ATOMS[7:], 1) if R.random() < .05 else []), "rules": rrules()} for _ in range(a.n)],
         "labels": [{"conf": [R.choice(CONF) for _ in range(R.randint(0, 5))], "trust": [R.choice(TRUST) for _ in range(R.randint(0, 5))]} for _ in range(a.n)],
         "decide": [{"policy": rpolicy(), "ctx": rctx()} for _ in range(a.n * 2)]}

def err(f, *x):
    try: return f(*x)
    except (sc.ScopeError, cl.BudgetError): return "ERR"
exp = {"scope_match": [err(sc.matches, c["scope"], c["value"]) for c in cases["scope_match"]],
       "scope_subsumes": [err(sc.subsumes, c["a"], c["b"]) for c in cases["scope_subsumes"]],
       "closure": [err(cl.closure, c["atoms"], c["rules"]) for c in cases["closure"]],
       "labels": [lb.output_label(c["conf"], c["trust"]) for c in cases["labels"]],
       "decide": [dc.decide(c["policy"], c["ctx"]) for c in cases["decide"]]}
with tempfile.TemporaryDirectory() as d:
    p = Path(d) / "cases.json"; p.write_text(json.dumps(cases))
    r = subprocess.run(["cargo", "run", "--quiet", "--release", "-p", "horizon-diff", "--", str(p)], cwd=ROOT / "core", capture_output=True, text=True)
    if r.returncode: print(r.stderr[-3000:]); raise SystemExit(2)
    got = json.loads(r.stdout)
bad = 0
for k in exp:
    mism = [i for i, (e, g) in enumerate(zip(exp[k], got[k])) if e != g]
    errs = sum(e == "ERR" for e in exp[k]); trues = sum(e is True for e in exp[k]); verd = {}
    if k == "decide":
        for e in exp[k]: verd[e["verdict"]] = verd.get(e["verdict"], 0) + 1
    print(f"{k}: n={len(exp[k])} mismatches={len(mism)} ERR={errs} true={trues} {verd or ''}")
    for i in mism[:3]: print("  case", json.dumps(cases[k][i])[:300], "\n   py ", json.dumps(exp[k][i])[:200], "\n   rs ", json.dumps(got[k][i])[:200])
    bad += len(mism) + (len(exp[k]) != len(got[k]))
raise SystemExit(1 if bad else 0)
