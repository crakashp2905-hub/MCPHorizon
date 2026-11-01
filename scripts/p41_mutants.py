#!/usr/bin/env python3
"""Mutation check for P41: each mutant must make tests.p41.test_counterfactual fail (run on a copy of the tree)."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); CO, CM, SCN = "horizon/counterfactual/core.py", "horizon/counterfactual/commit.py", "horizon/counterfactual/scenarios.py"
MUT = [(CO, "if got != approved_digest: c.execute(\"rollback\")", "if False: c.execute(\"rollback\")", "DB commit does not re-derive/compare the diff (no CAS)"),
       (CO, "if BAD_KW.search(body): return \"UNSUPPORTED:forbidden-keyword\"", "pass", "forbidden keywords accepted"),
       (CO, "if not s or \";\" in body: return \"UNSUPPORTED:multi-statement\"", "if not s: return \"UNSUPPORTED:multi-statement\"", "stacked statements accepted"),
       (CO, "if ds[0] != ds[1] or NONDET.search", "if NONDET.search", "double-run determinism check removed"),
       (CO, "if not (lo <= len(ch) <= hi): R.append", "if False: R.append", "cardinality rule removed"),
       (CO, "if t not in contract.allowed_tables: R.append", "if False: R.append", "table allowlist removed"),
       (CO, "and c.get(\"class\") in contract.forbidden_package_classes: R.append(\"SENSITIVE_IN_PUBLIC", "and False: R.append(\"SENSITIVE_IN_PUBLIC", "public-prefix content rule removed"),
       (CO, "if diff.irreversible or diff.external: review.append", "if False: review.append", "irreversible/external allowed"),
       (CO, "return p if p.startswith(self.root + os.sep) else None", "return p", "realpath containment check removed (the lexical '..' check is redundant defense-in-depth: an accepted equivalent mutant)"),
       (CO, "if cur.digest() != approved_digest: return {\"committed\": False, \"why\": \"STATE_CHANGED\"}", "pass", "file commit does not re-validate"),
       (CM, "if p[\"artifact\"] != od: return", "if False: return", "attestation not bound to operation digest"),
       (CM, "if task in self.frozen:", "if False:", "frozen task can still commit"),
       (CM, "if v == \"BLOCK\": return", "if False: return", "BLOCK verdict not enforced"),
       (CM, "and p[\"artifact\"] == od and p[\"args_digest\"] == dd and p[\"iss\"] != requester", "and True", "review approval not bound to op+diff"),
       (CM, "if A == R: return \"NONE\"", "if False: return \"NONE\"", "severity: equal diffs not NONE"),
       (CM, "if not extra: return \"LOW\"", "if False: return \"LOW\"", "severity: missing changes not LOW"),
       (CM, "if auto_rollback and out.get(\"_backup\"):", "if False:", "no automatic rollback"),
       (CM, "return {\"verified\": not again, \"residual_changes\": len(again)}", "return {\"verified\": True, \"residual_changes\": 0}", "rollback verification faked"),
       (SCN, "snap[\"db\"] = K.receipt(\"db\", world.db); snap[\"fs\"]", "pass; snap[\"fs\"]", "oracle baseline not re-taken after the race")]


def main():
    surv, ran = [], 0
    for f, a, b, why in MUT:
        d = tempfile.mkdtemp(prefix="p41m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target")); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        r = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "tests.p41.test_counterfactual"], cwd=t, capture_output=True, text=True, timeout=900)
        print(("KILLED  " if r.returncode else "SURVIVED"), why)
        if not r.returncode: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
