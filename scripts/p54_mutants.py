#!/usr/bin/env python3
"""Mutation check for P54 (the temp dir is made world-readable because the Code Mode runner drops privileges and must read its own files): each mutant must make tests.p54 fail (run on a copy of the tree). Optional argv: only mutants whose description contains one of the words."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def ign(d, names):
    """Skip heavy dirs, but keep codemode/node_modules: the Code Mode path of the protocol-parity test needs it."""
    return [n for n in names if n in (".git", "__pycache__", "target") or (n == "node_modules" and os.path.basename(d) != "codemode")]
P = lambda x: "horizon/integration/%s.py" % x
AU, RC, RV, ST, PR, SM, TP, GT, MF, RP, RG = [P(x) for x in ("audit", "receipts", "review", "stats", "protocols", "statemachine", "tamper", "gates", "manifest", "reproduce", "registry")]
MUT = [(AU, 'if int(m.group(2)) <= maxphase: seen[m.group(1)] = int(m.group(2))', 'seen[m.group(1)] = int(m.group(2))', "spec ids not limited to P0..P38"),
       (AU, 'tot = sorted(i for i, q in ids.items() if q == p); m = [i for i in tot if i in acc]; b = [i for i in tot if i not in acc]', 'tot = sorted(i for i, q in ids.items() if q == p); m = tot; b = []', "unmapped tasks not blocked"),
       (AU, '"status": "COMPLETE-MAPPED" if not b else ("BLOCKED-PARTIAL" if m else "BLOCKED")', '"status": "COMPLETE-MAPPED" if not b else "BLOCKED-PARTIAL"', "empty phase called partial"),
       (AU, 'if not os.path.exists(p): d.append("missing " + f)', 'if not os.path.exists(p): pass', "missing frozen file ignored"),
       (AU, 'elif sha(open(p, "rb").read()) != h: d.append("modified " + f)', 'elif False: d.append("modified " + f)', "modified frozen file ignored"),
       (AU, 'if cur["task_ids"] != fr["task_ids"]: d.append("task_ids changed")', 'if False: d.append("task_ids changed")', "changed task id list ignored"),
       (AU, 'if d.startswith("p54"): continue', 'if False: continue', "freeze includes P54's own results"),
       (RC, 'if p["artifact"] != mid or p["claim"].get("m") != mid:', 'if False:', "receipt for another module accepted"),
       (RC, 'if p["claim"].get(k) != cur[k]: r.append', 'if False: r.append', "edited evidence not detected"),
       (RC, 'except EvidenceError as e: return {"module": mid, "verdict": "UNKNOWN", "reasons": ["RECEIPT_" + e.code]}', 'except EvidenceError as e: return {"module": mid, "verdict": "INTACT", "reasons": ["RECEIPT_" + e.code]}', "unverifiable receipt passes"),
       (RC, 'if token is None: return {"module": mid, "verdict": "UNKNOWN", "reasons": ["NO_RECEIPT"]}', 'if token is None: return {"module": mid, "verdict": "INTACT", "reasons": ["NO_RECEIPT"]}', "missing receipt passes"),
       (RC, '"orc": bundle_hash(m["oracle"]), "sys": bundle_hash(m["system"])}', '"orc": bundle_hash(m["oracle"]), "sys": bundle_hash([])}', "system files not bound"),
       (RC, '"orc": bundle_hash(m["oracle"]),', '"orc": bundle_hash([]),', "oracle files not bound"),
       (RC, 'if not ind["independent"]: return {"module": mid, "verdict": "INTACT", "reasons": ["ORACLE_REACHES_SYSTEM_CODE"], "caveat": True}', 'if False: pass', "independence caveat dropped"),
       (RC, 'self._iss = self.auth.register_issuer("receipts", {"ATTESTATION"})', 'self._iss = self.auth.register_issuer("receipts", {"ATTESTATION", "APPROVAL"})', "receipt issuer given extra kind"),
       (RV, 'if n.module: out.add(n.module.split(".")[0])', 'if False: out.add(n.module.split(".")[0])', "relative from-module imports ignored"),
       (RV, 'elif isinstance(n, ast.ImportFrom) and n.module and n.module.startswith("horizon.%s." % pkg): out.add(n.module.split(".")[2])', 'elif False: pass', "absolute package imports ignored"),
       (RV, 'todo += list(_imports(f, pkg) - seen)', 'pass', "transitive imports not followed"),
       (RV, 'return seen - {os.path.basename(rel)[:-3]}', 'return seen', "oracle counted as reaching itself"),
       (RV, '"independent": all(not x["reaches_system"] for x in rows)}', '"independent": True}', "independence always true"),
       (RV, '"fixture", "experiment.py": "fixture"', '"evidence-service", "experiment.py": "fixture"', "world files treated as evidence services"),
       (RV, 'ROLE.get(f, "other")', '"fixture"', "unlabelled authority sites hidden"),
       (RV, 'if k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True', 'if False', "shell=True not flagged"),
       (RV, '("os", "system"), ("os", "popen"),', '("os", "popen"),', "os.system not flagged"),
       (RV, 'DANGER = {"eval", "exec", "compile", "__import__"}', 'DANGER = {"exec", "compile", "__import__"}', "eval not flagged"),
       (ST, 'if a["k"] < a["n"]: out.append', 'if False: out.append', "unprevented attacks not reported"),
       (ST, 'if b["k"] < b["n"]: out.append', 'if False: out.append', "blocked benign runs not reported"),
       (ST, 'if not _has(src, needle): raise AssertionError', 'if False: raise AssertionError', "curated finding not checked against its source"),
       (ST, 'f["attack_k"] += r["attack_prevented"]["k"]', 'f["attack_k"] += r["attack_prevented"]["n"]', "family pooling counts every attack as prevented"),
       (ST, 'def ci(k, n): return None if not n else', 'def ci(k, n): return [0.0, 1.0] if not n else', "empty interval invented"),
       (PR, 'return {"workflows": len(wfs), "paths": list(PA.PATHS), "discrepancies": d,', 'return {"workflows": len(wfs), "paths": list(PA.PATHS), "discrepancies": [],', "parity discrepancies dropped"),
       (PR, 'return [d for d in p["discrepancies"] if (d["path"], d["cls"]) not in ex]', 'return []', "unexpected discrepancies hidden"),
       (PR, 'return [(n, F.equivalent(a, b)) for n, a, b in PA.non_equivalent_fixtures()]', 'return [(n, False) for n, a, b in PA.non_equivalent_fixtures()]', "non-equivalence fixtures not evaluated"),
       (PR, '"run_here": False', '"run_here": True', "browser adapter claimed as run"),
       (SM, 'sum(ok) == limit // each and led.invariants() == [] and led.verify_chain()', 'True', "budget concurrency not checked"),
       (SM, '"ok": sum(won) == 1 and a.obj("d")["version"] == 2 and not lost', '"ok": True', "CAS race not checked"),
       (SM, '"ok": lost == n - 1', '"ok": True', "last-writer-wins control not checked"),
       (SM, 'a["ok"] and b["ok"] and not other["ok"] and used.get("compute_units") == 30', 'True', "retry charging not checked"),
       (SM, '"ok": got == 8 and l2.verify_chain() and l2.audit(lid) == []', '"ok": True', "privacy concurrency not checked"),
       (SM, '"ok": not r["violations"] and r["replay_status"] not in (None, "MIGRATED")', '"ok": True', "replay not checked"),
       (TP, 'inside = [x for x in rows if x["kind"] != "boundary"]', 'inside = rows', "boundary case counted inside the assumptions"),
       (TP, 'if r["violation"] and sc["kind"] != "boundary": n += 1; f += r["false_pass"]', 'if False: n += 1; f += r["false_pass"]', "control graders not run"),
       (TP, 'out["other_authority"] = RC.verdict("P53", RC.ReceiptService().issue("P53"), v)', 'out["other_authority"] = out["intact"] if "intact" in out else RC.verdict("P53", tok, v)', "foreign authority case not tested"),
       (TP, 'return o["intact"]["verdict"] == "INTACT" and all(o[k]["verdict"] in ("TAMPERED", "UNKNOWN") for k in o if k != "intact")', 'return True', "receipt tamper result ignored"),
       (GT, 'st = "PASS" if all(checks.values()) else "FAIL"', 'st = "PASS" if any(checks.values()) else "FAIL"', "gate passes on any check"),
       (GT, '"no_signer_or_authority_created_outside_fixtures_and_evidence_services": not other', '"no_signer_or_authority_created_outside_fixtures_and_evidence_services": True', "ES-G2 ignores duplicate authority"),
       (GT, '"P39_oracle_independent_of_system_code": _ind(R, "P39")', '"P39_oracle_independent_of_system_code": True', "ES-G3 ignores oracle independence"),
       (GT, '"no_false_pass_within_assumptions": TP["evaluator"]["false_pass"] == 0', '"no_false_pass_within_assumptions": True', "ES-G14 ignores false passes"),
       (GT, '"weak_graders_do_false_pass_on_same_runs": all(v["false_pass"] > 0 for v in TP["evaluator_baselines"].values())', '"weak_graders_do_false_pass_on_same_runs": True', "ES-G14 control ignored"),
       (GT, '"freeze_matches_tree": R["freeze_diff"] == []', '"freeze_matches_tree": True', "ES-G1 ignores the freeze"),
       (GT, '"P44_unprevented_attacks_disclosed": any(n["module"] == "P44" for n in R["negative_findings"])', '"P44_unprevented_attacks_disclosed": True', "ES-G9 ignores disclosure"),
       (GT, '"every_module_has_baselines_or_ablations": all(R["has_baselines"].values())', '"every_module_has_baselines_or_ablations": True', "ES-G15 ignores baselines"),
       (MF, '"models": "none: no live model is used by any of P39..P54"', '"models": "gpt"', "model statement changed"),
       (RP, 'return {"module": mid, "level": "rerun", "ok": fresh == rec,', 'return {"module": mid, "level": "rerun", "ok": True,', "rerun result not compared"),
       (RP, 'if p.returncode: return {"module": mid, "level": "rerun", "ok": False,', 'if p.returncode: return {"module": mid, "level": "rerun", "ok": True,', "rerun failure ignored"),
       (RG, 'return dict(family="guard", system="runtime", attack_prevented=cnt(s["attacks_with_no_unsafe_commit"], s["attack_runs"])', 'return dict(family="guard", system="runtime", attack_prevented=cnt(s["attack_runs"], s["attack_runs"])', "P40 headline always full"),
       (RG, 'attack_prevented=cnt(a["n"] - a["k"], a["n"]), benign_completed=kn(s["benign_completed"]), notes=["benign blocked: "', 'attack_prevented=cnt(a["n"], a["n"]), benign_completed=kn(s["benign_completed"]), notes=["benign blocked: "', "P51 headline hides violations")]


def main():
    d = tempfile.mkdtemp(prefix="p54m-base-"); os.chmod(d, 0o755); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=ign)
    r = subprocess.run([sys.executable, "-W", "ignore", "-m", "pytest", "-x", "-q", "tests/p54", "-k", "not Recorded and not Docs", "-p", "no:cacheprovider"], cwd=t, capture_output=True, text=True, timeout=600); shutil.rmtree(d, ignore_errors=True)
    if r.returncode: print("BASELINE FAILS ON THE UNMUTATED COPY: a killed mutant would prove nothing\n" + (r.stdout + r.stderr)[-800:]); sys.exit(3)
    surv, ran = [], 0
    for f, a, b, why in [m for m in MUT if not sys.argv[1:] or any(x in m[3] for x in sys.argv[1:])]:
        d = tempfile.mkdtemp(prefix="p54m-"); os.chmod(d, 0o755); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=ign); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        try: r = subprocess.run([sys.executable, "-W", "ignore", "-m", "pytest", "-x", "-q", "tests/p54", "-k", "not Recorded and not Docs", "-p", "no:cacheprovider"], cwd=t, capture_output=True, text=True, timeout=300); rc = r.returncode
        except subprocess.TimeoutExpired: rc = 1
        print(("KILLED  " if rc else "SURVIVED"), why, flush=True)
        if not rc: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
