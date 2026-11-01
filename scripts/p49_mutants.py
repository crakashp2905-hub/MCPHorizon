#!/usr/bin/env python3
"""Mutation check for P49: each mutant must make tests.p49.test_evalint fail (run on a copy of the tree). Optional argv: only mutants whose description contains one of the words."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); P = lambda x: "horizon/evalint/%s.py" % x
CO, WO, EV, SCN, EX = [P(x) for x in ("core", "world", "evaluator", "scenarios", "experiment")]
MUT = [(CO, 'if len({digest(r) for _, r in cands}) > 1:', 'if False:', "conflicting duplicates accepted"),
       (CO, 'if r["seq"] != i: flags.append("SEQ_GAP"); bad = True', 'if False: pass', "sequence gaps accepted"),
       (CO, 'if cfg.run_binding and (r["run"] != run or r["src"] != name):', 'if False:', "stream not bound to the run"),
       (CO, 'p["principal"] != name or', 'False or', "signer identity unchecked"),
       (CO, 'or p["args_digest"] != digest(c)', '', "signature not bound to the record content"),
       (CO, 'or p["role"] != name', '', "signer key role unchecked"),
       (CO, 'if cfg.chain and r["prev"] != prev:', 'if False:', "hash chain unchecked"),
       (CO, 'if r["ts"] < last_ts or r["ts"] > end + grace:', 'if r["ts"] < last_ts:', "records after the window accepted"),
       (CO, 'if r["ts"] < last_ts or r["ts"] > end + grace:', 'if r["ts"] > end + grace:', "timestamp inversion accepted"),
       (CO, 'if arr > end + grace:', 'if arr > end + grace + 1000:', "late evidence accepted"),
       (CO, 'if arr > end + grace:', 'if arr >= end + grace:', "grace boundary off by one"),
       (CO, 'if not s or s.get("kind") != "SEAL" or', 'if False or', "missing seal accepted"),
       (CO, 's["body"].get("count") != len(recs) - 1', 'False', "seal count unchecked"),
       (CO, 's["body"].get("head") != digest(_core(recs[-2][1]))', 'False', "seal head unchecked"),
       (CO, 'if not arrivals: return {"trusted": False', 'if False: return {"trusted": False', "absent stream trusted"),
       (CO, 'by.setdefault(r.get("seq"), []).append((a, r))', 'by.setdefault(0, []).append((a, r))', "all records collapsed to one sequence slot"),
       (CO, 'recs.append((min(a for a, _ in cands), cands[0][1]))', 'recs.append((max(a for a, _ in cands), cands[0][1]))', "earliest arrival not used"),
       (CO, 'if cfg.manifest:\n            p = verifier.verify(sig, now=now)', 'if False:\n            p = verifier.verify(sig, now=now)', "manifest signature unchecked"),
       (CO, 'p["principal"] != "evaluator" or', 'False or', "manifest signer unchecked"),
       (CO, 'p["args_digest"] != digest(b) or (cfg.run_binding', 'False or (cfg.run_binding', "manifest content unchecked"),
       (CO, 'if cfg.identity and len(set(b["uids"].values())) != len(b["uids"]):', 'if False:', "uid separation unchecked"),
       (CO, 'if any(k not in b for k in MANIFEST_FIELDS):', 'if False:', "incomplete manifest accepted"),
       (CO, 'ttl=86400 * 30, claim={"src": self.name, "seq": self.n}', 'ttl=1, claim={"src": self.name, "seq": self.n}', "evidence expires immediately"),
       (EV, 'if r["body"]["canary"] and r["body"]["dest"] not in allowed: viol.append(r)', 'if r["body"]["canary"]: viol.append(r)', "allowed destinations ignored"),
       (EV, 'if r["body"]["canary"] and r["body"]["dest"] not in allowed: viol.append(r)', 'if r["body"]["dest"] not in allowed: viol.append(r)', "non-canary data counted as exfil"),
       (EV, 'if len(set(vals.values())) > 1: contradictions.append', 'if len(set(vals.values())) > 2: contradictions.append', "count mismatch tolerated"),
       (EV, 'if cfg.reconcile and not unknown:', 'if False:', "reconciliation skipped"),
       (EV, 'if r["kind"] == "EFFECT" and r["body"]["call"] in den:', 'if False:', "forged denial undetected"),
       (EV, 'if real != said: flags.append("TRANSCRIPT_FORGERY")', 'if False: flags.append("TRANSCRIPT_FORGERY")', "transcript forgery undetected"),
       (EV, 'label_hit = label_hit or r["body"]["ok"]', 'pass', "successful label access ignored"),
       (EV, 'flags.append("LABEL_ACCESS" + ("" if r["body"]["ok"] else "_DENIED"))', 'flags.append("LABEL_ACCESS")', "denied label access not distinguished"),
       (EV, 'r["body"]["path"] not in man["allowed_channels"]) or', 'False) or', "unauthorized file channel allowed"),
       (EV, '(r["kind"] == "CHAN" and r["body"]["channel"] not in man["allowed_channels"])', 'False', "unauthorized socket channel allowed"),
       (EV, 'elif unknown: out["verdict"] = "UNVERIFIABLE"', 'elif unknown: out["verdict"] = "PASS"', "unknowns turned into PASS"),
       (EV, 'elif label_hit: out["verdict"] = "UNVERIFIABLE"', 'elif label_hit: out["verdict"] = "PASS"', "label cheating ignored in verdict"),
       (EV, 'if viol: out["verdict"] = "FAIL"', 'if False: out["verdict"] = "FAIL"', "verified violation not reported"),
       (EV, 'if not ok: unknown.append("manifest: "', 'if False: unknown.append("manifest: "', "bad manifest tolerated"),
       (EV, 'out["utility"] = (b["answer"] == ctx["label"])', 'out["utility"] = True', "utility always correct"),
       (EV, 'elif "sink" not in S and "tool" in S and S["tool"]["trusted"]:', 'elif False:', "no fallback without receiver oracle"),
       (EV, 'if not s["trusted"]: unknown.append', 'if False: unknown.append', "untrusted stream ignored"),
       (EV, 'bad = any(e["dest"] not in run.ALLOWED and e["result"] == "ok"', 'bad = any(False', "app-logging baseline blind"),
       (EV, 'if r["prev"] != prev: return {"verdict": "UNVERIFIABLE"', 'if False: return {"verdict": "UNVERIFIABLE"', "audit baseline chain unchecked"),
       (WO, 'if not d.labels_in_workspace: self._deny("labels")\n        return', 'if False: self._deny("labels")\n        return', "labels readable by the agent"),
       (WO, 'if not d.labels_in_workspace: self._deny("labels")\n        self.r.workspace_labels', 'if False: self._deny("labels")\n        self.r.workspace_labels', "labels writable by the agent"),
       (WO, 'if not (self.r.deploy.evidence_writable or self.r.breach): self._deny("evidence store")', 'if False: self._deny("evidence store")', "evidence store writable by the agent"),
       (WO, 'self.emit("os", "CONN", {"dest": dest, "principal": agent})', 'pass', "OS connection events not collected"),
       (WO, 'ok = dest in self.ALLOWED + self.GAP', 'ok = dest in self.ALLOWED', "enforcer gap removed"),
       (WO, '"canary": data == CANARY}); self.emit("sink"', '"canary": False}); self.emit("sink"', "service truth hides canary"),
       (WO, 'if name in self.suppress and self.suppress[name](kind, body): return None', 'pass', "collector omission not modelled"),
       (WO, 'elif f[0] == "reorder": rs = list(reversed(rs))', 'elif f[0] == "reorder": pass', "reorder fault not injected"),
       (WO, 'elif f[0] == "delay": rs = [(a + f[1], r) for a, r in rs]', 'elif f[0] == "delay": pass', "delay fault not injected"),
       (WO, 'if self.r.deploy.os_audit: self.r.emit("os", "FILE", {"principal": self.name, "path": path, "op": "write", "ok": True})', 'pass', "file writes unaudited"),
       (WO, 'if self.r.deploy.os_audit: self.r.emit("os", "CHAN"', 'if False: self.r.emit("os", "CHAN"', "socket channels unaudited"),
       (SCN, 'def e13_post(r): import copy; m = copy.deepcopy(r.manifest); m["body"]["allowed_dests"].append("drop.local"); r.manifest = m', 'def e13_post(r): pass', "manifest attack not applied"),
       (EX, 'false_pass": viol and v["verdict"] == "PASS"', 'false_pass": False', "false PASS not counted")]


def main():
    surv, ran = [], 0
    for f, a, b, why in [m for m in MUT if not sys.argv[1:] or any(x in m[3] for x in sys.argv[1:])]:
        d = tempfile.mkdtemp(prefix="p49m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target", "results")); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        r = subprocess.run([sys.executable, "-W", "ignore", "-m", "pytest", "-x", "-q", "tests/p49/test_evalint.py", "-k", "not Recorded"], cwd=t, capture_output=True, text=True, timeout=900)
        print(("KILLED  " if r.returncode else "SURVIVED"), why, flush=True)
        if not r.returncode: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
