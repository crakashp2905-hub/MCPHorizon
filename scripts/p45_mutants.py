#!/usr/bin/env python3
"""Mutation check for P45: each mutant must make tests.p45.test_privacy fail (run on a copy of the tree)."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); P = lambda x: "horizon/privacy/%s.py" % x
MX, AC, RF, LG, SV, CA, BL, SC, UN = [P(x) for x in ("mechanisms", "accountant", "reference", "ledger", "service", "carriers", "baselines", "scenarios", "units")]
MUT = [(MX, 'alpha = math.exp(-eps / sens)', 'alpha = math.exp(-eps)', "noise ignores sensitivity"),
       (MX, 'return geometric(st.u(), alpha) - geometric(st.u(), alpha)', 'return geometric(st.u(), alpha)', "one-sided noise"),
       (MX, 'if not (0 < eps < 1): raise ValueError', 'if False: raise ValueError', "Gaussian calibration outside its validity range"),
       (MX, 'return sens * math.sqrt(2.0 * math.log(1.25 / delta)) / eps', 'return sens * math.sqrt(2.0 * math.log(1.25 / delta)) / eps / 2', "Gaussian sigma too small"),
       (MX, 'return float(c["eps"]) ** 2 / 2.0', 'return float(c["eps"]) / 2.0', "Laplace zCDP cost wrong"),
       (MX, '("horizon.privacy.noise\\x00%s\\x00%s" % (request_id, label))', '("horizon.privacy.noise\\x00%s" % label)', "noise not keyed by request id"),
       (AC, 'return se <= _F(b["eps"]) and sd <= _F(b["delta"]), {"eps"', 'return se < _F(b["eps"]) and sd <= _F(b["delta"]), {"eps"', "basic: boundary refused"),
       (AC, 'return se <= _F(b["eps"]) and sd <= _F(b["delta"]), {"eps"', 'return se <= _F(b["eps"]), {"eps"', "basic: delta ignored"),
       (AC, 'def _F(x): return Fraction(str(x))', 'def _F(x): return Fraction(float(x))', "basic: inexact arithmetic"),
       (AC, 'adv = A + math.sqrt(2.0 * B * math.log(1.0 / dt))', 'adv = A + math.sqrt(B * math.log(1.0 / dt))', "advanced: bound too small"),
       (AC, 'if prod <= 1.0 - db: return ok_b', 'if False: return ok_b', "advanced: inadmissible delta not handled"),
       (AC, 'return ok_b or adv * (1.0 + MARGIN) <= eb', 'return adv * (1.0 + MARGIN) <= eb', "advanced: basic branch dropped"),
       (AC, 'eps = rho + 2.0 * math.sqrt(rho * math.log(1.0 / db))', 'eps = rho + math.sqrt(rho * math.log(1.0 / db))', "zcdp: conversion too small"),
       (AC, 'return eps * (1.0 + MARGIN) <= float(_F(b["eps"]))', 'return eps <= float(_F(b["eps"]))', "zcdp: safety margin removed"),
       (AC, 'if db <= 0.0: raise Unsupported', 'if False: raise Unsupported', "zcdp: delta=0 accepted"),
       (RF, 'elif e["op"] == "refund": live.pop(e["id"], None)', 'elif e["op"] == "refund": pass', "reference ignores refunds"),
       (RF, 'rho += (D(x["eps"]) ** 2 / 2) if', 'rho += (D(x["eps"]) / 2) if', "reference: wrong Laplace rho"),
       (LG, 'if old and p["object_version"] <= old[0]: raise EvidenceError', 'if False: raise EvidenceError', "budget rollback accepted"),
       (LG, 'if p["artifact"] != lid or str(c["eps"]) != r[2]', 'if p["artifact"] != lid', "budget row tampering undetected"),
       (LG, 'if p["args_digest"] != digest(c) or c.get("accountant") not in AC.ACCOUNTANTS: raise', 'if False: raise', "budget digest unchecked"),
       (LG, 'if row[0] != qdigest: return {"ok": False, "reason": "REQUEST_ID_REUSE"}', 'if False: pass', "request id reuse with another query allowed"),
       (LG, 'if not ok: self._log({"op": "deny", "ledger": lid, "req": request_id, "why": "BUDGET_EXCEEDED"}); return', 'if False: return', "budget not enforced"),
       (LG, 'if not AC.fits(b["accountant"], {"eps": a[0], "delta": a[1]}, own)[0]:', 'if False:', "allocation not enforced"),
       (LG, 'self.db.execute("BEGIN IMMEDIATE")\n        try: r = fn(); self.db.execute("COMMIT"); return r\n        except BaseException: self.db.execute("ROLLBACK"); raise\n    def _log', 'return fn()\n    def _log', "reservation not transactional"),
       (LG, 'if s == "STARTED": self.db.execute("UPDATE res SET state=\'ABANDONED\'', 'if s == "STARTED" and False: self.db.execute("UPDATE res SET state=\'ABANDONED\'', "cancel after start leaves entry unmarked"),
       (LG, "AND state='RESERVED' AND t_reserved+ttl<?", "AND state IN ('RESERVED','STARTED') AND t_reserved+ttl<?", "started requests expire into refunds"),
       (LG, "state IN ('RESERVED','STARTED','COMMITTED','ABANDONED') \" + where", "state IN ('STARTED','COMMITTED','ABANDONED') \" + where", "reserved requests not counted"),
       (LG, 'if s == "RESERVED": self.db.execute("UPDATE res SET state=\'CANCELLED\'', 'if s in ("RESERVED", "COMMITTED"): self.db.execute("UPDATE res SET state=\'CANCELLED\'', "committed answers refundable"),
       (LG, 'if p != prev or hashlib.sha256((p + b).encode()).hexdigest() != h: return False', 'if p != prev: return False', "hash chain content unchecked"),
       (LG, 'elif e["op"] == "cancel": implied[r] = "CANCELLED" if e.get("refund") else "ABANDONED"', 'elif e["op"] == "cancel": implied[r] = "CANCELLED"', "audit ignores abandoned"),
       (LG, 'if s == "COMMITTED": r = self.db.execute("SELECT answer,receipt', 'if s == "COMMITTED" and False: r = self.db.execute("SELECT answer,receipt', "commit not idempotent"),
       (SV, 'if self.derive_ledger and ctx is not None and ctx.get("ledger") not in (None, U.ledger_id(d.name)): return', 'if False: return', "caller-chosen ledger accepted"),
       (SV, 'if self.declared_bounds and q.get("bounds") is not None and tuple(q["bounds"]) != tuple(d.bounds[q["column"]]): return', 'if False: return', "caller bounds accepted"),
       (SV, 'if d.name not in p["dp"]: return self._deny("NOT_AUTHORIZED_DP")', 'pass', "DP access unchecked"),
       (SV, 'if d.name not in p["raw"] or q.get("purpose") not in p["purposes"]: return', 'if d.name not in p["raw"]: return', "purpose unchecked for raw"),
       (SV, 'if self.min_cell_on and len(rows) < d.min_cell:', 'if False:', "minimum cell count off"),
       (SV, 'if 0 < delta_n < d.min_cell: return', 'if 0 < delta_n < 1: return', "differencing guard weakened"),
       (SV, 'or ap["principal"] != principal', 'or False', "export approval not bound to principal"),
       (SV, 'or ap["args_digest"] != LG.digest({"op": "export", "dataset": dataset, "purpose": purpose}):', ':', "export approval digest (dataset, purpose) unchecked"),
       (SV, 'return CAP * max(abs(lo), abs(hi))', 'return CAP * abs(hi - lo) // 2', "sum sensitivity halved"),
       (SV, 'self.signer.sign(b"privacy.receipt.v1\\x00" + body)', 'self.signer.sign(body)', "receipt domain separation removed"),
       (CA, 'if len(ctx["chain"]) >= MAX_DEPTH: raise', 'if False: raise', "delegation depth unlimited"),
       (BL, 'if d is not None and d.public: return self._noacct(principal, q, ctx)', 'pass', "per-agent baseline counts public queries"),
       (SC, 'seen.setdefault((q["request_id"], a), (q, a))', 'seen.setdefault(q["request_id"], (q, a))', "oracle merges different answers for one id"),
       (SC, 'a = r.get("answer") if r.get("status") == "OK" else r.get("leaked_answer") if r.get("status") == "TIMEOUT" else None', 'a = r.get("answer") if r.get("status") == "OK" else None', "oracle ignores leaked answers"),
       (SC, 'eps_eff = float(q["eps"]) * true_s / used if used else float("inf")', 'eps_eff = float(q["eps"])', "oracle ignores under-scaled noise"),
       (UN, 'return "led:" + hashlib.sha256(("horizon.privacy.ledger\\x00%s\\x00%s" % (dataset, unit)).encode()).hexdigest()[:24]', 'return "led:" + hashlib.sha256(("horizon.privacy.ledger\\x00%s" % dataset).encode()).hexdigest()[:24]', "ledger id ignores the privacy unit")]


def main():
    surv, ran = [], 0
    for f, a, b, why in MUT:
        d = tempfile.mkdtemp(prefix="p45m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target")); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        r = subprocess.run([sys.executable, "-W", "ignore", "-m", "pytest", "-x", "-q", "tests/p45/test_privacy.py", "-k", "not Recorded"], cwd=t, capture_output=True, text=True, timeout=900)
        print(("KILLED  " if r.returncode else "SURVIVED"), why, flush=True)
        if not r.returncode: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
