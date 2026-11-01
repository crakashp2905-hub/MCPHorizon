#!/usr/bin/env python3
"""Mutation check for P50: each mutant must make tests.p50.test_budget fail (run on a copy of the tree). Optional argv: only mutants whose description contains one of the words."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); P = lambda x: "horizon/budget/%s.py" % x
UN, LE, BR, SI, EX = [P(x) for x in ("units", "ledger", "broker", "sinks", "experiment")]
MUT = [(UN, 'n < 0 or n > MAX_UNITS: raise CostError("BAD_UNITS")', 'n > MAX_UNITS: raise CostError("BAD_UNITS")', "negative cost accepted"),
       (UN, 'isinstance(n, bool) or not isinstance(n, int) or n < 0', 'not isinstance(n, int) or n < 0', "boolean cost accepted"),
       (UN, 'or not isinstance(n, int) or n < 0 or n > MAX_UNITS: raise CostError("BAD_UNITS")', 'or n < 0 or n > MAX_UNITS: raise CostError("BAD_UNITS")', "fractional cost accepted"),
       (UN, 'or any(k not in CLASSES for k in l)', 'or False', "unknown class in limits"),
       (UN, 'or v < 0 or v > MAX_UNITS for v in l.values()', 'or v > MAX_UNITS for v in l.values()', "negative limit accepted"),
       (UN, 'if t is None: raise CostError("UNKNOWN_TOOL")', 'if t is None: return {}', "unknown tool is free"),
       (LE, 'if self.signed and p["role"] != self.owner_role: raise', 'if False: raise', "any role may assign a budget"),
       (LE, 'if c.get("rev") != self.policy["rev"]: raise', 'if False: raise', "budget for another policy revision accepted"),
       (LE, 'p["object_version"] <= old[0]', 'p["object_version"] < old[0]', "budget version may repeat"),
       (LE, 'or p["args_digest"] != U.digest(c): raise', ': raise', "budget digest unchecked"),
       (LE, 'c.get("type") != "budget" or', 'False or', "budget type unchecked"),
       (LE, 'if self.bind_principal and principal != s["principal"]:', 'if False:', "scope principal unchecked"),
       (LE, 'if row[0] != qdigest or row[2] != scope: return', 'if False: return', "request id reuse accepted"),
       (LE, 'if row[1] in ("EXPIRED", "RELEASED"): return', 'if False: return', "expired reservation replayed"),
       (LE, 'snap.get(k, 0) + v > n["cap"].get(k, 0)', 'snap.get(k, 0) + v >= n["cap"].get(k, 0)', "cap boundary strict"),
       (LE, 'snap.get(k, 0) + v > n["cap"].get(k, 0)', 'snap.get(k, 0) + v > n["cap"].get(k, 0) + 1', "cap boundary loose"),
       (LE, 'if v > 0 and snap.get(k, 0)', 'if snap.get(k, 0)', "zero-cost classes checked"),
       (LE, 'new = "EXPIRED" if st == "RESERVED" else ("UNKNOWN" if self.conservative else "RELEASED")', 'new = "EXPIRED"', "started timeout refunded"),
       (LE, 'WHERE state IN (\'RESERVED\',\'STARTED\') AND t0+ttl<?', 'WHERE state IN (\'RESERVED\',\'STARTED\') AND t0+ttl<=?', "expiry boundary"),
       (LE, 'CHARGED = ("RESERVED", "STARTED", "COMMITTED", "UNKNOWN", "HELD")', 'CHARGED = ("RESERVED", "STARTED", "COMMITTED", "HELD")', "unknown reservations not charged"),
       (LE, 'CHARGED = ("RESERVED", "STARTED", "COMMITTED", "UNKNOWN", "HELD")', 'CHARGED = ("STARTED", "COMMITTED", "UNKNOWN", "HELD")', "reserved not charged"),
       (LE, 'CHARGED = ("RESERVED", "STARTED", "COMMITTED", "UNKNOWN", "HELD")', 'CHARGED = ("RESERVED", "STARTED", "COMMITTED", "UNKNOWN")', "transfer hold not charged"),
       (LE, 'if r is None or r[0] != "RESERVED": return {"ok": False, "reason": "NOT_REFUNDABLE"', 'if r is None: return {"ok": False, "reason": "NOT_REFUNDABLE"', "started reservation refundable"),
       (LE, 'if r is None or r[0] != "RESERVED": return {"ok": False, "reason": "NOT_RESERVED"', 'if r is None: return {"ok": False, "reason": "NOT_RESERVED"', "double start"),
       (LE, 'if r is None or r[0] not in ("STARTED", "UNKNOWN"): return {"ok": False, "reason": "NOT_STARTED", "state"', 'if r is None: return {"ok": False, "reason": "NOT_STARTED", "state"', "commit without start"),
       (LE, 'UPDATE res SET state=\'COMMITTED\', charge=?, observed=?, overrun=?', 'UPDATE res SET state=\'COMMITTED\', charge=?, observed=?, overrun=?', None),
       (LE, 'json.dumps(obs), json.dumps(obs), json.dumps(over), rid)', 'json.dumps(reserved), json.dumps(obs), json.dumps(over), rid)', "commit charges the reservation not the observation"),
       (LE, 'over = {k: v - reserved.get(k, 0) for k, v in obs.items() if v > reserved.get(k, 0)}', 'over = {}', "overrun not recorded"),
       (LE, 'if observed is None: return {"ok": True', 'if False: return {"ok": True', "unreachable receiver refunds"),
       (LE, 'if all(v == 0 for v in observed.values()):', 'if any(v == 0 for v in observed.values()):', "partial zero refunds"),
       (LE, 'while self.ancestors and s["mode"] == "attenuate" and s["parent"]:', 'while False:', "ancestors ignored"),
       (LE, 'cap = {k: min(v, p["cap"].get(k, 0)) for k, v in caps.items()} if self.attenuate else dict(caps)', 'cap = dict(caps)', "child cap not clamped"),
       (LE, 'bad = self._over(p, caps, exclude_hold=None)', 'bad = []', "transfer exceeds parent"),
       (LE, 'if any(modes.get("/".join(segs[:i])) == "transfer" for i in range(k0 + 1, len(segs) + 1)): continue', 'pass', "transfer pool counted twice"),
       (LE, 'json.dumps({k: used.get(k, 0) for k in s["cap"]}), "hold:" + child)', 'json.dumps({k: 0 for k in s["cap"]}), "hold:" + child)', "closing a pool returns its used units"),
       (LE, 'if s is None or s["mode"] != "transfer": return {"ok": False, "reason": "NOT_TRANSFER"}', 'if s is None: return {"ok": False, "reason": "NOT_TRANSFER"}', "close of attenuated scope"),
       (LE, 'if self._scope(child) is not None: return {"ok": False, "reason": "SCOPE_EXISTS"}', 'if False: return {"ok": False, "reason": "SCOPE_EXISTS"}', "scope overwritten"),
       (LE, 'prev = (self.db.execute("SELECT hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone() or ("genesis",))[0]; b', 'prev = "genesis"; b', "audit chain not linked"),
       (LE, 'if p != prev or h != hashlib.sha256((prev + b).encode()).hexdigest(): return False', 'if p != prev: return False', "audit body not hashed"),
       (LE, 'self.db.execute("BEGIN IMMEDIATE")', 'self.db.execute("BEGIN")', "deferred transaction"),
       (BR, 'if not isinstance(rid, str) or not rid: return', 'if False: return', "missing request id accepted"),
       (BR, 'max_units=cost if self.sink_cap else None', 'max_units=None', "sink cap off"),
       (BR, 'c = self.led.commit(rid, r["observed"] if self.reconcile_charge else cost)', 'c = self.led.commit(rid, cost)', "charge ignores observation"),
       (BR, 'if res.get("replayed") and res["state"] == "COMMITTED": return', 'if False: return', "replay re-executes"),
       (BR, 'if res["state"] == "RESERVED":', 'if True:', "replayed request restarted"),
       (BR, 'if d is None or not isinstance(d[0], dict): return', 'if d is None: return', "context type unchecked"),
       (BR, 'if ps is None or (self.led.bind_principal and ps["principal"] != parent_principal): return', 'if False: return', "spawn by non-owner"),
       (BR, 'return self.led.reconcile(rid, self.rc.observe(rid))', 'return self.led.reconcile(rid, self.rc.observe(rid) or {})', "silent receiver refunds"),
       (BR, 'if carrier == "utcp": t = msg', 'if carrier == "utcp": t = msg', None),
       (SI, 'if self.idempotent and rid in self.by_rid:', 'if False:', "receiver not idempotent"),
       (SI, 'if max_units is not None: n = min(n, max_units.get(cls, 0))', 'pass', "receiver cap ignored"),
       (SI, 'if rid in self.crash_after:', 'if False:', "response loss not simulated"),
       (SI, 'if args.get("expand"): n *= 50', 'pass', "hidden fan-out not simulated"),
       (SI, 'return None if self.silent else', 'return', "telemetry outage not simulated"),
       (EX, '"over": over, "excess": sum(o["total"] - o["cap"] for o in over)', '"over": [], "excess": 0', "oracle blind"),
       ]
MUT = [m for m in MUT if m[3]]


def main():
    surv, ran = [], 0
    for f, a, b, why in [m for m in MUT if not sys.argv[1:] or any(x in m[3] for x in sys.argv[1:])]:
        d = tempfile.mkdtemp(prefix="p50m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target", "results")); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        try: r = subprocess.run([sys.executable, "-W", "ignore", "-m", "pytest", "-x", "-q", "tests/p50/test_budget.py", "-k", "not Recorded"], cwd=t, capture_output=True, text=True, timeout=240)
        except subprocess.TimeoutExpired: r = subprocess.CompletedProcess([], 124, "", "timeout")          # a mutant that makes the suite hang (lock deadlock) is detected
        print(("KILLED  " if r.returncode else "SURVIVED"), why, flush=True)
        if not r.returncode: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
