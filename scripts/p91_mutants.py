#!/usr/bin/env python3
"""P91/P92 research design mutation check: each mutant must make tests/p91 fail. Baseline must pass first. Files restored afterwards."""
import subprocess, sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); os.chdir(ROOT)
M = [
 ('horizon/research/design.py', 'if miss: raise', 'if False: raise'),
 ('horizon/research/design.py', 'if not (0 < kw["alpha"] < 1)', 'if False'),
 ('horizon/research/design.py', 'if kw["direction"] not in ("greater", "less")', 'if False'),
 ('horizon/research/design.py', 'if self.data_seen and any(', 'if False and any('),
 ('horizon/research/design.py', '("primary_metric", "success_threshold", "direction", "unit", "alpha")', '("primary_metric",)'),
 ('horizon/research/design.py', 'n.parent = self.digest', 'n.parent = None'),
 ('horizon/research/design.py', 'if n == 0: return (0.0, 1.0)', 'pass'),
 ('horizon/research/design.py', 'd = 1 + z * z / n', 'd = 1'),
 ('horizon/research/design.py', 'c = p + z * z / (2 * n)', 'c = p'),
 ('horizon/research/design.py', 'while n < 10 ** 7', 'while n < 10'),
 ('horizon/research/design.py', 'if not (0 <= p <= 1 and 0 < hw < 1)', 'if False'),
 ('horizon/research/design.py', 'for c in (r.choice(keys) for _ in keys) for v in by[c]', 'for c in (r.choice(keys) for _ in keys) for v in by[c][:1]'),
 ('horizon/research/design.py', 'ms[int(reps * alpha / 2)]', 'ms[0]'),
 ('horizon/research/design.py', 'ms[int(reps * (1 - alpha / 2)) - 1]', 'ms[-1]'),
 ('horizon/research/design.py', 'pvals[k] <= alpha / (m - i)', 'pvals[k] <= alpha / m'),
 ('horizon/research/design.py', 'else: break', 'else: continue'),
 ('horizon/research/design.py', 'k = min(b, c)', 'k = max(b, c)'),
 ('horizon/research/design.py', 'min(1.0, 2 * p)', '2 * p'),
 ('horizon/research/design.py', 'if t & c: prob.append', 'if False: prob.append'),
 ('horizon/research/design.py', 'if tt & ct: prob.append', 'if False: prob.append'),
 ('horizon/research/design.py', 'if not executed_correctly: return "REVISE_EXECUTION"', 'pass'),
 ('horizon/research/design.py', '"GO" if lo >= threshold', '"GO" if lo > threshold'),
 ('horizon/research/design.py', '("STOP" if hi < threshold else "REVISE")', '("STOP" if hi <= threshold else "REVISE")'),
 ('horizon/research/design.py', '"GO" if hi <= threshold', '"GO" if hi < threshold'),
 ('horizon/research/design.py', '("STOP" if lo > threshold else "REVISE")', '("STOP" if lo >= threshold else "REVISE")'),
 ('horizon/research/design.py', 'if verifier_reserve > cap: raise', 'if False: raise'),
 ('horizon/research/design.py', 'self.spent + amt > self.cap - self.reserve or', 'self.spent + amt > self.cap or'),
 ('horizon/research/design.py', 'self.by_task.get(task, 0.0) + amt > self.tc', 'False'),
 ('horizon/research/design.py', 'if self.v_spent + amt > self.reserve', 'if False'),
 ('horizon/research/design.py', 'self.digest = H({"cap": cap, "reserve": verifier_reserve, "tc": task_ceiling})', 'self.digest = H({"cap": cap})'),
 ('horizon/research/design.py', 'if meter_total is None: return {"status": "UNKNOWN", "delta": None}', 'pass'),
 ('horizon/research/design.py', 'abs(d) <= tol * max(meter_total, 1e-9)', 'True'),
 ('horizon/research/design.py', '("UNDER_REPORTED" if d > 0 else "OVER_REPORTED")', '("OVER_REPORTED" if d > 0 else "UNDER_REPORTED")'),
 ('horizon/research/design.py', 'None if actual.get(k) is None else actual[k] - forecast[k]', 'actual.get(k, 0) - forecast[k]'),
]
def run():
    try: return subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/p91"], capture_output=True, timeout=60, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1")).returncode
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
