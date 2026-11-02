#!/usr/bin/env python3
"""P90 framework adapter mutation check: each mutant must make tests/p90 fail. Baseline must pass first. Files restored afterwards."""
import subprocess, sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); os.chdir(ROOT)
M = [
 ('horizon/frameworks/adapter.py', 'isinstance(ctx.get(k), str) and ctx[k]', 'True'),
 ('horizon/frameworks/adapter.py', 'return all(', 'return any('),
 ('horizon/frameworks/adapter.py', 'if claimed not in LEVELS: raise', 'if False: raise'),
 ('horizon/frameworks/adapter.py', 'ENFORCING = ("NATIVE", "BRIDGED")', 'ENFORCING = ("NATIVE",)'),
 ('horizon/frameworks/adapter.py', 'if actual != pinned: return', 'if False: return'),
 ('horizon/frameworks/adapter.py', 'if not conformance_passed: return', 'if False: return'),
 ('horizon/frameworks/adapter.py', 'and not os_protected_paths: return', 'and False: return'),
 ('horizon/frameworks/adapter.py', '("UNSUPPORTED" if claimed in ENFORCING else claimed)', '"UNSUPPORTED"'),
 ('horizon/frameworks/adapter.py', 'path in ("subprocess", "raw_network")', 'path in ("subprocess",)'),
 ('horizon/frameworks/adapter.py', 'key=lambda x: (x["framework"], x["version"], x["path"])', 'key=lambda x: x["path"]'),
 ('horizon/frameworks/adapter.py', 'if len(self.q) >= self.limit', 'if len(self.q) > self.limit'),
 ('horizon/frameworks/adapter.py', 'if not valid_call(call["ctx"])', 'if False'),
 ('horizon/frameworks/adapter.py', 'self.q = [c for c in self.q if c["ctx"]["tool_call"] != tool_call]', 'pass'),
 ('horizon/frameworks/adapter.py', 'self.cancelled.add(tool_call);', 'pass;'),
 ('horizon/frameworks/adapter.py', 'if tc in self.cancelled: return "CANCELLED"', 'pass'),
 ('horizon/frameworks/adapter.py', 'if key is not None and key in self.done', 'if False'),
 ('horizon/frameworks/adapter.py', 'if key is not None: self.done[key] = r', 'pass'),
 ('horizon/frameworks/adapter.py', 'if call.get("idempotency_key") is None: return', 'if False: return'),
 ('horizon/frameworks/adapter.py', 'c = self.q.pop(0)', 'c = self.q.pop()'),
]
def run():
    try: return subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/p90"], capture_output=True, timeout=60, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1")).returncode
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
