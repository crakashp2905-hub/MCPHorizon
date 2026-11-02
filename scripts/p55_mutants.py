#!/usr/bin/env python3
"""P55/57/59 product primitives mutation check: each mutant must make tests/p55 fail. Baseline must pass first. Files restored afterwards."""
import subprocess, sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); os.chdir(ROOT)
M = [
 ('horizon/product/core.py', 'if mandatory_path and name not in self.reviewed', 'if False'),
 ('horizon/product/core.py', 'if not supported: return "UNSUPPORTED"', 'pass'),
 ('horizon/product/core.py', 'if independently_verified and implemented and documented', 'if independently_verified'),
 ('horizon/product/core.py', 'if implemented and documented: return "IMPLEMENTED"', 'if implemented: return "IMPLEMENTED"'),
 ('horizon/product/core.py', '"SUPPORTED" if r in set(tested)', '"SUPPORTED"'),
 ('horizon/product/core.py', 'SECRET.sub("[REDACTED]", str(detail))[:200]', 'str(detail)[:200]'),
 ('horizon/product/core.py', '[:200]', '[:2000]'),
 ('horizon/product/core.py', 'if code not in CODES: code = "E_INTERNAL"', 'pass'),
 ('horizon/product/core.py', '|AKIA[0-9A-Z]{8,}', ''),
 ('horizon/product/core.py', '|password\\s*[=:]\\s*\\S+', ''),
 ('horizon/product/core.py', '|TEST_CANARY_NOT_SECRET', ''),
 ('horizon/product/core.py', '|bearer\\s+[A-Za-z0-9._-]{8,}', ''),
 ('horizon/product/core.py', 'if mode not in ("audit", "enforce"): raise', 'if False: raise'),
 ('horizon/product/core.py', 'if mode == "audit": return {"allow": True', 'if False: return {"allow": True'),
 ('horizon/product/core.py', 'if not pep_present or pdp_result is None', 'if pdp_result is None'),
 ('horizon/product/core.py', 'pdp_result == "ALLOW"', 'pdp_result != "DENY"'),
 ('horizon/product/core.py', 'if not attempted: raise', 'if False: raise'),
 ('horizon/product/core.py', 'if sink_observed_commit is True: return', 'if False: return'),
 ('horizon/product/core.py', 'and sink_observed_commit is False: return', 'and True: return'),
 ('horizon/product/core.py', '"UNKNOWN" if sink_observed_commit is None else "ATTEMPTED"', '"ATTEMPTED"'),
 ('horizon/product/core.py', 'any(k in ("prompt", "content", "body", "secret") for k in labels)', 'False'),
 ('horizon/product/core.py', 'if not self.export_enabled: return None', 'pass'),
]
def run():
    try: return subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/p55"], capture_output=True, timeout=60, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1")).returncode
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
