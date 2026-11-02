#!/usr/bin/env python3
"""P89 skill policy mutation check: each mutant must make tests/p89 fail. Baseline must pass first. Files restored afterwards."""
import subprocess, sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); os.chdir(ROOT)
M = [
 ('horizon/skillpolicy/policy.py', 'if not isinstance(m, dict): raise', 'if False: raise'),
 ('horizon/skillpolicy/policy.py', 'if set(m) != need', 'if False'),
 ('horizon/skillpolicy/policy.py', 'NAME.match(m["name"])', 'True'),
 ('horizon/skillpolicy/policy.py', 'VER.match(m["version"])', 'True'),
 ('horizon/skillpolicy/policy.py', 'DIG.match(m["digest"])', 'True'),
 ('horizon/skillpolicy/policy.py', '0 < len(m["publisher"]) <= 64', 'True'),
 ('horizon/skillpolicy/policy.py', '0 < len(m["license"]) <= 64', 'True'),
 ('horizon/skillpolicy/policy.py', 'set(c) != set(CAPS)', 'False'),
 ('horizon/skillpolicy/policy.py', 'len(c[k]) <= 64', 'True'),
 ('horizon/skillpolicy/policy.py', '0 < len(x) <= 256', 'True'),
 ('horizon/skillpolicy/policy.py', 'len(d) > 128', 'False'),
 ('horizon/skillpolicy/policy.py', 'isinstance(x, str) and 0 < len(x) <= 128 for x in d', 'True for x in d'),
 ('horizon/skillpolicy/policy.py', '^[a-z][a-z0-9-]{0,63}$', '^[a-z][a-z0-9-]{0,64}$'),
 ('horizon/skillpolicy/policy.py', 'return H(canon(sorted((p, H(b)) for p, b in files.items())))', 'return H(canon(sorted(H(b) for p, b in files.items())))'),
 ('horizon/skillpolicy/policy.py', 'if self.latest_active(d) is None: raise', 'if False: raise'),
 ('horizon/skillpolicy/policy.py', 'if not verify_files(m, files): return', 'if False: return'),
 ('horizon/skillpolicy/policy.py', 'if e is None:', 'if False:'),
 ('horizon/skillpolicy/policy.py', 'if prev is not None:', 'if False:'),
 ('horizon/skillpolicy/policy.py', 'if x: return "NEEDS_REAPPROVAL"', 'if False: return "NEEDS_REAPPROVAL"'),
 ('horizon/skillpolicy/policy.py', 'if not hmac.compare_digest(e["sig"], self._sig(rec))', 'if False'),
 ('horizon/skillpolicy/policy.py', 'if self.state[(m["name"], m["version"])] != "ACTIVE"', 'if False'),
 ('horizon/skillpolicy/policy.py', 'if e["digest"] != m["digest"] or e["caps"] != m["caps"]', 'if e["digest"] != m["digest"]'),
 ('horizon/skillpolicy/policy.py', 'for v in reversed(self.history.get(name, []))', 'for v in self.history.get(name, [])'),
 ('horizon/skillpolicy/policy.py', 'if self.state.get((name, v)) == "ACTIVE"', 'if True'),
 ('horizon/skillpolicy/policy.py', 'self.state[(name, version)] = "QUARANTINED"', 'pass'),
 ('horizon/skillpolicy/policy.py', 'self.state[(name, version)] = "REVOKED"', 'pass'),
 ('horizon/skillpolicy/policy.py', '(curl|wget)[^\\n|]*\\|\\s*(sudo\\s+)?(ba)?sh', '(curl)[^\\n|]*\\|\\s*(sudo\\s+)?(ba)?sh'),
 ('horizon/skillpolicy/policy.py', '|eval\\s*\\$\\(\\s*(curl|wget)', '|eval\\s*\\$\\(\\s*(curl)'),
 ('horizon/skillpolicy/policy.py', 'pip\\s+install\\s+(--index-url|-i)\\s', 'pip\\s+install\\s+(--index-url)\\s'),
 ('horizon/skillpolicy/policy.py', 'if asked - allowed: out["ignored_widening"][k] = sorted(asked - allowed)', 'pass'),
 ('horizon/skillpolicy/policy.py', 'sorted(allowed & asked) if k in doc_claims else sorted(allowed)', 'sorted(asked) if k in doc_claims else sorted(allowed)'),
 ('horizon/skillpolicy/policy.py', 'for k in CAPS if set(new["caps"][k]) - set(old["caps"][k])}', 'for k in CAPS}'),
]
def run():
    try: return subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/p89"], capture_output=True, timeout=60, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1")).returncode
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
