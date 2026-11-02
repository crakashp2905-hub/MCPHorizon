#!/usr/bin/env python3
"""P87 delegation mutation check: each mutant must make tests/p87 fail. Baseline must pass first. Files restored afterwards."""
import subprocess, sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); os.chdir(ROOT)
M = [
 ('horizon/a2a/delegation.py', 'if not set(scope) <= set(parent["scope"]): raise', 'if False: raise'),
 ('horizon/a2a/delegation.py', 'if exp > parent["exp"]: raise', 'if False: raise'),
 ('horizon/a2a/delegation.py', '"depth": parent["depth"] + 1', '"depth": parent["depth"]'),
 ('horizon/a2a/delegation.py', '"tenant": parent["tenant"]', '"tenant": "t1"'),
 ('horizon/a2a/delegation.py', 'if len(chain) > max_depth + 1', 'if False'),
 ('horizon/a2a/delegation.py', 'if set(g) != set(FIELDS) | {"sig"}', 'if False'),
 ('horizon/a2a/delegation.py', 'if not hmac.compare_digest(g["sig"], self._sig(g))', 'if False'),
 ('horizon/a2a/delegation.py', 'if g["jti"] in self.revoked', 'if False'),
 ('horizon/a2a/delegation.py', 'if self.clock() >= g["exp"]', 'if self.clock() > g["exp"]'),
 ('horizon/a2a/delegation.py', 'if g["tenant"] != tenant', 'if False'),
 ('horizon/a2a/delegation.py', 'if g["depth"] != i', 'if False'),
 ('horizon/a2a/delegation.py', 'if g["parent"] is not None: return False, "root has parent"', 'pass'),
 ('horizon/a2a/delegation.py', 'if g["parent"] != self.digest(prev)', 'if False'),
 ('horizon/a2a/delegation.py', 'if g["issuer"] != prev["subject"]', 'if False'),
 ('horizon/a2a/delegation.py', 'if not set(g["scope"]) <= set(prev["scope"])', 'if False'),
 ('horizon/a2a/delegation.py', 'if g["exp"] > prev["exp"]', 'if False'),
 ('horizon/a2a/delegation.py', 'if prev["audience"] != verifier', 'if False'),
 ('horizon/a2a/delegation.py', 'if op not in prev["scope"]', 'if False'),
 ('horizon/a2a/delegation.py', 'if prev["jti"] in self.seen', 'if False'),
 ('horizon/a2a/delegation.py', 'self.seen.add(prev["jti"])', 'pass'),
 ('horizon/a2a/delegation.py', 'if consume:', 'if True:'),
 ('horizon/a2a/delegation.py', 'return url in tenant_dests.get(tenant, ())', 'return True'),
 ('horizon/a2a/delegation.py', '[:64]', '[:640]'),
 ('horizon/a2a/delegation.py', '[:2000]', '[:20000]'),
 ('horizon/a2a/delegation.py', '"trusted": False', '"trusted": True'),
 ('horizon/a2a/delegation.py', 'if not action_protected: return True', 'pass'),
 ('horizon/a2a/delegation.py', 'bool(artifact.get("provenance_verified")) and', 'True and'),
 ('horizon/a2a/delegation.py', 'artifact.get("origin_tenant") == artifact.get("tenant") and', 'True and'),
 ('horizon/a2a/delegation.py', 'not artifact.get("untrusted_instructions", True)', 'True'),
 ('horizon/a2a/delegation.py', 'if k in self.done: return', 'if False: return'),
 ('horizon/a2a/delegation.py', 'self.done[k] = effect(); return self.done[k], True', 'return effect(), True'),
 ('horizon/a2a/delegation.py', 'k = (run, step)', 'k = (step,)'),
 ('horizon/a2a/delegation.py', '"parent": self.digest(parent)}', '"parent": None}'),
 ('horizon/a2a/delegation.py', '"issuer": parent["subject"]', '"issuer": parent["issuer"]'),
]
def run():
    try: return subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/p87"], capture_output=True, timeout=60, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1")).returncode
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
