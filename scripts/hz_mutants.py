"""HorizonZero registry mutation check. Timeout counts as killed."""
import subprocess, sys, os
G = "horizon/assurance/registry.py"
M = [('if claim_id in self.invalid: return "REVOKED"', 'if False: return "REVOKED"'), ('if self.clock() >= c.expires_at', 'if self.clock() > c.expires_at'), ('if epoch_now > c.epoch', 'if epoch_now > c.epoch + 1'),
     ('if c is None: return "REVOKED", "unknown_claim"', 'if c is None: return "VALID", ""'), ('if dep_id in seen: return "cycle"', 'if False: return "cycle"'),
     ('if dep_id in self.invalid: return self.invalid[dep_id]', 'if False: return "x"'), ('            for d, dg in c.digests:\n                if d in self.nodes and self.nodes[d] != dg: return f"digest_changed:{d}"', '            for d, dg in ():\n                if d in self.nodes and self.nodes[d] != dg: return f"digest_changed:{d}"'),
     ('if set(c.depends_on) != {d for d, _ in c.digests}: raise', 'if False: raise'), ('if not c.depends_on or not c.scope: raise', 'if False: raise'), ('if c.claim_id in self.claims: raise', 'if False: raise'),
     ('if committed_by_sink_journal and witness_claim_valid: return "VERIFIED_COMMITTED"', 'if committed_by_sink_journal: return "VERIFIED_COMMITTED"'), ('return "NOT_OBSERVED" if witness_claim_valid else "UNKNOWN"', 'return "NOT_OBSERVED"'),
     ('if committed_by_sink_journal is None: return "UNKNOWN"', 'pass'), ('json.dumps([self.claim_id, self.scope, self.epoch, self.expires_at, self.depends_on, self.digests]', 'json.dumps([self.claim_id, self.scope, self.epoch, self.expires_at, self.depends_on]')]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.hz.test_registry"], capture_output=True, timeout=60, env=env).returncode
    except subprocess.TimeoutExpired: return 1
src = open(G).read(); assert run() == 0; surv = []
try:
    for a, b in M:
        if a not in src: surv.append(("MISSING", a)); continue
        open(G, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", a))
finally: open(G, "w").write(src)
print(f"{len(M)-len(surv)}/{len(M)} killed"); [print(*x) for x in surv]; sys.exit(1 if surv else 0)
