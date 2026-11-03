"""ENG-PR04 mutation check. Timeout counts as killed."""
import subprocess, sys, os
G = "horizon/effects/ledger.py"
M = [('if row[0] != "AUTHORIZED": return False', 'if False: return False'),
     ('if to not in NEXT[row[0]]: raise', 'if False: raise'),
     ('if self.db.execute("select 1 from nonces where nonce=?", (nonce,)).fetchone(): return False', 'pass'),
     ('"STARTED": {"COMMITTED", "BLOCKED", "UNKNOWN"}', '"STARTED": {"COMMITTED", "BLOCKED", "UNKNOWN", "AUTHORIZED"}'),
     ('"UNKNOWN": {"RECONCILED_COMMITTED", "RECONCILED_BLOCKED"}', '"UNKNOWN": {"RECONCILED_COMMITTED", "RECONCILED_BLOCKED", "COMMITTED"}'),
     ('"COMMITTED": set()', '"COMMITTED": {"STARTED"}'),
     ("where state='STARTED'", "where state='AUTHORIZED'"),
     ('self._move(i, "UNKNOWN"', 'self._move(i, "BLOCKED"'),
     ('if self.db.execute("select 1 from effects where effect_id=?", (effect_id,)).fetchone(): return False', 'pass'),
     ('if outcome not in ("COMMITTED", "BLOCKED", "UNKNOWN"): raise', 'if False: raise'),
     ('self.db.execute("rollback"); raise', 'raise'),
     ('"RECONCILED_COMMITTED" if sink_says_committed else "RECONCILED_BLOCKED"', '"RECONCILED_COMMITTED"')]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.e04.test_ledger"], capture_output=True, timeout=90, env=env).returncode
    except subprocess.TimeoutExpired: return 1
src = open(G).read(); assert run() == 0; surv = []
try:
    for a, b in M:
        if a not in src: surv.append(("MISSING", a)); continue
        open(G, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", a))
finally: open(G, "w").write(src)
print(f"{len(M)-len(surv)}/{len(M)} killed"); [print(*x) for x in surv]; sys.exit(1 if surv else 0)
