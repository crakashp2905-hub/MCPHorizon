"""ENG-PR03 mutation check. Timeout counts as killed."""
import subprocess, sys, os
G = "horizon/effects/canonical.py"
M = [('"session": self.session_id, ', ''), ('"server": self.server_id, ', ''),
     ('if self.effect not in E.EFFECTS: raise', 'if False: raise'), ('or "\\x00" in v: raise', ': raise'), ('not v or len(v) > 2048', 'False'),
     ('DOMAIN + body', 'body'), ('consume=consume)', 'consume=False)')]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.e03.test_commit_verify"], capture_output=True, timeout=60, env=env).returncode
    except subprocess.TimeoutExpired: return 1
src = open(G).read(); assert run() == 0; surv = []
try:
    for a, b in M:
        if a not in src: surv.append(("MISSING", a)); continue
        open(G, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", a))
finally: open(G, "w").write(src)
print(f"{len(M)-len(surv)}/{len(M)} killed"); [print(*x) for x in surv]; sys.exit(1 if surv else 0)
