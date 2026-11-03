"""HorizonSpectra toy mutation check. Timeout counts as killed."""
import subprocess, sys, os
G = "research/spectra/tomography.py"
M = [('if sink in self.sinks: self.rows.append', 'self.rows.append'), ('extra = seen - frozenset(declared.get(p, ()))', 'extra = frozenset()'),
     ('if not alive: return "UNKNOWN"', 'if False: return "UNKNOWN"'), ('{s for h in alive for s in h.get(p, ())} - instrumented', 'set()'),
     ('if b["left"] <= 0: return "UNKNOWN"', 'if False: return "UNKNOWN"'), ('if budget["left"] <= 0: raise', 'if False: raise'),
     ('alive = consistent(alive, p, seen, instrumented)', 'pass'), ('return (-len(groups), max', 'return (len(groups), -max'),
     ('& instrumented == seen]', '== seen]')]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.spectra.test_tomography"], capture_output=True, timeout=60, env=env).returncode
    except subprocess.TimeoutExpired: return 1
src = open(G).read(); assert run() == 0; surv = []
try:
    for a, b in M:
        if a not in src: surv.append(("MISSING", a)); continue
        open(G, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", a))
finally: open(G, "w").write(src)
print(f"{len(M)-len(surv)}/{len(M)} killed"); [print(*x) for x in surv]; sys.exit(1 if surv else 0)
