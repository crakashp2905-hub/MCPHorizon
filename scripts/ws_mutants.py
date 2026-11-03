"""Weight-space patch API mutation check. Timeout counts as killed."""
import subprocess, sys, os
G = "research/weightspace/patch.py"
M = [('if len(eds) > max_entries: raise', 'if False: raise'), ('if l2 > max_l2: raise', 'if False: raise'), ('not np.isfinite(v): raise', 'False: raise'),
     ('if t not in base or t not in allowed_tensors: raise', 'if t not in base: raise'), ('not (0 <= i < base[t].size)', 'not (0 <= i <= base[t].size)'),
     ('if (t, i) in seen: raise', 'if False: raise'), ('if proposal["base_digest"] != checkpoint_digest(base): raise', 'if False: raise'),
     ('cand = {k: v.copy() for k, v in base.items()}', 'cand = dict(base)'), ('(float(v) - float(base[t].flat[i])) ** 2', 'float(v) ** 2'),
     ('if not np.issubdtype(base[t].dtype, np.floating): raise', 'if False: raise'), ('if manifest(base, proposal, stats) != m: return False', 'pass'),
     ('if (t, int(i)) not in declared: return False', 'pass'), ('str(a.dtype).encode()', 'b""'), ('json.dumps(a.shape).encode()', 'b""'),
     ('if not isinstance(proposal["hypothesis"], str) or not proposal["hypothesis"].strip(): raise', 'if False: raise'),
     ('inv.append({"tensor": t, "index": i, "value": float(base[t].flat[i])})', 'inv.append({"tensor": t, "index": i, "value": v})')]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.ws.test_patch"], capture_output=True, timeout=60, env=env).returncode
    except subprocess.TimeoutExpired: return 1
src = open(G).read(); assert run() == 0; surv = []
try:
    for a, b in M:
        if a not in src: surv.append(("MISSING", a)); continue
        open(G, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", a))
finally: open(G, "w").write(src)
print(f"{len(M)-len(surv)}/{len(M)} killed"); [print(*x) for x in surv]; sys.exit(1 if surv else 0)
