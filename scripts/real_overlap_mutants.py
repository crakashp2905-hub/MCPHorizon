"""Overlap checker mutation check (timeout == killed)."""
import subprocess, sys, os
F = "bench/real/overlap.py"
M = [(F, 'MIN = 60', 'MIN = 5'), (F, 'if len(n) >= MIN:', 'if len(n) > MIN + 100:'),
     (F, 'return re.sub(r"\\s+", " ", s).strip().lower()', 'return s'),
     (F, 'k = len(ha & hb)', 'k = len(ha | hb)'), (F, 'if k:\n            res.append', 'if k > 1:\n            res.append'),
     (F, 'key=lambda x: -x["shared_strings"]', 'key=lambda x: x["shared_strings"]'),
     (F, 'k / min(len(ha), len(hb))', 'k / max(len(ha), len(hb))'),
     (F, 'if rel.startswith(SKIP_DIRS) or', 'if False or'),
     (F, 'for leaf in A.string_leaves(r if not isinstance(r, str) else [r]):', 'for leaf in []:')]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.real.test_overlap"], capture_output=True, timeout=120, env=env).returncode
    except subprocess.TimeoutExpired: return 1
assert run() == 0; surv = []
for f, a, b in M:
    src = open(f).read()
    if a not in src: surv.append(("MISSING", f, a)); continue
    try:
        open(f, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", f, a))
    finally: open(f, "w").write(src)
print(f"{len(M)-len(surv)}/{len(M)} killed"); [print(*x) for x in surv]; sys.exit(1 if surv else 0)
