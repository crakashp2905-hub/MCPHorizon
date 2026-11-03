"""Defended-run comparison mutation check (timeout == killed)."""
import subprocess, sys, os
F = "bench/real/defended_runs.py"
M = [(F, 'if pipeline.endswith("-" + d):', 'if pipeline.endswith(d):'),
     (F, 'return pipeline[: -len(d) - 1], d', 'return pipeline[: -len(d)], d'),
     (F, 'if r.error:\n            continue', 'if False:\n            continue'),
     (F, 'if r.attack == attack:', 'if r.attack != "none":'),
     (F, 'elif r.attack == "none":', 'elif False:'),
     (F, 'if r["defense"] == "none" or n is None:', 'if r["defense"] == "none":'),
     (F, 'r["asr"]["rate"] - n["asr"]["rate"]', 'n["asr"]["rate"] - r["asr"]["rate"]'),
     (F, 'r["utility_under_attack"]["rate"] - n["utility_under_attack"]["rate"]', 'r["utility_under_attack"]["rate"]'),
     (F, 'if r["utility_clean"] and n["utility_clean"] else None', 'if r["utility_clean"] and n["utility_clean"] else 0'),
     (F, 'a[0] += r["asr"]["k"]; a[1] += r["asr"]["n"]', 'a[0] += r["asr"]["k"]; a[1] += r["asr"]["k"]'),
     (F, 'a[6] += 1', 'a[6] += 2'),
     (F, 'if not att:\n            continue', 'if False:\n            continue')]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.real.test_defended"], capture_output=True, timeout=120, env=env).returncode
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
