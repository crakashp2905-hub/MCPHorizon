"""Real-data evaluator mutation check. Timeout counts as killed."""
import subprocess, sys, os
F = "bench/real/agentdojo.py"
M = [(F, 'return tool.startswith(EFFECT_PREFIXES) or tool in EGRESS_TOOLS', 'return tool.startswith(EFFECT_PREFIXES)'),
     (F, 'if len(rel) != 5:', 'if len(rel) != 6:'),
     (F, 'if len(n) >= 6 and n in inj and n not in up:', 'if len(n) >= 6 and n in inj:'),
     (F, 'and tok in inj and tok not in up):', 'and tok in inj):'),
     (F, 'if r.attack == "none" and r.utility and not r.error:', 'if r.attack == "none" and not r.error:'),
     (F, 'if mm != m:', 'if True:'),
     (F, 'if token_only and re.search(r"\\s", leaf.strip()):', 'if False:'),
     (F, 'if len(n) >= 4 and n not in up:', 'if len(n) >= 4 and n in up:'),
     (F, 'if r.error:\n            meta["errors_excluded"] += 1\n            continue', 'if False:\n            continue'),
     (F, '"attack_caught_lower_bound": _rate(\n                    b["caught"], b["attacks"] + b["unlabelled"]),', '"attack_caught_lower_bound": _rate(\n                    b["caught"], b["attacks"]),'),
     (F, 'if n == 0:\n        return (0.0, 1.0)', 'if n == 0:\n        return (0.0, 0.0)'),
     (F, 'return call[0] not in allowed', 'return call[0] in allowed'),
     (F, 'if len(n) >= 4 and n not in up and n not in seen:', 'if len(n) >= 4 and n not in up:'),
     (F, 'if mm != m:\n                    u |= vals', 'if True:\n                    u |= vals'),
     (F, 'elif (not is_attack) and r.utility:', 'elif (not is_attack):')]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.real.test_agentdojo"], capture_output=True, timeout=120, env=env).returncode
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
