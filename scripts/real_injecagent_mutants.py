"""InjecAgent evaluator mutation check (timeout == killed)."""
import subprocess, sys, os
F = "bench/real/injecagent.py"
M = [(F, 'if len(tok) >= 4 and IDENT.search(tok):', 'if len(tok) >= 2 and IDENT.search(tok):'),
     (F, 'IDENT = re.compile(r"[@./_\\-0-9]")', 'IDENT = re.compile(r"[@]")'),
     (F, 'tok = re.sub(r"^https?://", "", tok.strip(".,;:()[]\'\\"!?"))', 'tok = tok'),
     (F, 'return any(t not in up for t in ident_tokens(case["Attacker Instruction"]))', 'return any(t in up for t in ident_tokens(case["Attacker Instruction"]))'),
     (F, 'return any(t not in up for v in user_param_values(case) for t in ident_tokens(v))', 'return False'),
     (F, 'up = str(case["User Instruction"]).lower()\n    return any(t not in up for t in', 'up = str(case["User Instruction"])\n    return any(t not in up for t in'),
     (F, '[str(v) for v in d.values() if isinstance(v, (int, float))]', '[]'),
     (F, 'except (ValueError, SyntaxError):\n        return []', 'except (ValueError, SyntaxError):\n        raise'),
     (F, 'same = sum(1 for c in rows if c["User Tool"] in c["Attacker Tools"])', 'same = 0'),
     (F, '"ds_base": "test_cases_ds_base.json",', '"ds_base": "test_cases_dh_base.json",')]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.real.test_injecagent"], capture_output=True, timeout=120, env=env).returncode
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
