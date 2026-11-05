"""Mutation check for research/commitproof/model.py: a weakened model must be caught by tests (timeout counts as killed)."""
import subprocess, sys, os
F = "research/commitproof/model.py"
# EXCLUDED equivalent mutant: `if L == AUTH` guarding begin -> `if True` (the refused branch is unreachable in every design: only the authorizer reaches
# AUTHED and orphan expiry requires no AUTHED worker).  Documented, not hidden.
M = [('if fenced: out.append((f"w{i}.sink_write_refused(fenced)"', 'if False: out.append((f"w{i}.sink_write_refused(fenced)"'),
     ('nf = True if d["fenced"] else fenced', 'nf = fenced'),
     ('if L == LSTART and owner == i: out.append((f"w{i}.finish(COMMITTED)"', 'if owner == i: out.append((f"w{i}.finish(COMMITTED)"'),
     ('if d["recover"] == "timeout" or not owner_alive:', 'if True:'),
     ('if c > 1: bad.append("I1_at_most_one_sink_effect")', 'if c > 2: bad.append("I1_at_most_one_sink_effect")'),
     ('if c >= 1 and not used: bad.append', 'if False: bad.append'),
     ('if L in (COMMITTED, REC_C) and c != 1: bad.append', 'if False: bad.append'),
     ('if L in (BLOCKED, REC_B) and c != 0: bad.append', 'if False: bad.append'),
     ('REC_C if c >= 1 else REC_B', 'REC_C if c >= 2 else REC_B'),
     ('and not any(w == AUTHED for w in ws): out.append', 'and True: out.append'),
     ('if not succ and s[0] in (AUTH, LSTART, UNKNOWN) and', 'if False and'),
     ('        if bad: continue ', '        if False: continue '),
     ('if not used and L in (NONE, "REQUESTED"): out.append', 'if L in (NONE, "REQUESTED", AUTH): out.append'),
     ('if pc in (AUTHED, STARTED, WROTE): out.append((f"w{i}.CRASH"', 'if False: out.append((f"w{i}.CRASH"'),
     ('owner_alive = owner >= 0 and ws[owner] in (STARTED, WROTE, AUTHED)', 'owner_alive = False'),
     ('"retry_unknown=True"', '"retry_unknown=True"')]
M = [m for m in M if m[0] != m[1]]
def run():
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.commitproof.test_model"], capture_output=True, timeout=180, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1")).returncode
    except subprocess.TimeoutExpired: return 1
if run() != 0: print("BASELINE FAILED"); sys.exit(1)
surv = []
for a, b in M:
    src = open(F).read()
    if a not in src: surv.append(("MISSING", a)); continue
    try:
        open(F, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", a))
    finally: open(F, "w").write(src)
print(f"{len(M) - len(surv)}/{len(M)} killed"); [print(x) for x in surv]; sys.exit(1 if surv else 0)
