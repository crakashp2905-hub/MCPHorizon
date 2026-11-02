#!/usr/bin/env python3
"""P78-P82 campaign mutation check: each mutant must make tests/p84x fail. Baseline must pass first. Files restored afterwards."""
import subprocess, sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); os.chdir(ROOT)
M = [
 ('orchestrator/campaign.py', 'if kind in ("security_violation", "tamper", "forged_approval")', 'if False'),
 ('orchestrator/campaign.py', 'status == 429: return "rate_limited"', 'status == 428: return "rate_limited"'),
 ('orchestrator/campaign.py', '500 <= status < 600', '500 < status < 600'),
 ('orchestrator/campaign.py', 'or attempt >= max_attempts: return None', 'or attempt > max_attempts: return None'),
 ('orchestrator/campaign.py', 'back = min(cap, base * (2 ** attempt))', 'back = min(cap, base * (attempt + 1))'),
 ('orchestrator/campaign.py', 'back = max(back, float(retry_after))', 'back = back'),
 ('orchestrator/campaign.py', '(0.5 + 0.5 * r.random())', '1.0'),
 ('orchestrator/campaign.py', 'if self.clock() - self.opened >= self.cd', 'if self.clock() - self.opened > self.cd'),
 ('orchestrator/campaign.py', 'if self.probing: return False', 'pass'),
 ('orchestrator/campaign.py', 'def success(self): self.fails = 0;', 'def success(self):'),
 ('orchestrator/campaign.py', 'if t["status"] != "PENDING": continue', 'pass'),
 ('orchestrator/campaign.py', 'if any(d not in tasks for d in t.get("depends_on", [])): continue', 'pass'),
 ('orchestrator/campaign.py', 'and not rcr_signed: continue', 'and False: continue'),
 ('orchestrator/campaign.py', 'if t.get("external_dep") in set(breaker_open_deps): continue', 'pass'),
 ('orchestrator/campaign.py', 'if self.total + amount > self.pm or self.task.get(task, 0.0) + amount > self.tm', 'if self.total + amount > self.pm'),
 ('orchestrator/campaign.py', 'if amount < 0: raise ValueError("negative charge")', 'pass'),
 ('orchestrator/campaign.py', 'if task["data_class"] not in m["data_classes"]', 'if False'),
 ('orchestrator/campaign.py', 'if task["work_class"] not in m["task_classes"]', 'if False'),
 ('orchestrator/campaign.py', 'if failure_cls not in ("transient", "rate_limited")', 'if False'),
 ('orchestrator/campaign.py', 'if p != failed and provider_ok', 'if provider_ok'),
 ('orchestrator/campaign.py', 'a["used"] or self.clock() >= a["exp"]', 'self.clock() >= a["exp"]'),
 ('orchestrator/campaign.py', 'self.clock() >= a["exp"]: return False', 'self.clock() > a["exp"]: return False'),
 ('orchestrator/campaign.py', 'a["used"] = True; return True', 'return True'),
 ('orchestrator/campaign.py', 'if c.startswith("/") or ".." in c.split("/"): bad.append(c); continue', 'pass'),
 ('orchestrator/campaign.py', 'if any(c == p or c.startswith(p) for p in protected): bad.append(c); continue', 'pass'),
 ('orchestrator/campaign.py', '(a.endswith("/") and c.startswith(a))', '(c.startswith(a))'),
 ('orchestrator/campaign.py', '(x.endswith("/") and y.startswith(x)) or (y.endswith("/") and x.startswith(y))', '(y.startswith(x)) or (x.startswith(y))'),
 ('orchestrator/campaign.py', 'if evidence.get("synthetic")', 'if False'),
 ('orchestrator/campaign.py', 'if not evidence.get("party") or not evidence.get("signature")', 'if not evidence.get("party")'),
 ('orchestrator/campaign.py', 'if task_class != "EXTERNAL": return True, ""', 'pass'),
 ('orchestrator/campaign.py', 'if set(sinks_protected) - set(sinks_seen): return "UNKNOWN"', 'pass'),
 ('orchestrator/campaign.py', 'return "FAIL" if effects_observed else "PASS"', 'return "PASS"'),
 ('orchestrator/campaign.py', 'and results[key]["ok"] is False and ok is True', 'and False'),
 ('orchestrator/campaign.py', '"claimed_percent_complete": None', '"claimed_percent_complete": v / n if n else 0.0'),
 ('orchestrator/campaign.py', 'c.get(s, 0) for s in ("WAITING_EXTERNAL", "NEEDS_APPROVAL", "BLOCKED_SECURITY")', 'c.get(s, 0) for s in ("WAITING_EXTERNAL",)'),
]
def run():
    try: return subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/p84x"], capture_output=True, timeout=60, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1")).returncode
    except subprocess.TimeoutExpired: return 99  # hang counts as killed
if run() != 0: print("baseline fails"); sys.exit(2)
surv = []
for f, a, b in M:
    s = open(f).read()
    assert s.count(a) == 1, (f, a, s.count(a))
    open(f, "w").write(s.replace(a, b))
    try:
        if run() == 0: surv.append((f, a))
    finally: open(f, "w").write(s)
print("mutants %d, survivors %d" % (len(M), len(surv)))
for x in surv: print("SURVIVED", x)
sys.exit(1 if surv else 0)
