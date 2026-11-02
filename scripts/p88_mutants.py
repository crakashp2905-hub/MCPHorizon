#!/usr/bin/env python3
"""P88 approval broker mutation check: each mutant must make tests/p88 fail. Baseline must pass first. Files restored afterwards."""
import subprocess, sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); os.chdir(ROOT)
M = [
 ('horizon/approvalui/broker.py', 'if p is None or p["state"] != "NEEDS_APPROVAL"', 'if p is None'),
 ('horizon/approvalui/broker.py', 'if principal in self.agents: return "REJECT", "agents cannot approve"', 'pass'),
 ('horizon/approvalui/broker.py', 'self.approvers[principal] != session', 'False'),
 ('horizon/approvalui/broker.py', 'if origin not in self.origins: return', 'if False: return'),
 ('horizon/approvalui/broker.py', 'if self.csrf.pop(csrf, None) != principal', 'if False'),
 ('horizon/approvalui/broker.py', 'if self.clock() >= p["exp"]: return "REJECT"', 'if False: return "REJECT"'),
 ('horizon/approvalui/broker.py', 'if p["rev"] != self.rev: return "REJECT"', 'if False: return "REJECT"'),
 ('horizon/approvalui/broker.py', 'p["state"] = "APPROVED" if approve else "DENIED"', 'p["state"] = "NEEDS_APPROVAL"'),
 ('horizon/approvalui/broker.py', 'if not approve: return "DENIED", ""', 'pass'),
 ('horizon/approvalui/broker.py', 'if not hmac.compare_digest(token.get("sig", ""), self._sign(rec))', 'if False'),
 ('horizon/approvalui/broker.py', 'if rec["rid"] in self.revoked', 'if False'),
 ('horizon/approvalui/broker.py', 'if rec["rid"] in self.used', 'if False'),
 ('horizon/approvalui/broker.py', 'if self.clock() >= rec["exp"]: return "DENIED"', 'if False: return "DENIED"'),
 ('horizon/approvalui/broker.py', 'if rec["rev"] != self.rev: return "DENIED"', 'if False: return "DENIED"'),
 ('horizon/approvalui/broker.py', 'if op_digest(op) != rec["digest"]', 'if False'),
 ('horizon/approvalui/broker.py', 'if dest != rec["dest"]', 'if False'),
 ('horizon/approvalui/broker.py', 'self.used.add(rec["rid"]); return', 'return'),
 ('horizon/approvalui/broker.py', 'sort_keys=True, separators', 'sort_keys=False, separators'),
 ('horizon/approvalui/broker.py', '+ [str(v) for v in op.get("args", {}).values()]', ''),
 ('horizon/approvalui/broker.py', '[str(op["target"])] +', '[] +'),
 ('horizon/approvalui/broker.py', 'if token is None: return "UNKNOWN"', 'if token is None: return "APPROVED" if ui_state == "approved" else "UNKNOWN"'),
 ('horizon/approvalui/broker.py', 'ui_state == "approved" and token', 'ui_state == "approved"'),
 ('horizon/approvalui/broker.py', 'if seq in r["seen"]: return "DUPLICATE"', 'pass'),
 ('horizon/approvalui/broker.py', 'if r["closed"]: return "AFTER_CLOSE"', 'pass'),
 ('horizon/approvalui/broker.py', 'if seq != r["next"]: return "GAP_OR_REORDER"', 'pass'),
 ('horizon/approvalui/broker.py', 'if kind in ("CANCELLED", "DONE"): r["closed"] = kind', 'pass'),
 ('horizon/approvalui/broker.py', 'return "COMPLETE" if r["closed"] == "DONE" else', 'return "COMPLETE" if r["closed"] else'),
 ('horizon/approvalui/broker.py', 'if r is None: return "UNKNOWN"', 'if r is None: return "INCOMPLETE"'),
 ('horizon/approvalui/broker.py', '"%s on %s with %s" % (op["tool"], op["target"], args or "no arguments")', '"%s on %s with %s" % (op["tool"], op["target"], args or "")'),
 ('horizon/approvalui/broker.py', 'for k in sorted(op.get("args", {}))', 'for k in list(op.get("args", {}))[:1]'),
]
def run():
    try: return subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/p88"], capture_output=True, timeout=60, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1")).returncode
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
