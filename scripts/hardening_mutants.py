"""Mutation check for scripts/hardening_inventory.py (timeout counts as killed)."""
import subprocess, sys, os
F = "scripts/hardening_inventory.py"
M = [("if m[\"status\"] in ABOVE_CANDIDATE and not m[\"independent_attestation\"]", "if False and not m[\"independent_attestation\"]"),
     ("if m[\"independent_attestation\"] and not m[\"reviewer_identity\"]", "if False"),
     ("if not t[\"evidence\"]:", "if False:"),
     ("elif t[\"evidence_digests\"].get(e) != digest(e)", "elif False"),
     ("if not os.path.isfile(full)", "if False"),
     ("if t[\"id\"].endswith(\"-GATE\") and not m[\"independent_attestation\"]", "if False"),
     ("if t[\"id\"] in seen:", "if False:"),
     ("if m[\"status\"] not in STATUSES", "if False"),
     ("done=bool(o.get(\"done\", False))", "done=bool(o.get(\"done\", t[\"doc_checked\"]))"),
     ("if task[\"id\"].endswith(\"-GATE\"): return \"EXTERNAL\"", "if False: return \"EXTERNAL\""),
     ("exists=os.path.exists(os.path.join(ROOT, q.rstrip(\"/\")))", "exists=True"),
     ("ABOVE_CANDIDATE = (\"INDEPENDENTLY_VERIFIED\", \"HARDENED_FOR_SCOPE\")", "ABOVE_CANDIDATE = (\"INDEPENDENTLY_VERIFIED\",)")]
def run():
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.hardening.test_inventory"], capture_output=True, timeout=120, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1")).returncode
    except subprocess.TimeoutExpired: return 1
assert run() == 0
surv = []
for a, b in M:
    src = open(F).read()
    if a not in src: surv.append(("MISSING", a)); continue
    try:
        open(F, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", a))
    finally: open(F, "w").write(src)
print(f"{len(M) - len(surv)}/{len(M)} killed"); [print(s) for s in surv]; sys.exit(1 if surv else 0)
