"""HorizonForge slice mutation check. Timeout counts as killed."""
import subprocess, sys, os
M = [("horizon/forge/checker.py", 'if protected and leaves and plan.form == "raw":', 'if False:'),
     ("horizon/forge/checker.py", 'if plan.form == "aggregate" and not task.aggregate_ok:', 'if False:'),
     ("horizon/forge/checker.py", 'if not set(plan.controls) <= set(task.available_controls)', 'if False'),
     ("horizon/forge/checker.py", 'not in plan.controls: v.append("LOCAL_SANDBOX_NOT_INSTALLED")', 'in plan.controls: v.append("LOCAL_SANDBOX_NOT_INSTALLED")'),
     ("horizon/forge/checker.py", 'if "enclave_attestation" not in plan.controls:', 'if False:'),
     ("horizon/forge/checker.py", 'task.remote_trust == "contracted" and "egress_contract_enforcer" in plan.controls', 'task.remote_trust == "contracted" or "egress_contract_enforcer" in plan.controls'),
     ("horizon/forge/checker.py", 'task.need_effect_witness and plan.placement != "local_sandbox" and not plan.witnesses', 'False'),
     ("horizon/forge/checker.py", 'return ["UNKNOWN_PLAN_VALUE"]', 'pass'),
     ("horizon/forge/checker.py", 'protected = task.data_label != "PUBLIC"', 'protected = True'),
     ("horizon/forge/synth.py", 'key=lambda p: (p.cost(), utility_loss(task, p), repr(p))', 'key=lambda p: (-p.cost(), utility_loss(task, p), repr(p))'),
     ("horizon/forge/synth.py", 'if checker.check(task, naive) else', 'if True else'),
     ("horizon/forge/synth.py", 'cert["bounds"]["plans_enumerated"] != len(plans) or', 'False or'),
     ("horizon/forge/synth.py", 'ref[repr(p)] and ref[repr(p)] == checker.violations(task, p)', 'True'),
     ("horizon/forge/synth.py", 'ref[repr(p)] and ref[repr(p)] == checker.violations(task, p)', 'ref[repr(p)]'),
     ("horizon/forge/worlds.py", 'a.violates != b.violates and observe', 'observe'),
     ("horizon/forge/worlds.py", 'observe(a, v) == observe(b, v)', 'True'),
     ("horizon/forge/worlds.py", '{a.name, b.name} == {cert["safe"], cert["leak"]} and', ''),
     ("horizon/forge/worlds.py", 'if cert is None: return False', 'pass')]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.hf.test_forge"], capture_output=True, timeout=60, env=env).returncode
    except subprocess.TimeoutExpired: return 1
assert run() == 0; surv = []
for f, a, b in M:
    src = open(f).read()
    if a not in src: surv.append(("MISSING", a)); continue
    try:
        open(f, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", a))
    finally: open(f, "w").write(src)
print(f"{len(M)-len(surv)}/{len(M)} killed"); [print(*x) for x in surv]; sys.exit(1 if surv else 0)
