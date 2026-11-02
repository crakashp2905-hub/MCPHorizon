#!/usr/bin/env python3
"""CI verifier: runs spec/acceptance.json commands on a clean checkout and writes receipts.json.
Provenance comes from a Sigstore attestation made by .github/workflows/verify.yml, not from a shared secret.
Receipts are produced by the CI job identity — a different principal from the coding worker."""
import hashlib, json, subprocess, sys, os, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
if subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip():
    raise SystemExit("dirty checkout; refusing to verify")
lock = json.loads((ROOT / "spec/plan.lock").read_text()); acc = json.loads((ROOT / "spec/acceptance.json").read_text())
# Commands that exercise kernel sandboxing (chown, uid drop, /var/lib/hz-runs) need root, exactly as in tests.yml. The allowlist
# still applies to the ORIGINAL command (python3 only); only the privilege wrapper is added, and only for these module families.
ROOT_MODULES = ("tests.p24.", "tests.p25.", "tests.p26.", "tests.p27.", "tests.p28.", "tests.p29.", "tests.p30.", "tests.p33.", "tests.p34.", "tests.p35.", "tests.p37.", "tests.p38.", "tests.p42.", "scripts/security_gate.py", "scripts/p42_release_gate.py", "scripts/p38_runner_check.py")
def needs_root(cmd): return any(m in " ".join(cmd) for m in ROOT_MODULES)
cache, receipts = {}, []
for task, spec in acc.items():
    if task.startswith("_"): continue
    code, hashes = 0, []
    for cmd in spec["cmds"]:
        if cmd[0] not in ("python3",): raise SystemExit(f"command not allowed: {cmd}")
        key = tuple(cmd)
        if key not in cache:
            run_cmd = (["sudo", "-E", "env", "PATH=" + os.environ.get("PATH", "")] + cmd) if needs_root(cmd) and os.geteuid() != 0 else cmd
            t0 = time.time(); p = subprocess.run(run_cmd, cwd=ROOT, capture_output=True, text=True, timeout=1800)
            cache[key] = (p.returncode, hashlib.sha256((p.stdout + p.stderr).encode()).hexdigest(), round(time.time() - t0, 1))
            print(f"$ {' '.join(cmd)} -> exit {p.returncode}", flush=True)
            if p.returncode: print((p.stdout + p.stderr)[-2000:])
        rc, h, _ = cache[key]; code = code or rc; hashes.append(h)
    receipts.append({"task": task, "git_sha": sha, "plan_digest": lock["plan_digest_sha256"], "cmds": spec["cmds"],
                     "exit_code": code, "report_hashes": hashes, "covers": spec["covers"],
                     "verifier": "github-actions:verify.yml", "run_id": os.environ.get("GITHUB_RUN_ID"),
                     "result": "PASS" if code == 0 else "FAIL"})
out = ROOT / "receipts"; out.mkdir(exist_ok=True)
(out / "receipts.json").write_text(json.dumps({"git_sha": sha, "receipts": receipts}, indent=1, sort_keys=True))
print(f"{sum(r['result']=='PASS' for r in receipts)}/{len(receipts)} PASS at {sha}")
raise SystemExit(0 if all(r["result"] == "PASS" for r in receipts) else 1)
