"""Independent verifier (candidate for P85). Runs the acceptance command itself; never trusts worker claims."""
from __future__ import annotations
import hashlib, subprocess
from .ledger import sign

ALLOWED_PROGRAMS = {"python3", "python", "pytest"}


def run_acceptance(ledger_plan_digest: str, task: str, epoch: int, git_sha: str, argv: list[str],
                   cwd: str, verifier_id: str, key: bytes, timeout: int = 600) -> tuple[dict, str]:
    """Execute argv (no shell) in cwd, which MUST be a checkout of git_sha prepared by the verifier."""
    if not argv or argv[0] not in ALLOWED_PROGRAMS:
        raise ValueError("acceptance command program not in verifier allowlist")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=cwd, capture_output=True, text=True).stdout.strip()
    if head != git_sha:
        raise ValueError(f"checkout HEAD {head[:12]} != submitted sha {git_sha[:12]}")
    if subprocess.run(["git", "status", "--porcelain"], cwd=cwd, capture_output=True, text=True).stdout.strip():
        raise ValueError("verifier checkout is dirty")
    try:
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        code, out = p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        code, out = 124, "TIMEOUT"
    receipt = {"task": task, "verifier": verifier_id, "git_sha": git_sha, "epoch": epoch, "plan": ledger_plan_digest,
               "cmd": argv, "exit_code": code, "report_hash": hashlib.sha256(out.encode()).hexdigest()}
    return receipt, sign(key, receipt)
