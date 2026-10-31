"""Independent verifier v2 (candidate for P85). Stdlib + git.

What it does: replays trusted acceptance commands in a CLEAN clone checked out at the exact submitted commit, with a scrubbed
environment, and derives the verdict ONLY from its own run — worker-supplied exit codes, logs and PASS claims are never inputs.
It flags worker edits to pre-existing oracle files (tests, graders, fixtures) and files that can change test behaviour.
It returns UNKNOWN when required protected-sink telemetry was not independently observed.
What it does NOT do: it is not a sandbox. Commands run as the verifier's OS user with process-level isolation only (no network or
filesystem namespace); a hostile test can still read what that user can read. See docs/security/VERIFIER_TRUST.md."""
from __future__ import annotations
import fnmatch, hashlib, hmac, json, os, shutil, subprocess, sys, tempfile, time
from pathlib import Path
from .recovery import scrub

ALLOWED_PROGRAMS = {"python3", "python", "pytest", "node", "npm", "cargo"}
SHADOW_NAMES = {"conftest.py", "sitecustomize.py", "usercustomize.py", "pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml", ".coveragerc"}
KEEP_ENV = ("PATH", "HOME_VERIFIER", "LANG", "LC_ALL", "TZ")


class VerifierError(Exception):
    pass


def canon(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def sha(b: bytes | str) -> str: return hashlib.sha256(b if isinstance(b, bytes) else b.encode()).hexdigest()


def safe_env(tmp_home: str) -> dict:
    """Minimal environment: no inherited credentials, tokens or proxy settings."""
    env = {k: os.environ[k] for k in KEEP_ENV if k in os.environ}
    env.update({"HOME": tmp_home, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0", "GIT_CONFIG_NOSYSTEM": "1"})
    return env


def git(args, cwd, check=True):
    p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, env={"PATH": os.environ["PATH"], "HOME": tempfile.gettempdir(), "GIT_CONFIG_NOSYSTEM": "1"})
    if check and p.returncode: raise VerifierError(f"git {' '.join(args)} failed: {p.stderr.strip()[:200]}")
    return p.stdout


def clean_checkout(repo: str, commit: str, dest: str) -> str:
    """Fresh clone (no hardlinks, no alternates) detached at `commit`; verifies HEAD and a clean tree. The worker's working tree is never used."""
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit): raise VerifierError("commit must be a full 40-hex sha")
    git(["clone", "--quiet", "--no-hardlinks", "--local", repo, dest], cwd=tempfile.gettempdir())
    git(["checkout", "--quiet", "--detach", commit], cwd=dest)
    if git(["rev-parse", "HEAD"], dest).strip() != commit: raise VerifierError("checkout HEAD does not match requested commit")
    if git(["status", "--porcelain"], dest).strip(): raise VerifierError("fresh checkout is dirty")
    return dest


def oracle_tamper(repo: str, base: str, commit: str, protected_globs: list[str]) -> dict:
    """Compare the worker commit against the trusted base. Modified/deleted/renamed PRE-EXISTING protected files are tampering;
    newly added files are allowed unless their name can alter test behaviour (conftest.py, sitecustomize.py, config files, *.pth)."""
    out = git(["diff", "--name-status", "--no-renames", f"{base}", f"{commit}"], repo)
    changed, shadow = [], []
    for line in out.splitlines():
        st, path = line.split("\t", 1)
        prot = any(fnmatch.fnmatch(path, g) for g in protected_globs)
        if st != "A" and prot: changed.append(f"{st} {path}")
        if st == "A" and (os.path.basename(path) in SHADOW_NAMES or path.endswith(".pth")): shadow.append(path)
    return {"modified_protected": sorted(changed), "shadowing_additions": sorted(shadow)}


class KeyStore:
    """Verifier signing keys with validity windows and revocation. Keys live only in the verifier process/host."""
    def __init__(self): self.keys: dict[str, tuple[bytes, float, float]] = {}; self.revoked: dict[str, str] = {}
    def add(self, key_id: str, key: bytes, not_before: float, not_after: float): self.keys[key_id] = (key, not_before, not_after)
    def revoke(self, key_id: str, reason: str): self.revoked[key_id] = reason
    def _usable(self, key_id: str, now: float):
        if key_id in self.revoked: raise VerifierError(f"key {key_id} revoked: {self.revoked[key_id]}")
        if key_id not in self.keys: raise VerifierError(f"unknown key {key_id}")
        k, nb, na = self.keys[key_id]
        if not (nb <= now < na): raise VerifierError(f"key {key_id} outside validity window")
        return k
    def ledger_sign(self, key_id: str, payload: dict, now: float) -> str:
        """Signature in the exact format Ledger.accept_receipt verifies (same key bytes must be registered as the verifier principal)."""
        from .ledger import sign as _ls
        return _ls(self._usable(key_id, now), payload)

    def sign(self, key_id: str, payload: dict, now: float) -> str:
        return hmac.new(self._usable(key_id, now), key_id.encode() + b"\x1f" + canon(payload), hashlib.sha256).hexdigest()
    def verify(self, key_id: str, payload: dict, sig: str, now: float) -> bool:
        try: want = self.sign(key_id, payload, now)
        except VerifierError: return False
        return hmac.compare_digest(sig, want)


def run_command(argv: list[str], cwd: str, timeout: int) -> dict:
    if not argv or argv[0] not in ALLOWED_PROGRAMS: raise VerifierError("program not in verifier allowlist")
    home = tempfile.mkdtemp(prefix="verifier-home-"); t0 = time.monotonic()
    try:
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=safe_env(home), stdin=subprocess.DEVNULL)
        code, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        code, out, err = 124, (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""), "TIMEOUT"
    finally: shutil.rmtree(home, ignore_errors=True)
    return {"argv": argv, "exit_code": code, "stdout_sha256": sha(out), "stderr_sha256": sha(err), "seconds": round(time.monotonic() - t0, 3), "_stdout": out, "_stderr": err}


def verify_task(*, repo: str, base: str, commit: str, task: str, attempt: int, epoch: int, plan_digest: str, acceptance: list[list[str]],
                protected_globs: list[str], required_sinks: list[str], independent_observed: list[str], observations: list[dict] | None = None,
                env_digest: str, verifier_id: str, keystore: KeyStore, key_id: str, now: float, timeout: int = 600) -> tuple[dict, dict, str, dict]:
    """Returns (ledger_receipt, envelope, signature, private_detail). `acceptance`, `protected_globs`, `required_sinks` MUST come from the trusted
    plan/base ref, never from the worker. `independent_observed` is what a protected collector saw; worker-reported observations are recorded
    but never counted toward coverage."""
    tmp = tempfile.mkdtemp(prefix="verifier-co-")
    try:
        co = clean_checkout(repo, commit, os.path.join(tmp, "src"))
        tamper = oracle_tamper(repo, base, commit, protected_globs)
        results = [run_command(a, co, timeout) for a in acceptance] if not (tamper["modified_protected"] or tamper["shadowing_additions"]) else []
    finally: shutil.rmtree(tmp, ignore_errors=True)
    obs = [{**o, "counts_toward_coverage": o.get("source") == "independent"} for o in (observations or [])]
    unobserved = sorted(set(required_sinks) - set(independent_observed))
    if tamper["modified_protected"] or tamper["shadowing_additions"]: verdict, why = "FAIL", "oracle tampering or test-shadowing files"
    elif any(r["exit_code"] != 0 for r in results): verdict, why = "FAIL", "acceptance command failed"
    elif unobserved: verdict, why = "UNKNOWN", f"no independent telemetry for protected sinks: {unobserved}"
    else: verdict, why = "PASS", "all acceptance commands passed on a clean checkout with full required coverage"
    env = {"schema": "horizon.evidence/1", "task": task, "attempt": attempt, "epoch": epoch, "plan": plan_digest, "source": {"commit": commit, "base": base},
           "oracle_id": sha(canon([acceptance, sorted(protected_globs)])), "env_digest": env_digest,
           "commands": [{k: v for k, v in r.items() if not k.startswith("_")} for r in results], "tamper": tamper, "observations": obs,
           "coverage": {"required": sorted(required_sinks), "independently_observed": sorted(set(independent_observed)), "unobserved": unobserved},
           "verdict": verdict, "reason": why, "verifier": verifier_id, "key_id": key_id, "issued_at": now}
    env_sha = sha(canon(env))
    code = 0 if verdict == "PASS" else (3 if verdict == "UNKNOWN" else (next((r["exit_code"] for r in results if r["exit_code"]), 0) or 2))
    receipt = {"task": task, "verifier": verifier_id, "git_sha": commit, "epoch": epoch, "plan": plan_digest, "cmd": acceptance, "exit_code": code,
               "report_hash": env_sha, "verdict": verdict, "envelope_sha256": env_sha, "key_id": key_id}
    return receipt, env, keystore.ledger_sign(key_id, receipt, now), {"results": results}


def failure_report(env: dict, detail: dict, tail_lines: int = 40) -> dict:
    """P85-15: failing requirement + minimal reproduction. Output tail is credential-scrubbed."""
    bad = next((r for r in detail["results"] if r["exit_code"] != 0), None)
    return {"task": env["task"], "verdict": env["verdict"], "reason": env["reason"], "failed_command": bad["argv"] if bad else None,
            "tamper": env["tamper"], "unobserved_sinks": env["coverage"]["unobserved"],
            "repro": [f"git clone <repo> repro && cd repro && git checkout {env['source']['commit']}"] + ([" ".join(bad["argv"])] if bad else []),
            "output_tail": scrub("\n".join((bad["_stdout"] + bad["_stderr"]).splitlines()[-tail_lines:])) if bad else ""}


def audit_export(env: dict) -> dict:
    """P85-13: privacy-safe export — digests and verdicts only; no command output, no worker-supplied free text."""
    keep = ("schema", "task", "attempt", "epoch", "plan", "source", "oracle_id", "env_digest", "coverage", "verdict", "reason", "verifier", "key_id", "issued_at")
    return {**{k: env[k] for k in keep}, "commands": [{"argv": c["argv"], "exit_code": c["exit_code"], "stdout_sha256": c["stdout_sha256"]} for c in env["commands"]],
            "tamper_counts": {k: len(v) for k, v in env["tamper"].items()}, "observation_count": len(env["observations"])}
