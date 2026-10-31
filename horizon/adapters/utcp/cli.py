"""CLI transport facade (P5-13..P5-15). argv arrays only, absolute allowlisted executables, scrubbed env, bounded output. NOT a sandbox:
rlimits + process group only; filesystem/network confinement needs an OS sandbox that is not provided here."""
from __future__ import annotations
import os, resource, subprocess
from ...service.redact import redact

SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"}
SHELLS = {"sh", "bash", "zsh", "dash", "fish", "cmd", "powershell", "pwsh", "env", "xargs", "sudo", "eval"}


class CliError(Exception):
    def __init__(self, code, msg): super().__init__(msg); self.code = code


def build_argv(template: list, params: dict, *, allowed: set) -> list[str]:
    """Template elements are literals or {"param": name}. A parameter fills exactly ONE argv element and is never interpolated into another."""
    if not isinstance(template, list) or not template or not all(isinstance(x, (str, dict)) for x in template): raise CliError("TEMPLATE", "command must be an argv array")
    out = []
    for x in template:
        if isinstance(x, dict):
            v = params.get(x.get("param")) if set(x) == {"param"} else None
            if not isinstance(v, str) or "\x00" in v: raise CliError("PARAM", f"bad parameter {x}")
            out.append(v)
        else:
            if "{" in x and "}" in x: raise CliError("INTERPOLATION", "string interpolation in argv is not allowed; use {\"param\": name}")
            out.append(x)
    exe = out[0]
    if not os.path.isabs(exe) or os.path.realpath(exe) not in allowed or os.path.basename(exe) in SHELLS: raise CliError("EXECUTABLE", "executable not allowlisted")
    if isinstance(template[0], dict): raise CliError("EXECUTABLE", "executable cannot be a parameter")
    return out


def run(argv: list[str], *, cwd: str, timeout=10, max_out=65_536, max_cpu=5, max_mem=512 * 2**20, max_files=64, extra_env: dict | None = None) -> dict:
    def pre():
        os.setsid(); resource.setrlimit(resource.RLIMIT_CPU, (max_cpu, max_cpu)); resource.setrlimit(resource.RLIMIT_AS, (max_mem, max_mem)); resource.setrlimit(resource.RLIMIT_NOFILE, (max_files, max_files)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    p = subprocess.Popen(argv, cwd=cwd, env={**SAFE_ENV, **(extra_env or {})}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=pre, shell=False)
    try: out, err = p.communicate(timeout=timeout); timed_out = False
    except subprocess.TimeoutExpired:
        try: os.killpg(p.pid, 9)
        except ProcessLookupError: pass
        out, err = p.communicate(); timed_out = True
    def cut(b): return (b[:max_out].decode("utf-8", "replace"), len(b) > max_out)
    (so, so_t), (se, se_t) = cut(out), cut(err)
    return {"exit_code": p.returncode, "timed_out": timed_out, "stdout": redact(so), "stderr": redact(se), "truncated": so_t or se_t}
