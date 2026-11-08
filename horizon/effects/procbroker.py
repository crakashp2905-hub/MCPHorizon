"""Process broker policy + runner. CANDIDATE, stdlib only, imports nothing from this repo.
DEFAULT POLICY ALLOWS NOTHING. No command is built in: the owner supplies an allowlist of Rule(program, argv patterns). I did not invent one.
For a request made THROUGH the broker it enforces: argv is a list of strings (never a shell string, shell=False); argv[0] must be an ABSOLUTE path whose realpath equals the realpath of an allowed program
(so a symlink or relative name cannot select another binary); every following argument must match one of that rule's fullmatch regexes (anything else is refused); no NUL bytes; the environment is replaced by
a fixed minimal one (the caller's environment never reaches the child); cwd must be inside the rule's directory; wall-clock timeout kills the whole process group; stdout/stderr are capped; CPU, address space,
and open-files rlimits are set in the child (process-count limit only if the owner sets it: RLIMIT_NPROC is per-uid, so it bounds the whole user, not this tree).
What it does NOT do: stop an agent that has its own way to execute programs (that needs an OS-level boundary: namespaces/seccomp/no exec rights for the agent, NOT implemented or tested here), or make an
allowed program safe - a permitted `python` with a permitted script path is only as safe as that script. rlimits are best-effort on Linux and are not a sandbox."""
from __future__ import annotations
import os, re, resource, selectors, signal, subprocess, time
from dataclasses import dataclass, field


class ProcBrokerError(Exception):
    def __init__(self, code, msg=""): super().__init__(f"{code}: {msg}" if msg else code); self.code = code


@dataclass(frozen=True)
class Rule:
    program: str                       # absolute path
    arg_patterns: tuple = ()           # regexes; each argument must fullmatch at least one. Empty tuple = no arguments allowed at all
    cwd_root: str | None = None        # cwd, if requested, must resolve inside this directory
    timeout: float = 10.0
    max_output: int = 1 << 16
    cpu_seconds: int = 10
    max_memory: int = 512 << 20
    max_files: int = 64
    max_procs: int | None = None      # RLIMIT_NPROC counts ALL processes of the same uid, not just this child's tree: a small value makes fork fail on a busy host (it did on CI). None = not set
    env: tuple = ()                    # extra (name, value) pairs; the base environment is only PATH=/usr/bin:/bin and LANG=C


@dataclass
class ProcBroker:
    rules: tuple = field(default_factory=tuple)

    def check(self, argv, cwd=None) -> Rule:
        if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) for a in argv): raise ProcBrokerError("BAD_ARGV")
        if any("\x00" in a for a in argv): raise ProcBrokerError("BAD_ARGV", "NUL")
        if not os.path.isabs(argv[0]): raise ProcBrokerError("PROGRAM_NOT_ABSOLUTE")
        real = os.path.realpath(argv[0]); rule = next((r for r in self.rules if os.path.realpath(r.program) == real), None)
        if rule is None: raise ProcBrokerError("PROGRAM_NOT_ALLOWED", argv[0])
        for a in argv[1:]:
            if not any(re.fullmatch(p, a) for p in rule.arg_patterns): raise ProcBrokerError("ARG_NOT_ALLOWED", a)
        if cwd is not None:
            if rule.cwd_root is None: raise ProcBrokerError("CWD_NOT_ALLOWED")
            root = os.path.realpath(rule.cwd_root); c = os.path.realpath(cwd)
            if not (c == root or c.startswith(root + os.sep)): raise ProcBrokerError("CWD_OUTSIDE_ROOT")
        return rule

    def run(self, argv, cwd=None, stdin: bytes = b""):
        rule = self.check(argv, cwd)
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", **dict(rule.env)}
        def limits():
            os.setsid()
            for lim, v in ((resource.RLIMIT_CPU, rule.cpu_seconds), (resource.RLIMIT_AS, rule.max_memory), (resource.RLIMIT_NOFILE, rule.max_files), (resource.RLIMIT_NPROC, rule.max_procs)):
                if v is not None: resource.setrlimit(lim, (v, v))
        p = subprocess.Popen(list(argv), cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True, preexec_fn=limits)
        try: out, err = _drain(p, stdin, rule.timeout, rule.max_output)
        except ProcBrokerError:
            try: os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            p.wait(); raise
        return p.returncode, out, err


def _drain(p, stdin, timeout, cap):
    """Read stdout/stderr incrementally and stop as soon as either exceeds `cap` (the child is killed by the caller), so a flooding child cannot exhaust this process's memory."""
    sel = selectors.DefaultSelector(); bufs = {p.stdout: bytearray(), p.stderr: bytearray()}; end = time.monotonic() + timeout
    for f in bufs: os.set_blocking(f.fileno(), False); sel.register(f, selectors.EVENT_READ)
    try:
        if stdin: p.stdin.write(stdin)
    except BrokenPipeError: pass
    finally:
        try: p.stdin.close()
        except OSError: pass
    while sel.get_map():
        left = end - time.monotonic()
        if left <= 0: raise ProcBrokerError("TIMEOUT")
        for key, _ in sel.select(min(left, 0.2)):
            chunk = os.read(key.fd, 65536)
            if not chunk: sel.unregister(key.fileobj); continue
            bufs[key.fileobj] += chunk
            if len(bufs[key.fileobj]) > cap: raise ProcBrokerError("OUTPUT_TOO_LARGE")
    left = end - time.monotonic()
    try: p.wait(timeout=max(left, 0.01))
    except subprocess.TimeoutExpired: raise ProcBrokerError("TIMEOUT")
    return bytes(bufs[p.stdout]), bytes(bufs[p.stderr])
