"""Code Mode execution facade (P6-02..P6-05, P6-11, P6-12, P6-16..P6-18, P6-20, P6-22).
A generated program runs inside an isolated-vm isolate in a separate, nonprivileged, resource-limited process. Its ONLY capability is
`tools.<name>(args)`, and every such call is sent here to `mediate()` with trusted context; nothing in the program can set principal, tenant or parent ids.

THREAT MODEL (see docs/security/CODE_MODE_SECURITY_LIMITS.md): isolated-vm is a V8 isolate, NOT a security boundary against a V8 engine bug; the OS layer
here (separate process, setuid nobody when root, rlimits, optional user+net namespace) reduces but does not eliminate that risk. No external audit."""
from __future__ import annotations
import hashlib, json, os, resource, select, shutil, signal, subprocess, time, uuid
from pathlib import Path
from ..service.redact import redact

HERE = Path(__file__).resolve().parents[2] / "codemode"
RUNNER, SCANNER = HERE / "runner.mjs", HERE / "scanner.mjs"
MAX_LINE = 1_000_000


class CodeModeError(Exception): pass


def scan(code: str, node: str = "node") -> dict:
    """Static preview. Never exhaustive; callers must not present it as a complete verdict."""
    p = subprocess.run([node, str(SCANNER)], input=json.dumps({"code": code}), capture_output=True, text=True, timeout=20, cwd=str(HERE), env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
    if p.returncode != 0: raise CodeModeError("scanner failed")
    r = json.loads(p.stdout); r["has_unknown"] = bool(r["unknown"]); return r


def _sha(o) -> str: return "sha256:" + hashlib.sha256(json.dumps(o, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class Executor:
    def __init__(self, mediate, *, node: str | None = None, drop_privileges=True, net_namespace=False, cpu_s=10, nofile=64, nproc=256, fsize=1 << 20):
        """mediate(ctx: dict) -> {"ok": bool, "result"|"error"}; ctx = {exec_id, parent_execution_id, call_id, principal, tool, args, args_digest}.
        It MUST be the host's enforcement path (gates + decision service); the executor itself never decides."""
        self.mediate, self.node = mediate, node or shutil.which("node") or "node"
        self.drop, self.netns, self.cpu_s, self.nofile, self.nproc, self.fsize = drop_privileges, net_namespace, cpu_s, nofile, nproc, fsize
        self.audit: list[dict] = []; self.cancelled: set[str] = set(); self.info: dict[str, dict] = {}

    def cancel(self, exec_id: str) -> None: self.cancelled.add(exec_id)

    def _preexec(self):
        os.setsid()
        dropping = self.drop and os.geteuid() == 0
        lims = [(resource.RLIMIT_CPU, self.cpu_s), (resource.RLIMIT_NOFILE, self.nofile), (resource.RLIMIT_FSIZE, self.fsize), (resource.RLIMIT_CORE, 0)]
        if dropping: lims.append((resource.RLIMIT_NPROC, self.nproc))      # NPROC is per-UID: only meaningful (and safe) when the runner has its own UID
        for r, v in lims: resource.setrlimit(r, (v, v))
        if dropping: os.setgroups([]); os.setgid(65534); os.setuid(65534)

    def _argv(self):
        a = [self.node, str(RUNNER)]
        if self.netns:
            u = shutil.which("unshare")
            if not u: raise CodeModeError("net_namespace requested but unshare is not available")
            a = [u, "-Urn", "--"] + a
        return a

    def run(self, code: str, tool_names: list[str], *, principal: str, parent_execution_id: str | None = None, timeout_s: float = 5.0, memory_mb: int = 64, max_calls: int = 200, max_log_bytes: int = 16384) -> dict:
        if not isinstance(principal, str) or not principal: raise CodeModeError("principal required (from the trusted host)")
        if not isinstance(code, str) or len(code) > 200_000: raise CodeModeError("program too large")
        if not all(isinstance(n, str) and n.replace(".", "").replace("_", "").replace("-", "").isalnum() for n in tool_names): raise CodeModeError("bad tool name")
        exec_id = "x-" + uuid.uuid4().hex[:16]; known = set(tool_names)
        rec = {"exec_id": exec_id, "parent_execution_id": parent_execution_id, "principal": principal, "code_digest": _sha(code), "calls": [], "logs": [], "late_calls": 0}
        p = subprocess.Popen(self._argv(), cwd=str(HERE), env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/nonexistent", "LANG": "C.UTF-8"}, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, preexec_fn=self._preexec, text=False, bufsize=0)
        gone = {"v": False}
        def send(o):
            if gone["v"]: return
            try: p.stdin.write((json.dumps(o) + "\n").encode()); p.stdin.flush()
            except (BrokenPipeError, OSError): gone["v"] = True          # runner already exited (e.g. outer program completed): keep reading its remaining output
        out = {"exec_id": exec_id, "ok": False, "error": "RUNNER_FAILED", "result": None}; hello = None; dl = time.monotonic() + timeout_s + 2
        try:
            send({"code": code, "tool_names": tool_names, "timeout_ms": int(timeout_s * 1000), "memory_mb": memory_mb, "max_calls": max_calls, "max_log_bytes": max_log_bytes})
            buf = b""; fd = p.stdout.fileno(); eof = False
            while True:
                if exec_id in self.cancelled: out = {**out, "error": "CANCELLED"}; break
                if b"\n" not in buf:
                    if eof: break
                    left = dl - time.monotonic()
                    if left <= 0: out = {**out, "error": "TIMEOUT"}; break
                    if not select.select([fd], [], [], min(left, 0.1))[0]:
                        if p.poll() is not None and not select.select([fd], [], [], 0)[0]: break
                        continue
                    chunk = os.read(fd, 65536)             # raw read + own line buffer: select() on a buffered stream can strand complete lines
                    if not chunk: eof = True; continue
                    buf += chunk
                    if len(buf) > 4 * MAX_LINE: out = {**out, "error": "RUNNER_PROTOCOL"}; break
                    continue
                line, buf = buf.split(b"\n", 1)
                if len(line) > MAX_LINE: out = {**out, "error": "RUNNER_PROTOCOL"}; break
                try: m = json.loads(line)
                except ValueError: out = {**out, "error": "RUNNER_PROTOCOL"}; break
                t = m.get("t")
                if t == "hello": hello = {"uid": m.get("uid"), "env_keys": [str(k)[:64] for k in (m.get("env_keys") or [])][:50]}
                elif t == "log": rec["logs"].append({"level": str(m.get("level"))[:8], "text": redact(str(m.get("text"))[:4096])})
                elif t == "late_call": rec["late_calls"] += 1; self.audit.append({"exec_id": exec_id, "event": "late_call_denied", "tool": str(m.get("tool"))[:100]})
                elif t == "call":
                    send({"t": "result", "cid": m["cid"], "payload": self._call(rec, exec_id, parent_execution_id, principal, known, m)})
                elif t == "done":
                    out = {"exec_id": exec_id, "ok": bool(m.get("ok")), "result": m.get("result"), "error": m.get("error"), "message": redact(str(m["message"])) if m.get("message") else None, "log_truncated": bool(m.get("log_truncated"))}; break
        finally:
            try: os.killpg(p.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError): pass
            try: p.communicate(timeout=3)
            except Exception: pass
        out["pending_unconfirmed"] = [c["call_id"] for c in rec["calls"] if c["outcome"] == "started"]      # calls in flight at kill: outcome unknown
        rec.update(outcome=out.get("error") or "ok", runner=hello); out.update(logs=rec["logs"], calls=rec["calls"], runner=hello, late_calls=rec["late_calls"]); self.info[exec_id] = rec; self.audit.append({"exec_id": exec_id, "event": "finished", "outcome": rec["outcome"], "parent_execution_id": parent_execution_id, "calls": len(rec["calls"])})
        return out

    def _call(self, rec, exec_id, parent, principal, known, m) -> dict:
        n = len(rec["calls"]) + 1; call_id = f"{exec_id}.c{n}"; tool = str(m.get("tool"))
        c = {"call_id": call_id, "tool": tool, "parent_execution_id": exec_id, "outcome": "started"}; rec["calls"].append(c)
        if exec_id in self.cancelled: c["outcome"] = "cancelled"; return {"ok": False, "error": "CANCELLED"}
        if tool not in known: c["outcome"] = "unknown_tool"; return {"ok": False, "error": "UNKNOWN_TOOL"}
        try: args = json.loads(m.get("args", "{}"))
        except ValueError: c["outcome"] = "bad_args"; return {"ok": False, "error": "BAD_ARGS"}
        if not isinstance(args, dict): c["outcome"] = "bad_args"; return {"ok": False, "error": "BAD_ARGS"}
        c["args_digest"] = _sha(args)
        try: r = self.mediate({"exec_id": exec_id, "parent_execution_id": parent, "call_id": call_id, "principal": principal, "tool": tool, "args": args, "args_digest": c["args_digest"]})
        except Exception: c["outcome"] = "mediator_error"; return {"ok": False, "error": "MEDIATOR_ERROR"}
        if not isinstance(r, dict) or not isinstance(r.get("ok"), bool): c["outcome"] = "mediator_error"; return {"ok": False, "error": "MEDIATOR_ERROR"}
        c["outcome"] = "ok" if r["ok"] else "denied_or_failed"
        if r["ok"]: return {"ok": True, "result": r.get("result")}
        return {"ok": False, "error": str(r.get("error", "DENIED"))[:60]}


def diff_report(static: dict, runtime_calls: list[dict]) -> dict:
    """P6-22: runtime calls that the static preview did not list are static false negatives (reported, not hidden)."""
    s = {c["name"] for c in static["calls"]}; r = {c["tool"] for c in runtime_calls}
    return {"static_names": sorted(s), "runtime_names": sorted(r), "static_false_negatives": sorted(r - s), "static_unexercised": sorted(s - r), "static_flagged_unknown": static["has_unknown"]}
