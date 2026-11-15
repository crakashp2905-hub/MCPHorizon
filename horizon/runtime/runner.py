"""K2: ONE confined agent runner. Default is ENFORCED: a weaker policy is refused (not silently run), the kernel-reported profile is verified before the agent starts (sandbox.launch), the agent works on a private copy of the
workspace and nothing it does there reaches the real repository until a separate trusted step applies the reported changes (item 3 routes that through the EffectKernel). Direct socket/file/process bypasses are proven by
BYPASS_PROBES, run both confined (must all be blocked) and unconfined (control: must be reachable, otherwise a probe proves nothing).
CANDIDATE. Proven here only on THIS kernel as root; the designated-Linux-host proof is a separate, owner-supplied step (BLOCKED until then). Not claimed: kernel/Landlock bugs, same-uid side channels, CPU/timing channels."""
from __future__ import annotations
import hashlib, json, os, shutil, tempfile
from dataclasses import dataclass, field
from horizon.runtime import sandbox as S

REQUIRED = ("netns", "pidns", "mntns", "landlock", "landlock_net", "seccomp", "drop_privs", "rlimits", "exec_deny")
MAX_CHANGE_BYTES = 8 << 20


def enforced_policy(**over) -> S.Policy: return S.Policy(exec_deny=True, **over)
def weaknesses(pol: S.Policy) -> list: return [k for k in REQUIRED if not getattr(pol, k)]


@dataclass
class RunReport:
    run_id: str; confined: bool; refused: str | None; exit: int | None; stdout: str; stderr: str; timed_out: bool; policy_digest: str; profile: dict
    changes: list = field(default_factory=list); skipped: list = field(default_factory=list)


def _tree(root: str) -> dict:
    out = {}
    for d, ds, fs in os.walk(root):
        ds[:] = [x for x in ds if x != ".git"]
        for f in fs:
            p = os.path.join(d, f); rel = os.path.relpath(p, root)
            if os.path.islink(p): out[rel] = ("link", os.readlink(p)); continue
            if os.path.isfile(p): out[rel] = ("file", hashlib.sha256(open(p, "rb").read()).hexdigest())
    return out


class ConfinedRunner:
    def __init__(self, workspace: str, *, policy: S.Policy | None = None, unconfined: bool = False, timeout_s: float = 20):
        self.workspace = os.path.realpath(workspace); self.policy = policy or enforced_policy(); self.unconfined = unconfined; self.timeout_s = timeout_s
    def run(self, code: str, *, run_id: str, extra_env: dict | None = None, stdin: bytes = b"") -> RunReport:
        weak = weaknesses(self.policy)
        if weak and not self.unconfined: return RunReport(run_id, False, "POLICY_TOO_WEAK:" + ",".join(weak), None, "", "", False, self.policy.digest(), {})
        scratch = tempfile.mkdtemp(prefix=f"hz-run-{run_id}-", dir=S.SCRATCH_BASE if os.path.isdir(S.SCRATCH_BASE) else None); os.chmod(scratch, 0o700)
        try:
            work = os.path.join(scratch, "work"); shutil.copytree(self.workspace, work, symlinks=True, ignore=shutil.ignore_patterns(".git"))
            if self.policy.drop_privs and os.geteuid() == 0:
                for d, ds, fs in os.walk(work):
                    for n in ds + fs: os.lchown(os.path.join(d, n), S.UID, S.GID)
                os.chown(work, S.UID, S.GID)
            before = _tree(work)
            r = S.launch("import os\nos.chdir('work')\n" + code, run_id=run_id, policy=self.policy, scratch=scratch, timeout_s=self.timeout_s, extra_env=extra_env, stdin=stdin)
            rep = RunReport(run_id, not weak, r.refused, r.exit, r.stdout, r.stderr, r.timed_out, r.policy_digest, r.profile)
            if r.refused: return rep
            after = _tree(work); total = 0
            for rel in sorted(set(before) | set(after)):
                b, a = before.get(rel), after.get(rel)
                if b == a: continue
                if a is not None and a[0] == "link": rep.skipped.append({"path": rel, "why": "symlink"}); continue
                op = "delete" if a is None else ("create" if b is None else "modify")
                data = None
                if a is not None:
                    data = open(os.path.join(work, rel), "rb").read(); total += len(data)
                    if total > MAX_CHANGE_BYTES: rep.skipped.append({"path": rel, "why": "size_cap"}); continue
                rep.changes.append({"path": rel, "op": op, "sha256": None if a is None else a[1], "data": data})
            return rep
        finally: shutil.rmtree(scratch, ignore_errors=True)


def _probe(name, body): return (name, "import json,os,sys,socket,subprocess\nT=os.environ['PROBE_TARGET']\ndef out(blocked,detail=''): print(json.dumps({'n':%r,'blocked':blocked,'detail':str(detail)[:120]}))\n" % name + body)


def probes() -> list:
    return [
        _probe("tcp_connect_loopback", "L=int(os.environ['PROBE_PORT'])\ntry:\n  s=socket.create_connection(('127.0.0.1',L),timeout=2); s.sendall(b'EXFIL'); out(False,'connected')\nexcept OSError as e: out(True,e)"),
        _probe("udp_socket", "try:\n  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'x',('127.0.0.1',int(os.environ['PROBE_PORT']))); out(False,'sent')\nexcept OSError as e: out(True,e)"),
        _probe("raw_socket", "try:\n  socket.socket(socket.AF_INET,socket.SOCK_RAW,1); out(False,'raw')\nexcept OSError as e: out(True,e)"),
        _probe("unix_socket_to_host", "try:\n  s=socket.socket(socket.AF_UNIX); s.connect(os.environ['PROBE_UNIX']); out(False,'connected')\nexcept OSError as e: out(True,e)"),
        _probe("write_protected_root", "try:\n  open(os.path.join(T,'raw.txt'),'w').write('bypass'); out(False,'written')\nexcept OSError as e: out(True,e)"),
        _probe("read_outside_workspace", "try:\n  d=open(os.path.join(T,'secret.txt')).read(); out(False,d)\nexcept OSError as e: out(True,e)"),
        _probe("symlink_escape_write", "try:\n  os.symlink(os.path.join(T,'secret.txt'),'esc'); open('esc','w').write('x'); out(False,'wrote via symlink')\nexcept OSError as e: out(True,e)"),
        _probe("hardlink_escape", "try:\n  os.link(os.path.join(T,'secret.txt'),'hl'); out(False,'linked')\nexcept OSError as e: out(True,e)"),
        _probe("direct_exec", "try:\n  r=subprocess.run(['/bin/true']); out(r.returncode!=0 and False,'ran')\nexcept OSError as e: out(True,e)"),
        _probe("exec_shell_via_os_system", "r=os.system('/bin/echo pwned > '+os.path.join(T,'sh.txt')+' 2>/dev/null'); out(not os.path.exists(os.path.join(T,'sh.txt')),'rc=%s'%r)"),
        _probe("fork_then_exec", "pid=os.fork()\nif pid==0:\n  try: os.execv('/bin/true',['true']); os._exit(0)\n  except OSError: os._exit(77)\n_,st=os.waitpid(pid,0); out(os.WEXITSTATUS(st)==77,'st=%s'%st)"),
        _probe("write_exec_in_workspace_then_run", "p='x.sh'; open(p,'w').write('#!/bin/sh\\necho hi\\n'); os.chmod(p,0o755)\ntry:\n  r=subprocess.run(['./x.sh']); out(False,'ran rc=%s'%r.returncode)\nexcept OSError as e: out(True,e)"),
        _probe("mount", "import ctypes\nl=ctypes.CDLL(None,use_errno=True); r=l.mount(b'none',b'/proc',b'tmpfs',0,None); out(r!=0,'rc=%s errno=%s'%(r,ctypes.get_errno()))"),
        _probe("setuid_root", "try:\n  os.setuid(0); out(os.getuid()!=0,'uid=%s'%os.getuid())\nexcept OSError as e: out(True,e)"),
    ]


DESTRUCTIVE_WHEN_UNCONFINED = ("mount",)       # as real root with no mount namespace this would shadow the HOST's /proc; it is only ever run confined


def run_probes(runner: ConfinedRunner, *, target: str, port: int, unix_path: str, run_prefix: str = "probe") -> dict:
    res = {}
    for i, (name, code) in enumerate(probes()):
        if runner.unconfined and name in DESTRUCTIVE_WHEN_UNCONFINED: res[name] = {"refused": None, "exit": None, "blocked": None, "detail": "skipped: unsafe without confinement"}; continue
        r = runner.run(code, run_id=f"{run_prefix}{i}", extra_env={"PROBE_TARGET": target, "PROBE_PORT": str(port), "PROBE_UNIX": unix_path})
        line = next((l for l in r.stdout.splitlines() if l.startswith("{")), None)
        res[name] = {"refused": r.refused, "exit": r.exit, **(json.loads(line) if line else {"blocked": None, "detail": "no output: " + r.stderr[-120:]})}
    return res
