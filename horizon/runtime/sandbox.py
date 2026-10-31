"""HorizonRuntime Linux process isolation launcher (P24). Real kernel mechanisms via ctypes: namespaces (net/mnt/pid/ipc/uts), Landlock (fs + tcp + scoping), seccomp-BPF,
no_new_privs, capability bounding-set drop, unprivileged uid, rlimits, optional cgroup-v1 ceilings. Requires root/CAP_SYS_ADMIN and x86_64; otherwise REFUSES (never silently weakens).
This is a PROCESS sandbox on a Linux host; it is not a microVM launcher (P24-02 microVM is not implemented)."""
from __future__ import annotations
import ctypes, hashlib, json, os, platform, select, signal, struct, sys, tempfile, time
from dataclasses import dataclass, field, asdict

libc = ctypes.CDLL(None, use_errno=True)
CLONE = dict(NEWNS=0x00020000, NEWCGROUP=0x02000000, NEWUTS=0x04000000, NEWIPC=0x08000000, NEWUSER=0x10000000, NEWPID=0x20000000, NEWNET=0x40000000)
CLONE_NEW_MASK = sum(CLONE.values())
MS_REC, MS_PRIVATE, MS_NOSUID, MS_NODEV, MS_NOEXEC = 0x4000, 1 << 18, 2, 4, 8
AUDIT_ARCH_X86_64 = 0xC000003E
UID = GID = 10001
SCRATCH_BASE = "/var/lib/hz-runs"          # outside every masked tree; chmod 711 so only the run's own 0700 dir is usable


class Unsupported(RuntimeError):
    def __init__(self, what): super().__init__(f"UNSUPPORTED: {what}"); self.what = what


@dataclass
class Policy:
    netns: bool = True; pidns: bool = True; mntns: bool = True; landlock: bool = True; landlock_net: bool = True; seccomp: bool = True
    drop_privs: bool = True; rlimits: bool = True; cgroup: bool = False
    ro_paths: tuple = (); rw_extra: tuple = (); mask: tuple = ("/run", "/var/run", "/var/tmp", "/tmp", "/home", "/root", "/mnt", "/srv", "/media"); mem_bytes: int = 512 << 20; nproc: int = 256; cpu_s: int = 30; fsize: int = 64 << 20
    def digest(self) -> str: return "sha256:" + hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()
    @classmethod
    def open(cls): return cls(netns=False, pidns=False, mntns=False, landlock=False, landlock_net=False, seccomp=False, drop_privs=False, rlimits=False)       # B0: no isolation (test-safe because every sink is a local mock)


def _check(r, what):
    if r < 0: e = ctypes.get_errno(); raise OSError(e, f"{what}: {os.strerror(e)}")
    return r


# ---------------- Landlock
FS = dict(EXEC=1, WRITE_FILE=2, READ_FILE=4, READ_DIR=8, REMOVE_DIR=16, REMOVE_FILE=32, MAKE_CHAR=64, MAKE_DIR=128, MAKE_REG=256, MAKE_SOCK=512, MAKE_FIFO=1024, MAKE_BLOCK=2048, MAKE_SYM=4096, REFER=8192, TRUNCATE=16384, IOCTL_DEV=32768)
FS_ALL = sum(FS.values()); FS_RO = FS["EXEC"] | FS["READ_FILE"] | FS["READ_DIR"]; FS_RW = FS_ALL & ~FS["REFER"] | FS["REFER"]
NET_ALL = 3


class _Attr(ctypes.Structure): _fields_ = [("fs", ctypes.c_uint64), ("net", ctypes.c_uint64), ("scoped", ctypes.c_uint64)]
class _Rule(ctypes.Structure): _pack_ = 1; _fields_ = [("access", ctypes.c_uint64), ("fd", ctypes.c_int32)]


def landlock_abi() -> int:
    r = libc.syscall(444, None, 0, 1); return r if r > 0 else 0


def landlock_apply(ro: list, rw: list, *, deny_net: bool):
    abi = landlock_abi()
    if abi < 4: raise Unsupported("landlock ABI>=4 required")
    scoped = 3 if abi >= 6 else 0
    a = _Attr(FS_ALL, NET_ALL if deny_net else 0, scoped); fd = _check(libc.syscall(444, ctypes.byref(a), ctypes.sizeof(a), 0), "landlock_create_ruleset")
    try:
        for paths, acc in ((ro, FS_RO), (rw, FS_ALL)):
            for p in paths:
                try: pfd = os.open(p, os.O_PATH | os.O_CLOEXEC)
                except OSError: continue
                try:
                    isdir = os.path.isdir(p); eff = acc if isdir else (acc & (FS["EXEC"] | FS["READ_FILE"] | FS["WRITE_FILE"] | FS["TRUNCATE"] | FS["IOCTL_DEV"]))
                    _check(libc.syscall(445, fd, 1, ctypes.byref(_Rule(eff, pfd)), 0), f"landlock_add_rule {p}")
                finally: os.close(pfd)
        _check(libc.prctl(38, 1, 0, 0, 0), "no_new_privs"); _check(libc.syscall(446, fd, 0), "landlock_restrict_self")
    finally: os.close(fd)


# ---------------- seccomp
SYS = dict(unshare=272, setns=308, mount=165, umount2=166, pivot_root=155, chroot=161, ptrace=101, process_vm_readv=310, process_vm_writev=311, kexec_load=246, init_module=175, finit_module=313, delete_module=176,
           bpf=321, perf_event_open=298, userfaultfd=323, keyctl=250, add_key=248, request_key=249, mount_setattr=442, open_tree=428, move_mount=429, fsopen=430, fsconfig=431, fsmount=432, fspick=433,
           reboot=169, swapon=167, swapoff=168, acct=163, settimeofday=164, personality=135, iopl=172, ioperm=173)
SYS_CLONE, SYS_CLONE3, SYS_SOCKET = 56, 435, 41
ERRNO = lambda e: 0x00050000 | e
KILL = 0x80000000; ALLOW = 0x7FFF0000


def _bpf(code, jt, jf, k): return struct.pack("HBBI", code, jt, jf, k)


def seccomp_program(deny_sockets=True) -> bytes:
    """Deny list with explicit arch check. clone(NEW*) -> EPERM; clone3 -> ENOSYS (glibc falls back to clone); socket(non-AF_UNIX) -> EPERM; ~30 privileged syscalls -> EPERM."""
    LD, JEQ, JSET, RET, AND, JGE = 0x20, 0x15, 0x45, 0x06, 0x54, 0x35
    ins = [_bpf(LD, 0, 0, 4), _bpf(JEQ, 1, 0, AUDIT_ARCH_X86_64), _bpf(RET, 0, 0, KILL), _bpf(LD, 0, 0, 0), _bpf(JGE, 0, 1, 0x40000000), _bpf(RET, 0, 0, KILL)]      # arch + x32 ABI kill
    for nr in SYS.values(): ins += [_bpf(JEQ, 0, 1, nr), _bpf(RET, 0, 0, ERRNO(1))]
    ins += [_bpf(JEQ, 0, 1, SYS_CLONE3), _bpf(RET, 0, 0, ERRNO(38))]
    ins += [_bpf(JEQ, 0, 3, SYS_CLONE), _bpf(LD, 0, 0, 16), _bpf(JSET, 0, 1, CLONE_NEW_MASK), _bpf(RET, 0, 0, ERRNO(1))]
    # after clone block A is clobbered by arg load; reload syscall nr for the socket test
    ins += [_bpf(LD, 0, 0, 0)]
    if deny_sockets: ins += [_bpf(JEQ, 0, 4, SYS_SOCKET), _bpf(LD, 0, 0, 16), _bpf(JEQ, 1, 0, 1), _bpf(RET, 0, 0, ERRNO(1)), _bpf(RET, 0, 0, ALLOW)]
    ins += [_bpf(RET, 0, 0, ALLOW)]
    return b"".join(ins)


def seccomp_apply(deny_sockets=True):
    prog = seccomp_program(deny_sockets); n = len(prog) // 8; buf = ctypes.create_string_buffer(prog, len(prog))
    class FProg(ctypes.Structure): _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
    fp = FProg(n, ctypes.addressof(buf)); _check(libc.prctl(38, 1, 0, 0, 0), "no_new_privs"); _check(libc.prctl(22, 2, ctypes.byref(fp)), "seccomp")


# ---------------- result types
@dataclass
class Result:
    run_id: str; exit: int | None; signal: int | None; timed_out: bool; stdout: str; stderr: str; profile: dict; policy_digest: str; host_pid: int; duration_s: float; refused: str | None = None; broker_requests: list = field(default_factory=list)


def _read_status(pid) -> dict:
    out = {}
    for line in open(f"/proc/{pid}/status"):
        k, _, v = line.partition(":"); out[k] = v.strip()
    return out


def _ns_ids(pid) -> dict: return {n: os.readlink(f"/proc/{pid}/ns/{n}") for n in ("net", "mnt", "pid", "ipc", "uts")}


def effective_profile(pid) -> dict:
    s = _read_status(pid); return {"uid": s["Uid"].split()[0], "gid": s["Gid"].split()[0], "nonewprivs": s.get("NoNewPrivs"), "seccomp": s.get("Seccomp"), "cap_eff": s["CapEff"], "cap_bnd": s["CapBnd"], "cap_prm": s["CapPrm"], "ns": _ns_ids(pid)}


def verify_profile(pol: Policy, prof: dict, parent_ns: dict) -> list:
    """Launch-time verification of the ACTUAL kernel-reported profile against the requested policy (P24-15). Returns violations; any => launch refused (P24-16)."""
    bad = []
    if pol.drop_privs:
        if prof["uid"] != str(UID): bad.append("uid_not_dropped")
        if int(prof["cap_eff"], 16) or int(prof["cap_prm"], 16): bad.append("caps_not_dropped")
        if int(prof["cap_bnd"], 16): bad.append("bounding_set_not_cleared")
    if (pol.seccomp or pol.landlock) and prof["nonewprivs"] != "1": bad.append("no_new_privs_missing")
    if pol.seccomp and prof["seccomp"] != "2": bad.append("seccomp_not_installed")
    for flag, ns in ((pol.netns, "net"), (pol.mntns, "mnt"), (pol.pidns, "pid")):
        if flag and prof["ns"][ns] == parent_ns[ns]: bad.append(f"{ns}_ns_shared")
    return bad


def _cgroup_setup(run_id, pol) -> list:
    made = []
    for ctl, files in (("memory", {"memory.limit_in_bytes": str(pol.mem_bytes)}), ("pids", {"pids.max": str(pol.nproc)})):
        d = f"/sys/fs/cgroup/{ctl}/hz_{run_id}"
        try:
            os.mkdir(d)
            for f, v in files.items(): open(f"{d}/{f}", "w").write(v)
            made.append(d)
        except OSError as e: raise Unsupported(f"cgroup {ctl}: {e.strerror}")
    return made


def launch(code: str, *, run_id: str, policy: Policy | None = None, scratch: str | None = None, timeout_s: float = 20, extra_env: dict | None = None, broker=None, stdin: bytes = b"") -> Result:
    pol = policy or Policy(); t0 = time.time()
    isolation = any((pol.netns, pol.pidns, pol.mntns, pol.landlock, pol.seccomp, pol.drop_privs))
    if isolation:
        if platform.machine() != "x86_64": return _refused(run_id, pol, "UNSUPPORTED: only x86_64 syscall tables are implemented")
        if os.geteuid() != 0: return _refused(run_id, pol, "UNSUPPORTED: needs root/CAP_SYS_ADMIN")
        if pol.landlock and landlock_abi() < 4: return _refused(run_id, pol, "UNSUPPORTED: Landlock ABI>=4 unavailable")
    own_scratch = scratch is None; os.makedirs(SCRATCH_BASE, exist_ok=True) if scratch is None else None; scratch = scratch or tempfile.mkdtemp(prefix=f"hz-{run_id}-", dir=SCRATCH_BASE); os.chmod(scratch, 0o700)
    if pol.drop_privs and os.geteuid() == 0: os.chown(scratch, UID, GID)
    cg = []
    try:
        if pol.cgroup: cg = _cgroup_setup(run_id, pol)
    except Unsupported as e:
        if own_scratch:
            import shutil; shutil.rmtree(scratch, ignore_errors=True)
        return _refused(run_id, pol, str(e))
    out_r, out_w = os.pipe(); err_r, err_w = os.pipe(); rdy_r, rdy_w = os.pipe(); go_r, go_w = os.pipe(); pid_r, pid_w = os.pipe(); in_r, in_w = os.pipe()
    sock_p, sock_c = (None, None)
    if broker is not None:
        import socket; sock_p, sock_c = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    parent_ns = _ns_ids(os.getpid())
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": scratch, "TMPDIR": scratch, "HZ_RUN_ID": run_id, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", **(extra_env or {})}
    pid = os.fork()
    if pid == 0:                                                                   # ---- process A (still host pid ns)
        try:
            os.setsid()
            flags = (CLONE["NEWNET"] if pol.netns else 0) | (CLONE["NEWNS"] if pol.mntns else 0) | (CLONE["NEWPID"] if pol.pidns else 0) | (CLONE["NEWIPC"] | CLONE["NEWUTS"] if isolation and pol.mntns else 0)
            if flags: _check(libc.unshare(flags), "unshare")
            if pol.mntns: _check(libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None), "make-rprivate")
            bpid = os.fork()
            if bpid:                                                               # A: relay B's host pid to parent, then reap
                os.write(pid_w, struct.pack("i", bpid)); _, st = os.waitpid(bpid, 0); os._exit(os.waitstatus_to_exitcode(st) & 0xFF if os.WIFEXITED(st) else 128 + os.WTERMSIG(st))
            # ---- process B (pid 1 of the new pid ns when pidns)
            if pol.mntns and pol.pidns: _check(libc.mount(b"proc", b"/proc", b"proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, b"hidepid=2"), "mount proc")
            if pol.mntns:
                libc.sethostname(b"hz-sandbox", 10)
                for m in pol.mask:      # hide host sockets/home/tmp behind empty read-only tmpfs (P24-11/14); never mask the scratch tree itself
                    if os.path.isdir(m) and not os.path.islink(m) and not (scratch + "/").startswith(m.rstrip("/") + "/"): libc.mount(b"tmpfs", m.encode(), b"tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | 1, b"size=64k,mode=0555")
            if pol.rlimits:
                import resource
                for r, v in ((resource.RLIMIT_AS, pol.mem_bytes), (resource.RLIMIT_NPROC, pol.nproc), (resource.RLIMIT_CPU, pol.cpu_s), (resource.RLIMIT_FSIZE, pol.fsize), (resource.RLIMIT_NOFILE, 256), (resource.RLIMIT_CORE, 0)): resource.setrlimit(r, (v, v))
            for d in cg: open(f"{d}/cgroup.procs", "w").write(str(os.getpid()))
            if pol.landlock:
                base = {sys.base_prefix, os.path.dirname(os.path.realpath(sys.executable)), "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/ld.so.cache", "/etc/localtime", "/proc", "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"}
                landlock_apply(sorted(base | set(pol.ro_paths)), [scratch, *pol.rw_extra, "/dev/null"], deny_net=pol.landlock_net)
            if pol.drop_privs:
                for cap in range(0, 64):
                    if libc.prctl(24, cap, 0, 0, 0) < 0 and ctypes.get_errno() == 22: break          # PR_CAPBSET_DROP until EINVAL
                os.setgroups([]); os.setresgid(GID, GID, GID); os.setresuid(UID, UID, UID)
            keep = [0, 1, 2, rdy_w, go_r] + ([sock_c.fileno()] if sock_c else [])
            os.dup2(in_r, 0); os.dup2(out_w, 1); os.dup2(err_w, 2)
            if sock_c: os.dup2(sock_c.fileno(), 3)
            for fd in sorted(set(os.listdir("/proc/self/fd")), key=int) if os.path.exists("/proc/self/fd") else []:
                f = int(fd)
                if f not in (0, 1, 2, 3, rdy_w, go_r): 
                    try: os.close(f)
                    except OSError: pass
            if pol.seccomp: seccomp_apply(deny_sockets=True)
            os.write(rdy_w, b"R"); os.read(go_r, 1)                               # barrier: parent verifies /proc/<pid>/status before payload runs
            os.chdir(scratch); os.execve(sys.executable, [sys.executable, "-I", "-c", code], env)
        except BaseException as e:
            try: os.write(rdy_w if False else err_w, f"HZ-LAUNCH-ERROR {type(e).__name__}: {e}\n".encode())
            except Exception: pass
            os._exit(125)
    # ---------------- parent
    for fd in (out_w, err_w, in_r): os.close(fd)
    if sock_c: sock_c.close()
    refused = None; bpid = 0; prof = {}; timed = False
    try:
        r, _, _ = select.select([pid_r], [], [], 10); bpid = struct.unpack("i", os.read(pid_r, 4))[0] if r else 0
        r, _, _ = select.select([rdy_r], [], [], 10)
        if not r or os.read(rdy_r, 1) != b"R": refused = "launch_failed: " + os.read(err_r, 4096).decode(errors="replace").strip()
        else:
            prof = effective_profile(bpid); bad = verify_profile(pol, prof, parent_ns)
            if bad: refused = "profile_mismatch: " + ",".join(bad)
        if refused: _kill(bpid, pid)
        else:
            os.write(go_w, b"G"); os.write(in_w, stdin) if stdin else None; os.close(in_w)
    except Exception as e: refused = f"launch_error: {e}"; _kill(bpid, pid)
    out, err, reqs = b"", b"", []
    end = time.time() + timeout_s; done = False; status = None
    while not refused and not done:
        rl = [out_r, err_r] + ([sock_p] if sock_p else []); r, _, _ = select.select(rl, [], [], 0.05)
        for f in r:
            if f is sock_p:
                try: broker.serve_once(sock_p, run_id, reqs)
                except Exception as e: reqs.append({"error": str(e)})
            else:
                d = os.read(f, 65536)
                if f == out_r: out += d
                else: err += d
        w, st = os.waitpid(pid, os.WNOHANG)
        if w: done, status = True, st
        elif time.time() > end: timed = True; _kill(bpid, pid); _, status = os.waitpid(pid, 0); done = True
    if not refused:
        for f, buf in ((out_r, "o"), (err_r, "e")):
            try:
                while select.select([f], [], [], 0.05)[0]:
                    d = os.read(f, 65536)
                    if not d: break
                    out += d if buf == "o" else b""; err += d if buf == "e" else b""
            except OSError: pass
    else:
        try: os.waitpid(pid, 0)
        except ChildProcessError: pass
    for fd in (out_r, err_r, rdy_r, rdy_w, go_r, go_w, pid_r, pid_w): 
        try: os.close(fd)
        except OSError: pass
    if sock_p: sock_p.close()
    for d in cg:
        try: os.rmdir(d)
        except OSError: pass
    ex = sg = None
    if status is not None: ex, sg = (os.WEXITSTATUS(status), None) if os.WIFEXITED(status) else (None, os.WTERMSIG(status))
    res = Result(run_id, ex, sg, timed, out.decode(errors="replace")[:20000], err.decode(errors="replace")[:20000], prof, pol.digest(), bpid, round(time.time() - t0, 3), refused, reqs)
    if own_scratch:
        import shutil; shutil.rmtree(scratch, ignore_errors=True)
    return res


def _kill(bpid, apid):
    for p in (bpid, apid):
        if p:
            try: os.kill(p, signal.SIGKILL)
            except OSError: pass


def _refused(run_id, pol, why): return Result(run_id, None, None, False, "", "", {}, pol.digest(), 0, 0.0, why)
