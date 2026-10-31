"""Host-side observers (P26-09, P27-04/06/14/17). They watch the sandbox from OUTSIDE (host /proc, inotify), so the sandboxed code cannot falsify them. Limits are part of the contract:
ProcWatch polls (default ~50ms) so a process that lives shorter than the interval can be missed; FileWatch sees open/modify/create/delete inside the scratch directory only (depth 1 + dirs present at start)."""
from __future__ import annotations
import ctypes, os, struct, time

IN_ACCESS, IN_MODIFY, IN_CLOSE_WRITE, IN_OPEN, IN_CREATE, IN_DELETE = 0x1, 0x2, 0x8, 0x20, 0x100, 0x200
_libc = ctypes.CDLL(None, use_errno=True)


def _stat(pid):
    try:
        raw = open(f"/proc/{pid}/stat").read(); comm = raw[raw.index("(") + 1:raw.rindex(")")]; rest = raw[raw.rindex(")") + 2:].split()
        return {"pid": pid, "comm": comm, "ppid": int(rest[1]), "starttime": int(rest[19])}
    except (OSError, ValueError, IndexError): return None


def _cmdline(pid):
    try: return open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace").strip()[:200]
    except OSError: return ""


class ProcWatch:
    """Tracks every host process whose ancestry reaches the sandbox init (pid 1 of the new pid namespace). Identity = (pid, starttime) so pid reuse cannot alias."""
    name = "procs"
    def __init__(self, interval=0.0): self.seen, self.root, self.order = {}, None, []
    def start(self, scratch, bpid): self.root = bpid; self.poll()
    def poll(self):
        if self.root is None: return
        procs = {}
        for d in os.listdir("/proc"):
            if d.isdigit():
                s = _stat(int(d))
                if s: procs[s["pid"]] = s
        kids = {self.root}; changed = True
        while changed:
            changed = False
            for pid, s in procs.items():
                if pid not in kids and s["ppid"] in kids: kids.add(pid); changed = True
        for pid in kids:
            s = procs.get(pid)
            if s and (pid, s["starttime"]) not in self.seen:
                prof = {}
                try:
                    st = open(f"/proc/{pid}/status").read()
                    for l in st.splitlines():
                        k, _, v = l.partition(":")
                        if k in ("NoNewPrivs", "Seccomp", "CapEff", "Uid", "NSpid"): prof[k] = v.strip()
                except OSError: pass
                self.seen[(pid, s["starttime"])] = {"pid": pid, "ppid": s["ppid"], "comm": s["comm"], "cmdline": _cmdline(pid), "t": time.time(), "profile": prof}; self.order.append((pid, s["starttime"]))
    def stop(self):
        self.poll(); rows = [self.seen[k] for k in self.order]
        return {"processes": rows, "count": len(rows), "source": "host", "poll_limit": "processes shorter than the poll interval may be missed"}


class FileWatch:
    name = "files"
    def __init__(self, mask=IN_ACCESS | IN_MODIFY | IN_CLOSE_WRITE | IN_OPEN | IN_CREATE | IN_DELETE): self.mask, self.fd, self.wd, self.ev = mask, -1, {}, []
    def start(self, scratch, bpid):
        self.fd = _libc.inotify_init1(os.O_NONBLOCK)
        if self.fd < 0: raise OSError(ctypes.get_errno(), "inotify_init1")
        self.scratch = scratch; self._add(scratch)
        for n in os.listdir(scratch):
            p = os.path.join(scratch, n)
            if os.path.isdir(p) and not os.path.islink(p): self._add(p)
    def _add(self, p):
        w = _libc.inotify_add_watch(self.fd, p.encode(), self.mask)
        if w >= 0: self.wd[w] = p
    def poll(self):
        if self.fd < 0: return
        try: buf = os.read(self.fd, 65536)
        except BlockingIOError: return
        i = 0
        while i + 16 <= len(buf):
            wd, mask, _, ln = struct.unpack_from("iIII", buf, i); name = buf[i + 16:i + 16 + ln].split(b"\0")[0].decode(errors="replace"); i += 16 + ln
            base = self.wd.get(wd, "?"); path = os.path.join(base, name) if name else base
            for bit, k in ((IN_OPEN, "open"), (IN_ACCESS, "read"), (IN_MODIFY, "modify"), (IN_CLOSE_WRITE, "close_write"), (IN_CREATE, "create"), (IN_DELETE, "delete")):
                if mask & bit: self.ev.append({"op": k, "path": os.path.relpath(path, self.scratch)})
            if mask & IN_CREATE and mask & 0x40000000 and name: self._add(path)       # new subdirectory
    def stop(self):
        self.poll(); os.close(self.fd) if self.fd >= 0 else None; self.fd = -1; seen = []
        for e in self.ev:
            if e not in seen: seen.append(e)
        return {"events": seen, "source": "host-inotify", "scope": "scratch tree only"}
