"""OS-level mandatory mediation for the file sink (hardens ENG-PR05; addresses its same-OS-user bypass on Linux). Three uids: SINK owns the data directory (mode 0700) and runs the only writer process;
GATEWAY (permit-verifying process) is the only uid the sink will talk to (SO_PEERCRED check on every connection); AGENT is any other uid: it can neither open the directory nor be served by the socket.
The sink script is stdlib-only and self-contained so it can run unprivileged without importing the repo. It re-validates containment (realpath) itself and writes its own journal.
Needs root to switch uids (tests skip otherwise). Linux only. Does NOT protect against a kernel compromise, root-in-sandbox escape, or an agent that holds the GATEWAY uid."""
from __future__ import annotations
import json, os, socket, subprocess, sys, time, base64

SINK_SCRIPT = r'''
import os, sys, json, socket, struct, hashlib, base64, time
sock_path, root, journal, allowed_uid = sys.argv[1], os.path.realpath(sys.argv[2]), sys.argv[3], int(sys.argv[4])
if os.path.exists(sock_path): os.unlink(sock_path)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(sock_path); os.chmod(sock_path, 0o666); s.listen(8)
open(sock_path + ".ready", "w").write("1")
while True:
    c, _ = s.accept()
    try:
        pid, uid, gid = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        req = json.loads(c.makefile("r").readline() or "{}")
        if uid != allowed_uid: out = {"ok": False, "code": "PEER_NOT_GATEWAY"}
        elif req.get("op") == "stop": out = {"ok": True}; c.sendall((json.dumps(out) + "\n").encode()); break
        else:
            real = os.path.realpath(req["path"])
            if not (real.startswith(root + os.sep)) or os.path.isdir(real): out = {"ok": False, "code": "OUTSIDE_ROOT"}
            else:
                data = base64.b64decode(req["data"]); tmp = real + ".tmp"; open(tmp, "wb").write(data); os.replace(tmp, real)
                rec = {"effect_id": req["effect_id"], "path": real, "sha256": hashlib.sha256(data).hexdigest(), "uid_peer": uid, "ts": time.time()}
                open(journal, "a").write(json.dumps(rec, sort_keys=True) + "\n"); out = {"ok": True, "receipt": rec}
    except Exception as e: out = {"ok": False, "code": "SINK_ERROR:" + type(e).__name__}
    try: c.sendall((json.dumps(out) + "\n").encode())
    finally: c.close()
'''


def start_sink(workdir: str, sink_uid: int, gateway_uid: int):
    """Create <workdir>/data (0700, owned by sink_uid), run the sink as sink_uid. Returns (Popen, sock_path, data_dir, journal_path)."""
    data = os.path.join(workdir, "data"); jr = os.path.join(workdir, "journal.jsonl"); sp = os.path.join(workdir, "sink.sock"); sc = os.path.join(workdir, "sink.py")
    os.makedirs(data, exist_ok=True); open(jr, "a").close(); open(sc, "w").write(SINK_SCRIPT)
    for p, m in ((workdir, 0o755), (data, 0o700), (jr, 0o600), (sc, 0o644)): os.chmod(p, m); os.chown(p, sink_uid, sink_uid)
    def demote(): os.setgid(sink_uid); os.setuid(sink_uid)
    proc = subprocess.Popen([sys.executable, "-B", sc, sp, data, jr, str(gateway_uid)], preexec_fn=demote, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(100):
        if os.path.exists(sp + ".ready"): break
        time.sleep(0.05)
    else: raise RuntimeError("sink did not start")
    return proc, sp, data, jr


def call(sock_path: str, req: dict, *, as_uid: int | None = None) -> dict:
    """Client call, optionally from a different uid (forked, demoted child) — used by tests to play GATEWAY and AGENT."""
    code = ("import socket,sys,json\ns=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall((sys.argv[2]+'\\n').encode());print(s.makefile().readline())")
    def demote():
        if as_uid is not None: os.setgid(as_uid); os.setuid(as_uid)
    p = subprocess.run([sys.executable, "-B", "-c", code, sock_path, json.dumps(req)], preexec_fn=demote, capture_output=True, timeout=20)
    return json.loads(p.stdout.decode() or "{}") if p.returncode == 0 else {"ok": False, "code": "CLIENT_ERROR", "stderr": p.stderr.decode()[-200:]}


def write_req(path: str, data: bytes, effect_id: str) -> dict: return {"op": "write", "path": path, "data": base64.b64encode(data).decode(), "effect_id": effect_id}
