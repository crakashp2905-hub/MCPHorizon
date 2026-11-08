"""OS-level mandatory mediation for the file sink (hardens ENG-PR05; addresses its same-OS-user bypass on Linux). Three uids: SINK owns the data directory (mode 0700) and runs the only writer process;
GATEWAY (permit-verifying process) is the only uid the sink will talk to (SO_PEERCRED check on every connection); AGENT is any other uid: it can neither open the directory nor be served by the socket.
The sink script is stdlib-only and self-contained so it can run unprivileged without importing the repo. It re-validates containment (realpath) itself and writes its own journal.
Needs root to switch uids (tests skip otherwise). Linux only. Does NOT protect against a kernel compromise, root-in-sandbox escape, or an agent that holds the GATEWAY uid."""
from __future__ import annotations
import hashlib, json, os, socket, subprocess, sys, time, base64

SINK_SCRIPT = r'''
import os, sys, json, socket, struct, hashlib, base64, time
sock_path, root, journal, allowed_uid = sys.argv[1], os.path.realpath(sys.argv[2]), sys.argv[3], int(sys.argv[4])
if os.path.exists(sock_path): os.unlink(sock_path)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(sock_path); os.chmod(sock_path, 0o666); s.listen(8)
open(sock_path + ".ready", "w").write("1")
done, fenced = {}, set()                      # rebuilt from the sink-owned journal so fences and records survive a sink restart
Z = "0" * 64
def rh(prev, rec): return hashlib.sha256(prev.encode() + json.dumps({k: v for k, v in rec.items() if k not in ("prev", "h")}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
head, n, tampered = Z, 0, False               # hash chain (prev, h): an edited, reordered or unchained record makes the sink refuse everything (fail closed)
for line in (open(journal).read().splitlines() if os.path.exists(journal) else []):
    try: r = json.loads(line)
    except ValueError: tampered = True; break
    if r.get("prev") != head or r.get("h") != rh(head, r): tampered = True; break
    head, n = r["h"], n + 1
    if "fence" in r: fenced.add(r["fence"])
    elif "effect_id" in r: done[r["effect_id"]] = r
def append(rec):
    global head, n
    rec = dict(rec); rec["prev"] = head; rec["h"] = rh(head, rec)
    with open(journal, "a") as f: f.write(json.dumps(rec, sort_keys=True) + "\n"); f.flush(); os.fsync(f.fileno())
    head, n = rec["h"], n + 1
    return rec
while True:
    c, _ = s.accept()
    try:
        pid, uid, gid = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        req = json.loads(c.makefile("r").readline() or "{}")
        if uid != allowed_uid: out = {"ok": False, "code": "PEER_NOT_GATEWAY"}
        elif tampered and req.get("op") != "stop": out = {"ok": False, "code": "JOURNAL_TAMPERED"}
        elif req.get("op") == "head": out = {"ok": True, "n": n, "head": head}
        elif req.get("op") == "stop": out = {"ok": True}; c.sendall((json.dumps(out) + "\n").encode()); break
        elif req.get("op") == "observe": out = {"ok": True, "observed": done.get(req["effect_id"])}
        elif req.get("op") == "fence":   # ATOMIC fence-and-observe: the loop is single-threaded, so no write can interleave between the read and the tombstone
            if req["effect_id"] not in fenced:
                fenced.add(req["effect_id"]); append({"fence": req["effect_id"], "ts": time.time()})
            out = {"ok": True, "observed": done.get(req["effect_id"])}
        elif req["effect_id"] in fenced: out = {"ok": False, "code": "FENCED"}
        elif req["effect_id"] in done: out = {"ok": False, "code": "ALREADY_WRITTEN"}
        else:
            real = os.path.realpath(req["path"])
            if not (real.startswith(root + os.sep)) or os.path.isdir(real): out = {"ok": False, "code": "OUTSIDE_ROOT"}
            else:
                data = base64.b64decode(req["data"]); tmp = real + ".tmp"; open(tmp, "wb").write(data); os.replace(tmp, real)
                rec = {"effect_id": req["effect_id"], "path": real, "sha256": hashlib.sha256(data).hexdigest(), "uid_peer": uid, "ts": time.time()}
                rec = append(rec); done[req["effect_id"]] = rec; out = {"ok": True, "receipt": rec}
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


def fence_req(effect_id: str) -> dict: return {"op": "fence", "effect_id": effect_id}
def observe_req(effect_id: str) -> dict: return {"op": "observe", "effect_id": effect_id}
def write_req(path: str, data: bytes, effect_id: str) -> dict: return {"op": "write", "path": path, "data": base64.b64encode(data).decode(), "effect_id": effect_id}

def head_req() -> dict: return {"op": "head"}
def verify_journal(path: str) -> tuple:
    """Offline check of a sink journal -> (ok, n_records, head). Same hash rule as the sink. Tail truncation is NOT detectable here: compare (n, head) with an externally held anchor from head_req()."""
    prev, n = "0" * 64, 0
    if not os.path.exists(path): return True, 0, prev
    for line in open(path).read().splitlines():
        try: r = json.loads(line)
        except ValueError: return False, n, prev
        h = hashlib.sha256(prev.encode() + json.dumps({k: v for k, v in r.items() if k not in ("prev", "h")}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if r.get("prev") != prev or r.get("h") != h: return False, n, prev
        prev, n = h, n + 1
    return True, n, prev
