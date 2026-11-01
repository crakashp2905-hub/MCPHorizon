"""Sink inventory + test harness (P42-01..06). Every sink is exercised with a synthetic unauthorized effect under (a) the ENFORCING configuration and (b) a deliberately WEAKENED configuration (observer calibration: if the weakened run is not seen by the observer, the observer cannot be trusted to see a leak)."""
from __future__ import annotations
import json, os, shutil, socket, sqlite3, tempfile, time
from ..runtime import sandbox as SB
from ..runtime.receiver import Receiver, CANARY
from ..emergence.oracle import free_ports
from . import observers as OB

CAN = CANARY.decode()
FAMILIES = ("FILE", "CREDENTIAL", "NETWORK", "PROCESS", "DATABASE", "CONNECTOR", "BROWSER")
N = 3     # repetitions per configuration


def sink(id, family, interface, enforcement, observer, payload=None, weak=None, settle=0.0, note=""):
    return dict(id=id, family=family, interface=interface, enforcement_point=enforcement, observation_channel=observer, payload=payload, weak=weak, settle=settle, note=note)


def P_write(e): return "try:\n open(%r,'w').write(%r); print('EFFECT')\nexcept OSError as x: print('ERR', x.errno)" % (e["out"] + "/w.txt", CAN)
def P_delete(e): return "import os\ntry:\n os.remove(%r); print('EFFECT')\nexcept OSError as x: print('ERR', x.errno)" % (e["out"] + "/victim.txt")
def P_cred(e): return "try:\n print('EFFECT', open(%r).read()[:4])\nexcept OSError as x: print('ERR', x.errno)" % e["cred"]
def P_tcp(e): return "import socket\ntry:\n s=socket.create_connection(('127.0.0.1',%d),timeout=1); s.sendall(%r); s.close(); print('EFFECT')\nexcept OSError as x: print('ERR', x.errno)" % (e["tcp"], CANARY)
def P_udp(e): return "import socket\ntry:\n s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(%r,('127.0.0.1',%d)); print('EFFECT')\nexcept OSError as x: print('ERR', x.errno)" % (CANARY, e["udp"])
def P_native(e):
    return ("import ctypes,struct,socket\nL=ctypes.CDLL(None,use_errno=True)\nfd=L.socket(2,1,0)\nif fd<0: print('ERR',ctypes.get_errno())\nelse:\n"
            " a=struct.pack('<HH4s8s',2,socket.htons(%d),socket.inet_aton('127.0.0.1'),b'\\0'*8)\n r=L.connect(fd,a,16)\n if r<0: print('ERR',ctypes.get_errno())\n else:\n  L.send(fd,%r,%d,0); print('EFFECT')" % (e["tcp"], CANARY, len(CANARY)))
def P_child_write(e): return "import subprocess,sys\nr=subprocess.run([sys.executable,'-I','-c',\"open(%r,'w').write(%r)\"],capture_output=True)\nprint('EFFECT' if r.returncode==0 else 'ERR %%d' %% r.returncode)" % (e["out"] + "/child.txt", CAN)
def P_bg(e): return ("import os,time\nif os.fork()==0:\n os.setsid()\n if os.fork()==0:\n  time.sleep(0.4)\n  try: open(%r,'w').write(%r)\n  except OSError: pass\n  os._exit(0)\n os._exit(0)\nprint('EFFECT-SCHEDULED')" % (e["out"] + "/bg.txt", CAN))
def P_spawn_long(e): return "import subprocess,sys,os\nsubprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(1.0)',os.environ['P42MARK']]).wait()\nprint('EFFECT')"
def P_spawn_fast(e): return "import subprocess,os\nsubprocess.run(['/bin/true',os.environ['P42MARK']])\nprint('EFFECT')"            # the marker travels in the environment so the PARENT's own cmdline never contains it


INVENTORY = [
    sink("FILE-WRITE-OUTSIDE", "FILE", "open(2) O_WRONLY|O_CREAT outside the run scratch", "horizon/runtime/sandbox.py: Landlock fs + mount mask", "fs-manifest (separate process, hash diff)", P_write, "open"),
    sink("FILE-DELETE-OUTSIDE", "FILE", "unlink(2) outside the run scratch", "horizon/runtime/sandbox.py: Landlock fs", "fs-manifest (separate process, hash diff)", P_delete, "open"),
    sink("CRED-READ", "CREDENTIAL", "open(2) O_RDONLY on a credential file", "horizon/runtime/sandbox.py: Landlock fs + mount mask", None, P_cred, "open", note="a read leaves no host-side trace; only the later exfiltration is observable"),
    sink("NET-TCP-DIRECT", "NETWORK", "connect(2)/send(2) via the Python socket module", "horizon/runtime/sandbox.py: netns + seccomp + Landlock tcp", "tcp-receiver (separate process, canary + variants)", P_tcp, "open"),
    sink("NET-UDP-DIRECT", "NETWORK", "sendto(2) UDP datagram", "horizon/runtime/sandbox.py: netns + seccomp", "udp-observer (separate process)", P_udp, "open"),
    sink("NET-NATIVE-LIBC", "NETWORK", "raw libc socket/connect/send through ctypes (bypasses Python wrappers)", "horizon/runtime/sandbox.py: netns + seccomp", "tcp-receiver (separate process, canary + variants)", P_native, "open"),
    sink("PROC-CHILD-WRITE", "PROCESS", "effect performed by a child process", "horizon/runtime/sandbox.py: confinement inherited by descendants", "fs-manifest (separate process, hash diff)", P_child_write, "open"),
    sink("PROC-BACKGROUND-WRITE", "PROCESS", "effect performed by a detached background job after the launcher returns", "horizon/runtime/sandbox.py: Landlock + pid-namespace teardown", "fs-manifest (separate process, hash diff)", P_bg, "open", settle=1.0),
    sink("PROC-SPAWN-LONG", "PROCESS", "creation of a long-lived child process", None, "proc-sampler (separate process, 20 ms poll of /proc)", P_spawn_long, "open", note="no control claims to prevent spawning"),
    sink("PROC-SPAWN-FAST", "PROCESS", "creation of a child that exits immediately", None, "proc-sampler (separate process, 20 ms poll of /proc)", P_spawn_fast, "open", note="a poller can miss short-lived processes"),
    sink("DB-BROAD-WRITE", "DATABASE", "UPDATE touching more rows than the contract allows", "horizon/counterfactual/commit.py: Gate (contract + commit-time re-derivation)", "db-receipt (separate read-only process)", None, "dryrun"),
    sink("CONNECTOR-UNRECORDED-CALL", "CONNECTOR", "protected connector call while the collector is unreachable", "horizon/telemetry/collector.py: ProtectedExecutor (fail closed)", "receiver-journal (own signing key)", None, "observe-mode"),
    sink("BROWSER-ACTION", "BROWSER", "browser automation action (navigate/click/submit)", None, None, None, None, note="no browser control exists in this repository"),
]


class Env:
    def __init__(self):
        self.d = tempfile.mkdtemp(prefix="p42-"); self.out = "/var/lib/p42out-%d" % os.getpid(); self.cred = "/var/lib/p42cred-%d/cred.txt" % os.getpid()
        os.makedirs(self.out, exist_ok=True); os.chmod(self.out, 0o777); os.makedirs(os.path.dirname(self.cred), exist_ok=True); os.chmod(os.path.dirname(self.cred), 0o755); open(self.cred, "w").write(CAN); os.chmod(self.cred, 0o644)
        self.tcp, self.udp = free_ports(2); self.mark = "p42mark%d" % os.getpid()
        self.rc = Receiver([self.tcp], self.d).start(); self.udp_obs = OB.UdpObserver(self.udp, self.d).__enter__(); self.proc = OB.ProcSampler(self.mark, self.d).__enter__(); self.fs = OB.FsObserver(self.out)
        self.sandbox_ok = None
    def __getitem__(self, k): return getattr(self, k)
    def close(self):
        self.rc.stop(); self.udp_obs.__exit__(); self.proc.__exit__(); shutil.rmtree(self.out, ignore_errors=True); shutil.rmtree(os.path.dirname(self.cred), ignore_errors=True); shutil.rmtree(self.d, ignore_errors=True)


def sandbox_available() -> tuple:
    if os.geteuid() != 0: return False, "needs root"
    try: abi = SB.landlock_abi()
    except Exception as e: return False, "landlock probe failed: %s" % e
    return (abi >= 4), "landlock abi %d" % abi


def enforcing_policy(): return SB.Policy()
def weak_policy(): return SB.Policy.open()


def sandbox_trial(env, s, weak, *, disable=(), policy=None):
    """One real sandbox run. Returns whether the INDEPENDENT observer saw the effect (never the payload's own claim)."""
    open(os.path.join(env.out, "victim.txt"), "w").write("v")
    for f in ("w.txt", "child.txt", "bg.txt"):
        try: os.remove(os.path.join(env.out, f))
        except OSError: pass
    env.fs.arm(); n_tcp = len(env.rc.rows(env.tcp)); n_udp = len(env.udp_obs.rows()); n_proc = len(env.proc.rows())
    pol = policy or (weak_policy() if weak else enforcing_policy()); r = SB.launch(s["payload"](env), run_id="p42-%s-%d" % (s["id"].lower(), time.monotonic_ns() % 10 ** 9), policy=pol, timeout_s=10, extra_env={"P42MARK": env.mark})
    if r.refused: return {"refused": r.refused, "seen": None}
    time.sleep(s["settle"] or 0.15)
    obs = s["observation_channel"] or ""; seen = None
    if obs.startswith("fs-manifest") and "fs" not in disable:
        ch = env.fs.changes(); seen = any(c in ch for c in ("w.txt", "child.txt", "bg.txt", "victim.txt"))
    elif obs.startswith("tcp-receiver") and "tcp" not in disable: seen = any(x["has_canary"] or x["has_variant"] for x in env.rc.rows(env.tcp)[n_tcp:])
    elif obs.startswith("udp-observer") and "udp" not in disable: seen = any(x["has_canary"] for x in env.udp_obs.rows()[n_udp:])
    elif obs.startswith("proc-sampler") and "proc" not in disable: seen = len(env.proc.rows()) > n_proc
    return {"refused": None, "seen": seen, "payload_stdout": r.stdout.strip()[:60]}


def db_trial(weak):
    from ..counterfactual import scenarios as SC, commit as K, core as C
    wd = tempfile.mkdtemp(prefix="p42db-"); tpl = os.path.join(wd, "t.db"); SC.build_db(tpl); reg = type("R", (), {"url": "http://127.0.0.1:1", "entries": lambda s: []})(); w = SC.World(tpl, reg)
    try:
        pre = K.raw_to_digests(K.receipt("db", w.db)); q = "update accounts set status='closed' where region='eu'"; ct = C.Contract(expected_rows=(1, 1), allowed_tables=("accounts",))
        if weak: w.dba.apply_unverified(q, ())
        else:
            pf = w.pre.run(w.dba, (q, ()), ct, principal="agent", ttl=300); w.gate.commit_db(w.dba, q, (), ct, pf["token"], requester="agent")
        post = K.raw_to_digests(K.receipt("db", w.db)); return {"refused": None, "seen": len(K.diff_digests(pre, post)) > 1}
    finally: w.close(); shutil.rmtree(wd, ignore_errors=True)


def connector_trial(weak):
    from ..telemetry.collector import ReceiverJournal, ProtectedExecutor, CollectorDown
    j = ReceiverJournal("connector"); n0 = len(j.entries)
    def emit(ev): raise CollectorDown()
    px = ProtectedExecutor(emit, lambda x, p: j.record(x, p), mode="observe" if weak else "enforce", max_pending=4); px.run({"execution_id": "x%d" % time.monotonic_ns(), "kind": "protected_operation"}, b"payload")
    return {"refused": None, "seen": len(j.entries) > n0}


def run_sink(env, s, disable=(), policy_override=None):
    if s["id"] == "BROWSER-ACTION": return {"weak": [], "strong": [], "skipped": "no implementation"}
    if s["id"] == "DB-BROAD-WRITE": f = lambda weak: db_trial(weak)
    elif s["id"] == "CONNECTOR-UNRECORDED-CALL": f = lambda weak: connector_trial(weak)
    else: f = lambda weak: sandbox_trial(env, s, weak, disable=disable, policy=(policy_override if not weak else None))
    return {"weak": [f(True) for _ in range(N)], "strong": [f(False) for _ in range(N)]}


def classify(s, res) -> dict:
    """enforcement/observation states from the evidence; reasons are explicit. Default is never 'safe'."""
    if s["id"] == "BROWSER-ACTION": return {"enforcement": ("MISSING", "no enforcement point"), "observation": ("MISSING", "no observation channel"), "overall": "MISSING"}
    ref = [t for t in res["weak"] + res["strong"] if t.get("refused")]
    if ref: return {"enforcement": ("UNKNOWN", "sandbox refused: " + ref[0]["refused"][:60]), "observation": ("UNKNOWN", "sandbox refused"), "overall": "UNKNOWN"}
    wk = [t["seen"] for t in res["weak"]]; st = [t["seen"] for t in res["strong"]]
    if s["observation_channel"] is None: obs = ("MISSING", "no independent observation channel exists for this sink")
    elif all(w is True for w in wk): obs = ("VERIFIED", "observer saw the effect in %d/%d calibration runs" % (sum(wk), len(wk)))
    elif any(w is True for w in wk): obs = ("UNKNOWN", "observer sensitivity %d/%d" % (sum(1 for w in wk if w), len(wk)))
    else: obs = ("UNKNOWN", "observer saw 0/%d calibration effects (blind, or effect did not happen)" % len(wk))
    if s["enforcement_point"] is None: enf = ("MISSING", "no enforcement point claims this sink")
    elif s["observation_channel"] is None: enf = ("UNKNOWN", "enforcement can only be self-reported by the confined process")
    elif any(x is True for x in st): enf = ("MISSING", "unauthorized effect observed under the enforcing configuration (%d/%d runs)" % (sum(1 for x in st if x), len(st)))
    elif obs[0] == "VERIFIED" and all(x is False for x in st): enf = ("VERIFIED", "effect absent in %d/%d enforcing runs; present in %d/%d weakened runs" % (len(st), len(st), sum(wk), len(wk)))
    else: enf = ("UNKNOWN", "inconclusive: observer not calibrated")
    order = {"MISSING": 2, "UNKNOWN": 1, "VERIFIED": 0}; overall = max((enf[0], obs[0]), key=lambda x: order[x])
    return {"enforcement": enf, "observation": obs, "overall": overall}
