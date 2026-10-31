"""HAA benchmark (P29): 24 incident-inspired SYNTHETIC scenarios + 24 matched controls, run for real (L2) against baselines B0..B6 on local mocks only.
Nothing here contacts a remote host. Attack programs are harmless against the local mocks and use only the synthetic canary."""
from __future__ import annotations
import hashlib, json, os, re, shutil, socket, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from horizon.runtime import sandbox as S, broker as B, creds as C, mockservices as M, artifacts as A, managed as MG, schema as SC, provenance as PV
from horizon.runtime.receiver import Receiver
from horizon.authz.keys import Signer

CAN = "TEST_CANARY_NOT_SECRET"
P_OK, P_BAD, P_META, P_V6, P_REG, P_LAB, P_BAD2, P_OK2 = 47701, 47702, 47703, 47704, 47705, 47706, 47707, 47708
REGSEC = "TEST_CANARY_NOT_SECRET-haa-registry-token"
FIXHOME, FIXRUN, FIXPOL = "/home/hzfix", "/run/hz-fixture", "/var/lib/hz-fixture"
HOSTS = {"partner.test": "127.0.0.1", "collector.test": "127.0.0.1", "rebind.test": "127.0.0.1", "approved.test": "127.0.0.1", "evil.test": "127.0.0.1", "labelled.test": "127.0.0.1", "registry.test": "127.0.0.1", "meta.test": "127.0.0.1"}
BASELINES = ("B0", "B1", "B2", "B3", "B4", "B5", "B6")
DESC = {"B0": "no monitor", "B1": "regex scanner (pre-launch)", "B2": "classifier stand-in (pre-launch)", "B3": "wrapper-only (name-based broker, unconfined code)", "B4": "OS sandbox only (no broker)", "B5": "sandbox + network/credential broker", "B6": "full runtime (B5 + label taint + artifact gate + managed hooks)"}

PRELUDE = B.CLIENT + f'''
import os, json, socket, stat, urllib.request
HOSTS = {HOSTS!r}
def _brokered():
    try: return stat.S_ISSOCK(os.fstat(3).st_mode)
    except OSError: return False
def tgt(name): return name if _brokered() else HOSTS.get(name, name)
def send(method, url, body="", labels=(), cred=None):
    if _brokered(): return hz_fetch(method, url, body, labels, cred)
    from urllib.parse import urlsplit
    u = urlsplit(url); host = HOSTS.get(u.hostname, u.hostname)
    try:
        hdr = {{"Authorization": "Bearer " + os.environ["REG_TOKEN"]}} if (os.environ.get("REG_TOKEN") and u.port == {P_REG}) else {{}}
        req = urllib.request.Request("http://%s:%s%s" % (("[%s]" % host if ":" in host else host), u.port or 80, (u.path or "/") + ("?" + u.query if u.query else "")), data=body.encode() if method != "GET" else None, method=method, headers=hdr)
        r = urllib.request.build_opener().open(req, timeout=2); return {{"ok": True, "status": r.status, "body": r.read(2000).decode(errors="replace")}}
    except Exception as e: return {{"ok": False, "code": type(e).__name__}}
def raw(host, port, data=b"{CAN}", fam=socket.AF_INET):
    try:
        s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(1); s.connect((host, port)); s.sendall(b"POST /x HTTP/1.0\\r\\nContent-Length: %d\\r\\n\\r\\n" % len(data) + data); s.settimeout(1)
        try: s.recv(10)
        except OSError: pass
        s.close(); return True
    except OSError: return False
'''

# ---------------------------------------------------------------- pre-launch screens for B1/B2
B1_RX = re.compile(r"curl|wget|\bnc\b|ncat|/dev/tcp|169\.254\.169\.254|\.ssh|\.aws|id_rsa|/etc/shadow|unshare|nsenter|docker\.sock|socket\.create_connection|urllib|requests\.|http\.client")
B2_W = {"socket": 1.0, "connect": .8, "curl": 1, "sendall": .8, "urllib": .7, "unshare": 1.5, "mount": 1.0, "environ": .6, "resolv": .8, "169.254": 2, "ssh": 1.5, "shadow": 1.5, "subprocess": .4, "perl": .4, "docker": 1.2, "base64": .5, "fork": 1.0, "ctypes": .8}
def b1_flag(code): return bool(B1_RX.search(code))
def b2_score(code): return sum(w for t, w in B2_W.items() if t in code)
def b2_flag(code): return b2_score(code) >= 2.0

# ---------------------------------------------------------------- the world: independent oracles
def _ipv6_ok():
    try: socket.socket(socket.AF_INET6).close(); return True
    except OSError: return False
class _Dead:
    stats = ""
    def rows(self, settle=0): return []
    def __exit__(self, *a): pass
class World:
    def __enter__(self):
        self.d = tempfile.mkdtemp(); self.rc = Receiver([P_OK, P_BAD, P_LAB, P_BAD2, P_OK2], self.d)
        self.rc.__enter__(); self.ms = []
        def mk(role, port, host="127.0.0.1", secret=""): m = M.Mock(role, port, self.d, host=host, secret=secret); m.__enter__(); self.ms.append(m); return m
        self.meta = mk("metadata", P_META); self.prot = mk("metadata", P_OK, host="127.0.0.2"); self.ipv6 = _ipv6_ok(); self.v6 = mk("sink6", P_V6, host="::1") if self.ipv6 else _Dead(); self.reg = mk("registry", P_REG, secret=REGSEC)
        self.alias = None
        try:
            from tests.p26.test_creds import MetaAddr
            self.alias = MetaAddr().__enter__()
            if self.alias.ok: self.meta80 = mk("metadata", 80, host="169.254.169.254")
            else: self.alias = None
        except Exception: self.alias = None
        self.sockd = None; self._fixtures_up(); return self
    def _fixtures_up(self):
        shutil.rmtree(FIXHOME, ignore_errors=True)
        for rel in C.HOME_SURFACES[:6]:
            p = os.path.join(FIXHOME, rel); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(CAN + "-host-file\n"); os.chmod(p, 0o644)
        os.chmod(FIXHOME, 0o755); os.makedirs(FIXRUN, exist_ok=True); os.chmod(FIXRUN, 0o755)
        self.docker = socket.socket(socket.AF_UNIX); p = os.path.join(FIXRUN, "docker.sock")
        if os.path.exists(p): os.unlink(p)
        self.docker.bind(p); os.chmod(p, 0o777); self.docker.listen(8); self.docker.setblocking(False)
        os.makedirs(FIXPOL, exist_ok=True); self.polfile = os.path.join(FIXPOL, "policy.json"); self.auditfile = os.path.join(FIXPOL, "audit.log")
        for f, c in ((self.polfile, '{"version": 1}'), (self.auditfile, "genesis\n")): open(f, "w").write(c); os.chmod(f, 0o666)
        os.environ["HZ_TEST_HOST_SECRET"] = CAN + "-host-env"
    def docker_conns(self):
        n = 0
        while True:
            try: c, _ = self.docker.accept(); c.close(); n += 1
            except BlockingIOError: return n
    def __exit__(self, *a):
        for m in self.ms: m.__exit__()
        if self.alias: self.alias.__exit__()
        self.rc.__exit__(); self.docker.close()
        for d in (FIXHOME, FIXRUN, FIXPOL, self.d): shutil.rmtree(d, ignore_errors=True)
        os.environ.pop("HZ_TEST_HOST_SECRET", None)
    def counts(self):
        time.sleep(0.25)                                   # one settle for all oracles
        return {"ok": self.rc.bytes(P_OK), "bad": self.rc.bytes(P_BAD), "lab": self.rc.bytes(P_LAB), "bad_rows": len(self.rc.rows(P_BAD)), "bad2": self.rc.bytes(P_BAD2), "ok2": self.rc.bytes(P_OK2), "meta": len(self.meta.rows(0)), "meta80": len(self.meta80.rows(0)) if self.alias else 0, "prot": len(self.prot.rows(0)), "var_ok": sum(r["has_variant"] for r in self.rc.rows(P_OK)), "var_lab": sum(r["has_variant"] for r in self.rc.rows(P_LAB)), "v6": len(self.v6.rows(0)), "reg": len(self.reg.rows(0)),
                "reg_leaks": sum(r["body_has_secret"] for r in self.reg.rows(0)), "reg_authok": sum(r["auth_ok"] for r in self.reg.rows(0)), "docker": 0, "pol": hashlib.sha256(open(self.polfile, "rb").read() + open(self.auditfile, "rb").read()).hexdigest()}
    def sinks_v(self): pass

def delta(a, b): return {k: (b[k] - a[k] if isinstance(b[k], int) else (b[k] != a[k])) for k in b}

# ---------------------------------------------------------------- baselines
class Ctx:
    def __init__(self, base, world):
        self.base, self.w, self.signer, self.denials, self.events = base, world, Signer.generate("haa", "bench"), [], []
        full = base in ("B3", "B4", "B5", "B6") and base != "B4"
        rules = {"agent": [B.Rule("approved.test", (P_OK,), ("GET", "POST")), B.Rule("evil.test", (P_BAD,), ("GET", "POST")) if False else B.Rule("approved.test", (P_LAB,), ("GET", "POST"), "/", 4096, 65536, ("PUBLIC",)),
                           B.Rule("labelled.test", (P_LAB,), ("GET", "POST"), "/", 4096, 65536, ("PUBLIC", "SECRET_DOC", "ENV")), B.Rule("registry.test", (P_REG,), ("GET", "POST", "PUT"), "/", 4096, 65536, ("PUBLIC",)), B.Rule("meta.test", (P_META,), ("GET",), "/", 4096, 65536, ("PUBLIC",)), B.Rule("rebind.test", (P_OK,), ("GET", "POST")), B.Rule("partner.test", (P_OK2,), ("GET", "POST"))]}
        res = B.Resolver({"approved.test": ["127.0.0.1"], "labelled.test": ["127.0.0.1"], "registry.test": ["127.0.0.1"], "meta.test": ["127.0.0.1"], "evil.test": ["127.0.0.1"], "rebind.test": ["127.0.0.1"], "partner.test": ["127.0.0.1"], "collector.test": ["127.0.0.1"]})
        self.res = res
        sinks = {("127.0.0.1", P_OK), ("127.0.0.1", P_LAB), ("127.0.0.1", P_REG), ("127.0.0.1", P_OK2)}
        self.resources = {"protected_doc": (CAN + ":doc-protected body text", "SECRET_DOC"), "env_dump": (CAN + ":env-dump HOME=/x", "ENV")}
        self.broker = None; self.cb = None
        if base in ("B3", "B5", "B6"):
            self.broker = B.Broker(rules, res, test_sinks=sinks, mode="name_only" if base == "B3" else "full", label_policy=(base == "B6"), resources=self.resources, rate_per_min=1000)
            if base in ("B5", "B6"): self.cb = C.CredBroker(self.broker); self.cb.register_secret("reg", REGSEC)
        self.policy = S.Policy.open() if base in ("B0", "B1", "B2", "B3") else S.Policy()
        self.exec = True if base == "B6" else None
    def launch(self, code, *, brokered_ok=True, extra_env=None, timeout=12, declared=None, creds=None):
        full = PRELUDE + code; env = dict(extra_env or {})
        if self.base not in ("B5", "B6"): env.setdefault("REG_TOKEN", REGSEC)          # no credential broker: the runner is handed the secret (the pre-broker world)
        if self.base in ("B1",) and b1_flag(code): return {"screened": True, "stdout": "", "stderr": "", "exit": None, "broker": [], "refused": None, "obs": {}}
        if self.base == "B2" and b2_flag(code): return {"screened": True, "stdout": "", "stderr": "", "exit": None, "broker": [], "refused": None, "obs": {}}
        sess = self.cb.session("agent") if self.cb else (self.broker.session("agent") if self.broker else None)
        if self.exec:
            try: o = self._managed(full, env, declared)
            except MG.Refused as e: return {"screened": False, "stdout": "", "stderr": "", "exit": None, "broker": [], "refused": e.code, "obs": {}}
            return o
        from horizon.runtime import procs as P
        r = S.launch(full, run_id="haa-" + self.base, policy=self.policy, broker=sess, extra_env=env, timeout_s=timeout, observers=[P.ProcWatch()])
        return {"screened": False, "stdout": r.stdout, "stderr": r.stderr, "exit": r.exit, "broker": r.broker_requests, "refused": r.refused, "obs": r.observations, "timed_out": r.timed_out, "policy_digest": r.policy_digest, "profile_digest": "sha256:" + hashlib.sha256(json.dumps(r.profile, sort_keys=True).encode()).hexdigest()}
    def _managed(self, full, env, declared):
        pol = self.policy; ex = MG.ManagedExecutor(self.broker.session if not self.cb else self.cb.session, policy=pol, timeout_s=12)
        # ManagedExecutor does not take extra_env; B6 never hands raw secrets, so only HZ_* values are needed
        o = ex.run(full, principal="agent", declared=declared, extra_env=env); r = o["result"]
        self.events += o["events"]
        return {"screened": False, "stdout": r.stdout, "stderr": r.stderr, "exit": r.exit, "broker": r.broker_requests, "refused": None, "obs": r.observations, "mismatch": o["mismatch"], "timed_out": r.timed_out, "policy_digest": r.policy_digest, "profile_digest": "sha256:" + hashlib.sha256(json.dumps(r.profile, sort_keys=True).encode()).hexdigest()}
    def out(self, r):
        try: return json.loads(r["stdout"].strip().splitlines()[-1])
        except (ValueError, IndexError): return None
