import json, os, shutil, socket, subprocess, tempfile, time, unittest
from horizon.runtime import broker as B, creds as C, mockservices as M, sandbox as S
OK = os.geteuid() == 0 and S.landlock_abi() >= 4
SEC = "TEST_CANARY_NOT_SECRET-registry-token-0001"
RP, MP = 47511, 47512
FIX = "/home/hzfix"; SOCKDIR = "/run/hz-fixture"
def mkbroker(extra=()):
    rules = {"agent": [B.Rule("registry.test", (RP,), ("GET", "POST", "PUT"), "/", 4096, 65536, ("PUBLIC",)), *extra]}
    return B.Broker(rules, B.Resolver({"registry.test": ["127.0.0.1"], "meta.test": ["127.0.0.1"]}), test_sinks={("127.0.0.1", RP)})
def run(code, cb, **kw): return S.launch(B.CLIENT + code, run_id=kw.pop("run_id", "t"), broker=cb.session("agent"), **kw)
def last(r): return json.loads(r.stdout.strip().splitlines()[-1])

class Fixture:
    """Synthetic host secrets (world-readable on purpose, so only the sandbox controls can be what hides them)."""
    def __enter__(self):
        for rel in C.HOME_SURFACES[:6]:
            p = os.path.join(FIX, rel); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write("TEST_CANARY_NOT_SECRET-host-file\n"); os.chmod(p, 0o644)
        os.chmod(FIX, 0o755); os.makedirs(SOCKDIR, exist_ok=True); os.chmod(SOCKDIR, 0o755); self.socks = []
        for n in ("ssh-agent.sock", "docker.sock"):
            p = os.path.join(SOCKDIR, n)
            if os.path.exists(p): os.unlink(p)
            s = socket.socket(socket.AF_UNIX); s.bind(p); os.chmod(p, 0o777); s.listen(4); self.socks.append((s, p))
        os.environ["HZ_TEST_HOST_SECRET"] = "TEST_CANARY_NOT_SECRET-host-env"; return self
    def __exit__(self, *a):
        for s, p in self.socks: s.close(); os.path.exists(p) and os.unlink(p)
        shutil.rmtree(FIX, ignore_errors=True); shutil.rmtree(SOCKDIR, ignore_errors=True); os.environ.pop("HZ_TEST_HOST_SECRET", None)

class MetaAddr:
    """Binds the real metadata address as an alias on the host loopback (legacy SIOCSIFADDR 'lo:hzmeta') so a listener exists where an attacker would look. Host-local only; removed afterwards."""
    NAME = b"lo:hzm"
    def _ioctl(self, req, ip=None, flags=None):
        import fcntl, struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if ip: ifr = struct.pack("16sH2s4s8s", self.NAME, socket.AF_INET, b"\0\0", socket.inet_aton(ip), b"\0" * 8)
            else: ifr = struct.pack("16sh14s", self.NAME, flags, b"\0" * 14)
            fcntl.ioctl(s, req, ifr)
        finally: s.close()
    def __enter__(self):
        try: self._ioctl(0x8916, "169.254.169.254"); self._ioctl(0x891C, "255.255.255.255"); self._ioctl(0x8914, flags=0x1 | 0x40); self.ok = True       # SIOCSIFADDR, SIOCSIFNETMASK, SIOCSIFFLAGS(UP|RUNNING)
        except OSError: self.ok = False
        return self
    def __exit__(self, *a):
        if self.ok:
            try: self._ioctl(0x8914, flags=0)
            except OSError: pass

class Broker_(unittest.TestCase):
    def setUp(self):
        self.t = [1000.0]; self.br = mkbroker(); self.cb = C.CredBroker(self.br, clock=lambda: self.t[0]); self.cb.register_secret("reg", SEC)
    def test_binding_and_lifecycle(self):
        u = f"http://registry.test:{RP}/auth-check"; ref = self.cb.issue("agent", "reg", "GET", u, ttl_s=10, uses=2)
        self.assertEqual(self.cb.call("other", ref, "GET", u)["code"], "CRED_PRINCIPAL_MISMATCH"); self.assertEqual(self.cb.call("agent", ref, "POST", u)["code"], "CRED_BINDING_MISMATCH")
        self.assertEqual(self.cb.call("agent", ref, "GET", u + "x")["code"], "CRED_BINDING_MISMATCH"); self.assertEqual(self.cb.call("agent", "cref_nope", "GET", u)["code"], "CRED_UNKNOWN")
        self.t[0] += 11; self.assertEqual(self.cb.call("agent", ref, "GET", u)["code"], "CRED_EXPIRED")
        with self.assertRaises(KeyError): self.cb.issue("agent", "nosvc", "GET", u)
    def test_use_count_exhausts(self):
        u = f"http://registry.test:{RP}/auth-check"; ref = self.cb.issue("agent", "reg", "GET", u, uses=1); self.cb.call("agent", ref, "GET", u)       # consumed even if the service is down (no free retries)
        self.assertEqual(self.cb.call("agent", ref, "GET", u)["code"], "CRED_EXHAUSTED")
    def test_revoke_paths(self):
        u = f"http://registry.test:{RP}/auth-check"
        for how in ("revoke", "revoke_all", "scope"):
            ref = self.cb.issue("agent", "reg", "GET", u)
            if how == "revoke": self.cb.revoke(ref)
            elif how == "revoke_all": self.cb.revoke_all()
            else:
                with self.cb.scope("agent"): pass
            self.assertEqual(self.cb.call("agent", ref, "GET", u)["code"], "CRED_REVOKED", how)
    def test_secret_in_payload_rejected_all_encodings(self):
        import base64, urllib.parse
        u = f"http://registry.test:{RP}/publish"; 
        for enc in (SEC, base64.b64encode(SEC.encode()).decode(), SEC.encode().hex(), urllib.parse.quote(SEC)):
            ref = self.cb.issue("agent", "reg", "POST", u); self.assertEqual(self.cb.call("agent", ref, "POST", u, ("pkg:" + enc).encode())["code"], "SECRET_IN_PAYLOAD", enc)
        ref = self.cb.issue("agent", "reg", "GET", f"http://registry.test:{RP}/p?x={SEC}"); self.assertEqual(self.cb.call("agent", ref, "GET", f"http://registry.test:{RP}/p?x={SEC}")["code"], "SECRET_IN_PAYLOAD")
    def test_body_hash_binding(self):
        import hashlib
        u = f"http://registry.test:{RP}/publish"; ref = self.cb.issue("agent", "reg", "POST", u, body_sha256=hashlib.sha256(b"A").hexdigest()); self.assertEqual(self.cb.call("agent", ref, "POST", u, b"B")["code"], "CRED_BINDING_MISMATCH")
    def test_audit_never_contains_secret(self):
        u = f"http://registry.test:{RP}/auth-check"; ref = self.cb.issue("agent", "reg", "GET", u); self.cb.call("agent", ref, "GET", u); self.cb.revoke(ref)
        blob = json.dumps(self.cb.audit) + json.dumps(self.br.log) + repr(self.cb) ; self.assertNotIn(SEC, blob); self.assertTrue(all(k in ("event", "ref", "principal", "service", "ok", "code", "why") for a in self.cb.audit for k in a))
    def test_classify_diagnostic(self):
        for c, w in [("python3 --version", "ALLOWED_DIAGNOSTIC"), ("ls", "ALLOWED_DIAGNOSTIC"), ("cat /etc/resolv.conf", "SENSITIVE_RECON"), ("printenv", "SENSITIVE_RECON"), ("cat ~/.aws/credentials", "SENSITIVE_RECON"), ("curl http://169.254.169.254/", "SENSITIVE_RECON"), ("rm -rf x", "OTHER")]: self.assertEqual(C.classify_diagnostic(c), w, c)

@unittest.skipUnless(OK, "UNSUPPORTED environment: root + Landlock needed (HR-G3 not exercised)")
class Live(unittest.TestCase):
    def setUp(self): self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, True)
    def test_registry_auth_without_embedding(self):
        with M.Mock("registry", RP, self.d, secret=SEC) as reg:
            br = mkbroker(); cb = C.CredBroker(br); cb.register_secret("reg", SEC); u = f"http://registry.test:{RP}/publish"; ref = cb.issue("agent", "reg", "POST", u, uses=2)
            r = run(f"import json;print(json.dumps([hz_fetch('POST','{u}','package-bytes TEST_CANARY_NOT_SECRET'.replace('TEST_CANARY_NOT_SECRET','clean'),cred='{ref}'), hz_fetch('POST','{u}','pkg '+open('/proc/self/environ').read()[:0]+'{SEC}',cred='{ref}')]))", cb)
            o = last(r); rows = reg.rows(); self.assertTrue(o[0]["ok"]); self.assertEqual(o[1]["code"], "SECRET_IN_PAYLOAD")
            self.assertEqual(len(rows), 1); self.assertTrue(rows[0]["auth_ok"]); self.assertFalse(rows[0]["body_has_secret"])           # legit: authenticated, nothing embedded
            self.assertNotIn(SEC, r.stdout + r.stderr + json.dumps(r.broker_requests) + json.dumps(cb.audit))                               # sandbox/transcript never saw it
            self.assertTrue(all(x["cred_ref"] == ref for x in r.broker_requests))
    def test_leak_oracle_detects_embedded_secret_control(self):
        # control for the oracle itself: a deliberately leaky POST (made by trusted test code, bypassing the broker) IS flagged by the independent receiver
        import urllib.request
        with M.Mock("registry", RP, self.d, secret=SEC) as reg:
            urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{RP}/publish", data=("pkg " + SEC).encode(), method="POST", headers={"Authorization": "Bearer " + SEC})).read()
            rows = reg.rows(); self.assertTrue(rows[0]["body_has_secret"] and rows[0]["auth_ok"])
    def test_sandbox_cannot_present_raw_secret_or_guess_refs(self):
        with M.Mock("registry", RP, self.d, secret=SEC) as reg:
            br = mkbroker(); cb = C.CredBroker(br); cb.register_secret("reg", SEC); u = f"http://registry.test:{RP}/auth-check"
            r = run(f"import json;print(json.dumps([hz_fetch('GET','{u}',cred='{SEC}'), hz_fetch('GET','{u}',cred='cref_0000000000000000'), hz_fetch('GET','{u}')]))", cb); o = last(r)
            self.assertEqual([x.get("code") for x in o[:2]], ["CRED_UNKNOWN", "CRED_UNKNOWN"]); self.assertTrue(o[2]["ok"]); self.assertEqual([x["auth_present"] for x in reg.rows()], [False])     # uncredentialed call carries no Authorization
    def test_credential_not_forwarded_across_redirect_and_echo_scrubbed(self):
        with M.Mock("registry", RP, self.d, secret=SEC) as reg:
            br = mkbroker(); cb = C.CredBroker(br); cb.register_secret("reg", SEC)
            u = f"http://registry.test:{RP}/redir?to=http://registry.test:{RP}/echo-auth"; ref = cb.issue("agent", "reg", "GET", u)
            r = run(f"import json;print(json.dumps(hz_fetch('GET','{u}',cred='{ref}')))", cb); o = last(r); rows = reg.rows()
            self.assertEqual([x["auth_present"] for x in rows], [True, False]); self.assertIn('"you_sent": ""', o["body"]) if o.get("ok") else None
            u2 = f"http://registry.test:{RP}/echo-auth"; ref2 = cb.issue("agent", "reg", "GET", u2); r2 = run(f"import json;print(json.dumps(hz_fetch('GET','{u2}',cred='{ref2}')))", cb)
            self.assertNotIn(SEC, r2.stdout); self.assertIn("<REDACTED:CREDENTIAL>", r2.stdout)
    def test_revocation_on_timeout_and_emergency_stop(self):
        with M.Mock("registry", RP, self.d, secret=SEC) as reg:
            br = mkbroker(); cb = C.CredBroker(br); cb.register_secret("reg", SEC); u = f"http://registry.test:{RP}/auth-check"; ref = cb.issue("agent", "reg", "GET", u, uses=5)
            r = run("import time;time.sleep(30)", cb, timeout_s=1); self.assertTrue(r.timed_out); cb.revoke_all("agent", "timeout")
            self.assertEqual(cb.call("agent", ref, "GET", u)["code"], "CRED_REVOKED"); self.assertEqual(reg.rows(), [])
    def test_metadata_unreachable_from_every_path(self):
        with MetaAddr() as m:
            if not m.ok: self.skipTest("UNSUPPORTED: cannot bind metadata alias on lo")
            with M.Mock("metadata", 80, self.d, host="169.254.169.254") as meta, M.Mock("metadata", MP, self.d) as sim:
                # control: the listener is alive from the host
                socket.create_connection(("169.254.169.254", 80), timeout=2).sendall(b"GET /latest/meta-data/ HTTP/1.0\r\n\r\n"); self.assertEqual(len(meta.rows()), 1); open(meta.stats, "w").close(); open(sim.stats, "w").close()
                br = B.Broker({"agent": [B.Rule("approved.test", (80, MP), ("GET",), "/", 4096, 65536, ("PUBLIC",)), B.Rule("redir.test", (RP,), ("GET",))]},
                              B.Resolver({"approved.test": ["169.254.169.254"], "alias1.test": ["169.254.169.254"], "redir.test": ["127.0.0.1"]}), test_sinks={("127.0.0.1", RP)})
                cb = C.CredBroker(br)
                with M.Mock("registry", RP, self.d) as reg:
                    code = (f"import json,socket\nres=[]\nfor ip,p in [('169.254.169.254',80),('127.0.0.1',{MP}),('100.100.100.200',80),('169.254.170.2',80)]:\n  try: socket.create_connection((ip,p),timeout=1); res.append('CONNECTED')\n  except OSError as e: res.append(e.errno)\n"
                            f"res.append(hz_fetch('GET','http://approved.test:80/latest/meta-data/')['code'])\nres.append(hz_fetch('GET','http://169.254.169.254/latest/meta-data/')['code'])\nres.append(hz_fetch('GET','http://[::ffff:169.254.169.254]/')['code'])\nres.append(hz_fetch('GET','http://2852039166/')['code'])\n"
                            f"res.append(hz_fetch('GET','http://redir.test:{RP}/redir?to=http://169.254.169.254/latest/meta-data/')['code'])\nprint(json.dumps(res))")
                    r = run(code, cb); o = last(r)
                    self.assertNotIn("CONNECTED", o[:4]); self.assertEqual(o[4], "DESTINATION_CLASS_DENIED"); self.assertEqual(o[5], "DESTINATION_NOT_APPROVED"); self.assertEqual(o[8], "REDIRECT_DESTINATION_NOT_APPROVED")
                    self.assertEqual(meta.rows(), []); self.assertEqual(sim.rows(), [])                                                         # simulator oracle: zero served requests
    def test_inventory_nothing_exposed_and_control_exposes(self):
        with Fixture():
            rows = C.surface_inventory(FIX); self.assertTrue(rows); self.assertFalse([r for r in rows if r["exposed"]], [r for r in rows if r["exposed"]])
            self.assertTrue([r for r in rows if r["kind"] == "file" and r["host_exists"]])                                                  # surfaces really existed
            # ablation: with mounts unmasked and Landlock off, the same files ARE readable by uid 10001 => the controls are what hides them
            weak = S.Policy(mntns=False, landlock=False, landlock_net=False, mask=()); r = S.launch(f"print(open('{FIX}/.ssh/id_rsa').read())", run_id="abl", policy=weak)
            if r.refused: self.skipTest("ablation policy refused: " + r.refused)
            self.assertIn("TEST_CANARY_NOT_SECRET-host-file", r.stdout)
    def test_diagnostics_allowed_but_recon_confined(self):
        with Fixture():
            code = ("import subprocess,json,os\nout={}\nout['ver']=subprocess.run(['python3','--version'],capture_output=True).returncode\nout['ls']=subprocess.run(['ls'],capture_output=True).returncode\n"
                    "for k,p in [('resolv','/etc/resolv.conf'),('shadow','/etc/shadow'),('home','/home/hzfix/.ssh/id_rsa'),('run','/run/hz-fixture/docker.sock')]:\n  try: open(p).read(1); out[k]='READ'\n  except OSError as e: out[k]=e.errno\nout['env']=sorted(k for k in os.environ if 'SECRET' in k or 'TOKEN' in k or 'KEY' in k)\nprint(json.dumps(out))")
            o = last(S.launch(code, run_id="diag")); self.assertEqual((o["ver"], o["ls"]), (0, 0)); self.assertTrue(all(o[k] != "READ" for k in ("resolv", "shadow", "home", "run"))); self.assertEqual(o["env"], [])
    def test_cross_tenant_and_link_escapes(self):
        os.makedirs(S.SCRATCH_BASE, exist_ok=True); a = tempfile.mkdtemp(dir=S.SCRATCH_BASE); open(os.path.join(a, "secret"), "w").write("TEST_CANARY_NOT_SECRET-tenantA"); os.chmod(a, 0o755); os.chmod(os.path.join(a, "secret"), 0o644); self.addCleanup(shutil.rmtree, a, True)
        code = (f"import os,json\nout={{}}\ntry: os.symlink('{a}/secret','l1')\nexcept OSError as e: out['mk']=e.errno\n"
                f"def t(k,p):\n  try: out[k]='READ:'+open(p).read()[:40]\n  except OSError as e: out[k]=e.errno\n"
                f"t('abs','{a}/secret'); t('dots','../'+os.path.basename('{a}')+'/secret'); t('sym','l1'); t('procroot','/proc/self/root{a}/secret'); t('proc1','/proc/1/root{a}/secret'); t('cwd','/proc/self/cwd/../'+os.path.basename('{a}')+'/secret')\n"
                f"try: os.link('{a}/secret','hl'); out['hl']='LINKED'\nexcept OSError as e: out['hl']=e.errno\ntry: os.system('mount --bind {a} /tmp'); out['bind']=os.system('test -e /tmp/secret')\nexcept OSError as e: out['bind']=e.errno\nprint(json.dumps(out))")
        r = S.launch(code, run_id="tenantB"); o = last(r); self.assertNotIn("tenantA", r.stdout); self.assertFalse([k for k, v in o.items() if isinstance(v, str) and v.startswith("READ")], o); self.assertNotEqual(o["bind"], 0)
    def test_no_inherited_handles_even_in_children(self):
        fd = os.open(__file__, os.O_RDONLY); os.set_inheritable(fd, True)
        try:
            code = f"import os,subprocess,json\nme=[os.readlink('/proc/self/fd/'+x) for x in os.listdir('/proc/self/fd') if os.path.exists('/proc/self/fd/'+x)]\nch=subprocess.run(['sh','-c','for f in /proc/self/fd/*; do readlink $f; done'],capture_output=True,text=True).stdout.split()\nprint(json.dumps([me,ch]))"
            o = last(S.launch(code, run_id="fd")); self.assertFalse([x for x in o[0] + o[1] if x.endswith("test_creds.py")], o)
            r = S.launch(f"import os\ntry: os.fstat({fd}); print('INHERITED')\nexcept OSError: print('closed')", run_id="fd2"); self.assertEqual(r.stdout.strip(), "closed")
        finally: os.close(fd)
    def test_host_observed_file_provenance(self):
        from horizon.runtime import procs as P
        fw = P.FileWatch(); code = "open('a.txt','w').write('x');print(open('a.txt').read())\ntry: open('/etc/shadow')\nexcept OSError: pass"
        r = S.launch(code, run_id="fw", observers=[fw]); ev = r.observations["files"]; ops = {(e["op"], e["path"]) for e in ev["events"]}
        self.assertTrue({("create", "a.txt"), ("modify", "a.txt")} <= ops); self.assertEqual(ev["source"], "host-inotify"); self.assertFalse([e for e in ev["events"] if "shadow" in e["path"]])
if __name__ == "__main__": unittest.main()
