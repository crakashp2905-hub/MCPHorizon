import json, os, socket, sys, tempfile, unittest
from unittest import mock
from horizon.runtime import sandbox as S
from horizon.runtime.receiver import Receiver

CAN = S.os.geteuid() == 0 and S.platform.machine() == "x86_64" and S.landlock_abi() >= 4
need = unittest.skipUnless(CAN, "UNSUPPORTED environment: needs root, x86_64, Landlock ABI>=4 (HR-G1 not exercised here)")
PORTS = [47311, 47312]


def run(code, policy=None, **kw): return S.launch(code, run_id="t" + str(abs(hash(code)) % 10**6), policy=policy or S.Policy(), **kw)
def out(r): return json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else {"stdout_empty": True, "err": r.stderr[-300:], "refused": r.refused}


PROBE_NET = "import socket,json\ntry:\n s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(2);s.connect(('127.0.0.1',%d));s.sendall(b'POST / HTTP/1.1\\r\\n\\r\\nTEST_CANARY_NOT_SECRET');print(json.dumps({'ok':True}))\nexcept OSError as e: print(json.dumps({'ok':False,'errno':e.errno}))"
PROBE_NS = "import ctypes,json,os\nl=ctypes.CDLL(None,use_errno=True)\nr2=l.mount(b'none',b'/tmp',b'tmpfs',0,None);e2=ctypes.get_errno()\nr=l.unshare(0x10000000);e1=ctypes.get_errno()\nr3=l.setns(-1,0);e3=ctypes.get_errno()\nprint(json.dumps({'unshare_user':[r,e1],'mount':[r2,e2],'setns':[r3,e3]}))"


@need
class Isolation(unittest.TestCase):
    def test_profile_verified_and_minimal(self):
        r = run("print(1)"); self.assertIsNone(r.refused); p = r.profile
        self.assertEqual((p["uid"], p["nonewprivs"], p["seccomp"], int(p["cap_eff"], 16), int(p["cap_bnd"], 16)), ("10001", "1", "2", 0, 0)); self.assertEqual(r.policy_digest, S.Policy().digest())
    def test_namespaces_distinct_from_host(self):
        r = run("print(1)"); host = S._ns_ids(os.getpid())
        for k in ("net", "mnt", "pid", "ipc", "uts"): self.assertNotEqual(r.profile["ns"][k], host[k], k)
    def test_clean_env_no_host_creds_and_no_inherited_fds(self):
        os.environ["AWS_SECRET_ACCESS_KEY"] = "TEST_ONLY"; f = open(__file__)
        try: r = run("import os,json;print(json.dumps({'env':sorted(os.environ),'fds':sorted(os.listdir('/proc/self/fd'))}))")
        finally: del os.environ["AWS_SECRET_ACCESS_KEY"]; f.close()
        o = out(r); self.assertNotIn("AWS_SECRET_ACCESS_KEY", o["env"]); self.assertTrue(set(o["env"]) <= {"PATH", "HOME", "TMPDIR", "HZ_RUN_ID", "LANG", "PYTHONDONTWRITEBYTECODE"}); self.assertTrue(set(map(int, o["fds"])) <= {0, 1, 2, 3, 4}, o["fds"])
    def test_kernel_denies_namespace_and_mount_ops(self):
        o = out(run(PROBE_NS)); self.assertEqual(o["unshare_user"], [-1, 1]); self.assertEqual(o["mount"], [-1, 1]); self.assertEqual(o["setns"], [-1, 1])        # EPERM from seccomp
    def test_direct_network_blocked_by_each_layer_independently(self):
        with tempfile.TemporaryDirectory() as d, Receiver(PORTS, d) as rc:
            base = dict(netns=False, seccomp=False, landlock_net=False)
            r0 = out(run(PROBE_NET % PORTS[0], S.Policy(**base))); self.assertTrue(r0["ok"]); self.assertGreater(rc.bytes(PORTS[0]), 0)                       # no network layer: lands (baseline harm, observed by the independent receiver)
            before = rc.bytes(PORTS[0])
            for name, pol in (("seccomp", S.Policy(**{**base, "seccomp": True})), ("netns", S.Policy(**{**base, "netns": True})), ("landlock_net", S.Policy(**{**base, "landlock_net": True}))):
                o = out(run(PROBE_NET % PORTS[0], pol)); self.assertFalse(o["ok"], name)
            self.assertEqual(rc.bytes(PORTS[0]), before)       # receiver saw nothing from any single-layer run
    def test_filesystem_secrets_and_writes_denied_scratch_allowed(self):
        os.makedirs("/root/.hz_fake_home/.ssh", exist_ok=True); open("/root/.hz_fake_home/.ssh/id_test", "w").write("TEST_CANARY_NOT_SECRET")
        code = "import json\nr={}\nfor k,p in (('ssh','/root/.hz_fake_home/.ssh/id_test'),('shadow','/etc/shadow'),('write_etc','/etc/hz_x'),('write_root','/root/x')):\n try: open(p,'w' if k.startswith('write') else 'r').close(); r[k]='OPEN'\n except OSError as e: r[k]=e.errno\nopen('s.txt','w').write('x'); r['scratch']=open('s.txt').read()\nprint(json.dumps(r))"
        try: o = out(run(code))
        finally: os.remove("/root/.hz_fake_home/.ssh/id_test")
        self.assertEqual((o["ssh"], o["shadow"], o["write_etc"], o["write_root"], o["scratch"]), (2, 13, 13, 30, "x"))      # /root hidden (ENOENT) and read-only (EROFS) by the mount mask; /etc denied (EACCES) by Landlock+uid; scratch works
        o0 = out(run(code.replace("/root/.hz_fake_home/.ssh/id_test", "/etc/passwd"), S.Policy(landlock=False, drop_privs=False)))
        self.assertEqual(o0["shadow"], "OPEN")      # control: without Landlock+uid drop the same read succeeds
    def test_host_runtime_socket_unreachable(self):
        p = tempfile.mktemp(prefix="hz-docker-", suffix=".sock", dir="/var/tmp"); s = socket.socket(socket.AF_UNIX); s.bind(p); s.listen(1); os.chmod(p, 0o777)      # deliberately world-connectable: DAC would NOT stop the sandbox
        try:
            o0 = out(run(f"import socket,json\ns=socket.socket(socket.AF_UNIX)\ntry: s.connect({p!r});print(json.dumps({{'ok':True}}))\nexcept OSError as e: print(json.dumps({{'ok':False,'errno':e.errno}}))", S.Policy(mntns=False, landlock=False)))
            self.assertEqual(o0, {"ok": True})      # control: without the mount-namespace mask the world-connectable host socket IS reachable (Landlock ABI<9 does not scope pathname unix sockets)
            o = out(run(f"import socket,json\ns=socket.socket(socket.AF_UNIX)\ntry: s.connect({p!r});print(json.dumps({{'ok':True}}))\nexcept OSError as e: print(json.dumps({{'ok':False,'errno':e.errno}}))"))
            self.assertEqual(o, {"ok": False, "errno": 2})        # path masked: not even visible
        finally: s.close(); os.remove(p)
    def test_descendants_inherit_confinement(self):
        code = "import subprocess,sys,json\nc=subprocess.run([sys.executable,'-I','-c','import json;s=dict(l.split(\":\",1) for l in open(\"/proc/self/status\").read().splitlines() if \":\" in l);print(json.dumps({k:s[k].strip() for k in (\"Uid\",\"Seccomp\",\"NoNewPrivs\",\"CapEff\")}))'],capture_output=True,text=True)\nprint(c.stdout.strip().splitlines()[-1])"
        o = out(run(code)); self.assertEqual((o["Seccomp"], o["NoNewPrivs"], int(o["CapEff"], 16)), ("2", "1", 0)); self.assertTrue(o["Uid"].startswith("10001"))
    def test_fork_bomb_bounded_and_legit_build_passes(self):
        bomb = "import os,json\nn=0\npids=[]\ntry:\n for _ in range(2000):\n  p=os.fork()\n  if p==0:\n   import time;time.sleep(3);os._exit(0)\n  pids.append(p);n+=1\nexcept OSError as e: print(json.dumps({'forked':n,'errno':e.errno}))\nfinally:\n import signal\n [os.kill(p,9) for p in pids]"
        o = out(run(bomb, S.Policy(nproc=40))); self.assertLess(o["forked"], 40); self.assertEqual(o["errno"], 11)
        build = """import py_compile,json,subprocess,sys
open('m.py','w').write('def f(x):\\n return x+1\\n')
py_compile.compile('m.py',doraise=True)
r=subprocess.run([sys.executable,'-I','-c',"import sys;sys.path.insert(0,'.');import m;print(m.f(1))"],capture_output=True,text=True)
print(json.dumps({'ok':r.stdout.strip()=='2'}))"""
        self.assertEqual(out(run(build, S.Policy(nproc=64))), {"ok": True})        # positive control under the same isolation
    def test_timeout_kills_process_tree(self):
        r = run("import time,subprocess,sys\nsubprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\ntime.sleep(60)", timeout_s=1.0); self.assertTrue(r.timed_out)
    def test_full_ablation_every_layer_has_effect(self):
        b = dict(PROBE_NS=PROBE_NS)
        o = out(run(PROBE_NS, S.Policy(seccomp=False, drop_privs=False, landlock=False))); self.assertEqual(o["mount"][0], 0)      # without seccomp AND the uid/cap drop the mount succeeds (inside the PRIVATE mount ns, so the host is untouched)
        o = out(run(PROBE_NS, S.Policy(seccomp=False))); self.assertEqual(o["mount"], [-1, 1])      # defence in depth: capability drop alone also denies


@need
class Refusal(unittest.TestCase):
    def test_refuses_without_privilege_or_landlock(self):
        with mock.patch("os.geteuid", return_value=1000): self.assertIn("UNSUPPORTED", run("print(1)").refused)
        with mock.patch.object(S, "landlock_abi", return_value=0): self.assertIn("Landlock", run("print(1)").refused)
        with mock.patch.object(S.platform, "machine", return_value="aarch64"): self.assertIn("x86_64", run("print(1)").refused)
    def test_refuses_on_profile_mismatch(self):
        prof = {"uid": "0", "gid": "0", "nonewprivs": "0", "seccomp": "0", "cap_eff": "1", "cap_bnd": "1", "cap_prm": "1", "ns": {k: "same" for k in ("net", "mnt", "pid", "ipc", "uts")}}
        bad = S.verify_profile(S.Policy(), prof, {k: "same" for k in prof["ns"]}); self.assertEqual(set(bad), {"uid_not_dropped", "caps_not_dropped", "bounding_set_not_cleared", "no_new_privs_missing", "seccomp_not_installed", "net_ns_shared", "mnt_ns_shared", "pid_ns_shared"})
        self.assertEqual(S.verify_profile(S.Policy.open(), prof, {k: "same" for k in prof["ns"]}), [])
    def test_cgroup_unavailable_refuses_not_weakens(self):
        with mock.patch.object(S, "_cgroup_setup", side_effect=S.Unsupported("cgroup memory: nope")): r = run("print(1)", S.Policy(cgroup=True)); self.assertIn("UNSUPPORTED", r.refused); self.assertEqual(r.exit, None)
    def test_seccomp_program_structure(self):
        p = S.seccomp_program(); self.assertEqual(len(p) % 8, 0); self.assertLess(len(p) // 8, 4096)


if __name__ == "__main__": unittest.main()
