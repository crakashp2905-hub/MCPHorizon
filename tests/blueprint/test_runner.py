import os, shutil, socket, tempfile, threading, unittest
from horizon.runtime import sandbox as S
from horizon.runtime import runner as R

CAN = os.geteuid() == 0 and S.landlock_abi() >= 4 if hasattr(S, "landlock_abi") else False


class Listener:
    def __enter__(s):
        s.sock = socket.socket(); s.sock.bind(("127.0.0.1", 0)); s.sock.listen(8); s.port = s.sock.getsockname()[1]; s.got = []; s.stop = False
        s.us = tempfile.mktemp(prefix="hzu"); s.u = socket.socket(socket.AF_UNIX); s.u.bind(s.us); s.u.listen(8)
        def loop(sk):
            sk.settimeout(0.2)
            while not s.stop:
                try: c, _ = sk.accept(); c.settimeout(0.5); s.got.append(c.recv(10)); c.close()
                except OSError: pass
        s.th = [threading.Thread(target=loop, args=(x,), daemon=True) for x in (s.sock, s.u)]; [t.start() for t in s.th]; return s
    def __exit__(s, *a):
        s.stop = True; [t.join() for t in s.th]; s.sock.close(); s.u.close(); os.path.exists(s.us) and os.remove(s.us)


class Policy(unittest.TestCase):
    def test_weak_policy_is_refused_not_run(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        for k in R.REQUIRED:
            p = R.enforced_policy(); setattr(p, k, False); r = R.ConfinedRunner(d, policy=p).run("print(1)", run_id="w")
            self.assertEqual((r.confined, r.exit), (False, None), k); self.assertTrue(r.refused.startswith("POLICY_TOO_WEAK:") and k in r.refused)
        self.assertEqual(R.weaknesses(S.Policy.open()), list(R.REQUIRED)); self.assertEqual(R.weaknesses(R.enforced_policy()), [])

    def test_default_runner_policy_is_the_enforced_one(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True); self.assertEqual(R.ConfinedRunner(d).policy.digest(), R.enforced_policy().digest())


@unittest.skipUnless(CAN, "needs root + Landlock ABI>=4 (confinement cannot be exercised here; this is NOT a pass)")
class Confined(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, True)
        self.ws = os.path.join(self.d, "repo"); os.mkdir(self.ws); open(os.path.join(self.ws, "a.py"), "w").write("x=1\n")
        self.prot = os.path.join(self.d, "protected"); os.mkdir(self.prot); open(os.path.join(self.prot, "secret.txt"), "w").write("S3CRET")

    def test_legit_edit_is_allowed_and_reported_not_applied(self):
        r = R.ConfinedRunner(self.ws).run("open('a.py','a').write('y=2\\n'); open('new.py','w').write('z=3\\n'); os.remove('a.py') if False else None\nprint('done')", run_id="legit")
        self.assertEqual((r.refused, r.exit, r.stdout.strip(), r.confined), (None, 0, "done", True))
        self.assertEqual(sorted((c["path"], c["op"]) for c in r.changes), [("a.py", "modify"), ("new.py", "create")])
        self.assertEqual(open(os.path.join(self.ws, "a.py")).read(), "x=1\n"); self.assertFalse(os.path.exists(os.path.join(self.ws, "new.py")))     # real repo untouched

    def test_every_bypass_probe_is_blocked_when_confined_and_reachable_when_not(self):
        with Listener() as L:
            conf = R.run_probes(R.ConfinedRunner(self.ws), target=self.prot, port=L.port, unix_path=L.us, run_prefix="c")
            self.assertEqual(L.got, [], "confined run reached the listener")
            self.assertEqual({k: v["blocked"] for k, v in conf.items() if v["blocked"] is not True}, {}, conf)
            self.assertFalse(os.path.exists(os.path.join(self.prot, "raw.txt"))); self.assertEqual(open(os.path.join(self.prot, "secret.txt")).read(), "S3CRET")
            ctl = R.run_probes(R.ConfinedRunner(self.ws, policy=S.Policy.open(), unconfined=True), target=self.prot, port=L.port, unix_path=L.us, run_prefix="u")
        # control: the same probes must actually succeed with no confinement, otherwise "blocked" would prove nothing (raw socket/mount/setuid need caps that stay in the open run as root)
        must = ["tcp_connect_loopback", "udp_socket", "unix_socket_to_host", "write_protected_root", "read_outside_workspace", "direct_exec", "fork_then_exec", "write_exec_in_workspace_then_run", "symlink_escape_write"]
        self.assertEqual({k: ctl[k]["blocked"] for k in must if ctl[k]["blocked"] is not False}, {}, ctl)

    def test_exfiltration_of_secret_over_network_fails_and_nothing_arrives(self):
        with Listener() as L:
            r = R.ConfinedRunner(self.ws).run(f"import socket\ns=open({self.prot!r}+'/secret.txt').read() if os.path.exists({self.prot!r}) else ''\ntry:\n  socket.create_connection(('127.0.0.1',{L.port}),2).sendall(s.encode()); print('SENT')\nexcept OSError: print('no-net')", run_id="exf")
            self.assertEqual(r.stdout.strip(), "no-net"); self.assertEqual(L.got, [])

    def test_profile_is_verified_and_reported(self):
        r = R.ConfinedRunner(self.ws).run("print(os.getuid())", run_id="prof")
        self.assertEqual((r.profile["nonewprivs"], r.profile["seccomp"], r.profile["cap_eff"].strip("0")), ("1", "2", "")); self.assertNotEqual(r.stdout.strip(), "0")

    def test_timeout_kills_runaway_agent_and_cleans_scratch(self):
        before = set(os.listdir(S.SCRATCH_BASE)) if os.path.isdir(S.SCRATCH_BASE) else set()
        r = R.ConfinedRunner(self.ws, timeout_s=1).run("while True: pass", run_id="loop"); self.assertTrue(r.timed_out)
        self.assertEqual(set(os.listdir(S.SCRATCH_BASE)) - before, set())

    def test_changes_are_size_capped_and_symlinks_are_not_followed(self):
        r = R.ConfinedRunner(self.ws).run("os.symlink('/etc/passwd','lnk'); open('ok.txt','w').write('1')", run_id="lnk")
        self.assertEqual([c["path"] for c in r.changes], ["ok.txt"]); self.assertEqual(r.skipped, [{"path": "lnk", "why": "symlink"}])
if __name__ == "__main__": unittest.main()
