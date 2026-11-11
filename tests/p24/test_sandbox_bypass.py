"""PR-03 (M2, code-side): the three OS-level bypasses from tests/integration_bypass, exercised INSIDE the real launch() sandbox with positive controls.
Scope of the claim: this kernel/container only (root, x86_64, Landlock ABI>=4). It is NOT evidence about the owner's dedicated Linux host, a non-root deployment, or other kernels (masterplan section 12), and the agent here is a Python child, not an arbitrary agent runtime."""
import json, os, shutil, struct, sys, tempfile, unittest
from horizon.runtime import sandbox as S

CAN = os.geteuid() == 0 and S.platform.machine() == "x86_64" and S.landlock_abi() >= 4
need = unittest.skipUnless(CAN, "UNSUPPORTED environment: needs root, x86_64, Landlock ABI>=4 (not exercised here)")

# own.elf is a hand-built 129-byte STATIC x86_64 ELF that calls exit(0): static, so it has no ELF interpreter and only the scratch-dir EXEC grant decides whether it may run.
PROBE = '''
import socket, subprocess, os, json
r = {}
def t(k, f):
    try: f(); r[k] = "allowed"
    except OSError as e: r[k] = "denied:%%d" %% e.errno
t("socket_inet", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).close())
t("socket_unix", lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close())
t("write_protected", lambda: open(%r, "w").write("x"))
t("write_scratch", lambda: open("ok.txt", "w").write("x"))
t("exec_true", lambda: subprocess.run(["/bin/true"], check=True))
def own():
    open("own.elf", "wb").write(bytes.fromhex("7f454c4602010100000000000000000002003e0001000000780040000000000040000000000000000000000000000000000000004000380001000000000000000100000005000000000000000000000000004000000000000000400000000000810000000000000081000000000000000010000000000000b83c00000031ff0f05")); os.chmod("own.elf", 0o755); subprocess.run(["./own.elf"], check=True)
t("exec_own_file", own)
print(json.dumps(r))
'''


@need
class SandboxBypass(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prot = tempfile.mkdtemp(dir="/opt"); os.chmod(cls.prot, 0o777); cls.target = os.path.join(cls.prot, "raw.txt")

    @classmethod
    def tearDownClass(cls): shutil.rmtree(cls.prot, ignore_errors=True)

    def run_probe(self, pol):
        r = S.launch(PROBE % self.target, run_id="bp", policy=pol); self.assertIsNone(r.refused, r.refused); self.assertEqual(r.exit, 0, r.stderr); return json.loads(r.stdout)

    def test_raw_socket_and_protected_write_denied_with_positive_controls(self):
        r = self.run_probe(S.Policy())
        self.assertEqual(r["socket_inet"], "denied:1")                  # EPERM from seccomp
        self.assertEqual(r["socket_unix"], "allowed")                   # control: the filter is selective, not a blanket failure
        self.assertEqual(r["write_protected"], "denied:13")             # EACCES from Landlock, not ENOENT: the path exists
        self.assertEqual(r["write_scratch"], "allowed")                 # control: writes work where granted
        self.assertFalse(os.path.exists(self.target))

    def test_exec_is_allowed_by_default_policy_so_the_gap_is_real(self):
        r = self.run_probe(S.Policy()); self.assertEqual(r["exec_true"], "allowed"); self.assertEqual(r["exec_own_file"], "allowed")

    def test_exec_deny_blocks_system_programs_and_self_written_files(self):
        r = self.run_probe(S.Policy(exec_deny=True))
        self.assertEqual(r["exec_true"], "denied:13"); self.assertEqual(r["exec_own_file"], "denied:13")
        self.assertEqual(r["write_scratch"], "allowed"); self.assertEqual(r["socket_inet"], "denied:1")          # exec_deny does not disturb the other controls

    def test_open_policy_is_not_a_boundary(self):
        r = self.run_probe(S.Policy.open()); self.assertEqual(r["socket_inet"], "allowed"); self.assertEqual(r["write_protected"], "allowed")
        self.assertTrue(os.path.exists(self.target)); os.unlink(self.target)


class Elf(unittest.TestCase):
    def test_interpreter_of_python_or_none_and_garbage_is_none(self):
        i = S.elf_interpreter(os.path.realpath(sys.executable)); self.assertTrue(i is None or i.startswith("/"))
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        for name, data in (("empty", b""), ("text", b"#!/bin/sh\n"), ("trunc", b"\x7fELF\x02" + b"\0" * 20), ("elf32", b"\x7fELF\x01" + b"\0" * 80)):
            p = os.path.join(d, name); open(p, "wb").write(data); self.assertIsNone(S.elf_interpreter(p), name)
        self.assertIsNone(S.elf_interpreter(os.path.join(d, "missing")))

    @unittest.skipUnless(shutil.which("ls") and S.elf_interpreter(shutil.which("ls")), "dynamic ls not available")
    def test_interpreter_found_for_a_dynamic_binary(self): self.assertTrue(S.elf_interpreter(os.path.realpath(shutil.which("ls"))).startswith("/"))

    def test_exec_deny_without_landlock_is_refused_not_ignored(self):
        r = S.launch('print(1)', run_id='x', policy=S.Policy(landlock=False, exec_deny=True)); self.assertIn('exec_deny needs landlock', r.refused); self.assertIsNone(r.exit)

    def test_policy_digest_changes_with_exec_deny(self): self.assertNotEqual(S.Policy().digest(), S.Policy(exec_deny=True).digest())
if __name__ == "__main__": unittest.main()
