"""M0-06: KNOWN BYPASSES as executable, currently-failing tests. Each test asserts the DESIRED property from the masterplan; `expectedFailure` records that it does not hold today and names the closing milestone.
When a milestone closes a bypass the test starts passing, unittest reports 'unexpected success', and the decorator must be removed in that PR (so closure is visible, not silent).
These are CANDIDATE evidence of gaps only: they are in-process checks on this container, not OS-level proofs; the OS ones are BLOCKED on a dedicated Linux host + owner decisions (masterplan §12)."""
import ast, hashlib, os, tempfile, unittest, dataclasses
from horizon.effects.mcp_gateway import Gateway
from horizon.effects.canonical import CanonicalEffect
from horizon.effects.filesink import FileSink

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "horizon", "effects", "mcp_gateway.py")


class KnownBypasses(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.root = os.path.join(self.d, "root"); os.mkdir(self.root)

    # These three describe an UNSANDBOXED agent process, which still can do all of it. Inside the launch() sandbox the same actions are denied in this container (tests/p24/test_sandbox_bypass.py, PR-03);
    # what stays open is making the sandbox MANDATORY for every agent start on the owner's host, which needs the Linux host + owner decisions.
    @unittest.expectedFailure   # closes: M2 (protected root owned by another uid + sandbox) — needs Linux host/owner decision
    def test_agent_process_cannot_write_protected_root_directly(self):
        Gateway(self.root, os.path.join(self.d, "j"), os.path.join(self.d, "l.db"))
        with self.assertRaises(PermissionError): open(os.path.join(self.root, "raw.txt"), "w").write("bypass")

    @unittest.expectedFailure   # closes: M2 — seccomp/netns profile verified before agent start; needs Linux host
    def test_agent_process_cannot_open_raw_socket(self):
        import socket
        with self.assertRaises(OSError): socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()

    @unittest.expectedFailure   # closes: M2 — no ambient exec for the agent uid; needs Linux host/owner allowlist
    def test_agent_process_cannot_exec_directly(self):
        import subprocess
        with self.assertRaises(OSError): subprocess.run(["/bin/true"], check=False)

    def test_gateway_does_not_hold_signing_key(self):
        tree = ast.parse(open(SRC).read())
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "generate" and getattr(n.func.value, "id", "") == "Signer"]
        self.assertEqual(calls, [])

    def test_gateway_issuer_refuses_effects_that_do_not_carry_a_full_canonical_effect_v1(self):
        # K1: the gateway path now signs only effects whose permit covers a CanonicalEffectV1 (delegation, epochs, claim, idempotency, deadline...). The legacy CanonicalEffect class still exists for other callers.
        from horizon.authz.issuer import IssuerDenied
        g = Gateway(self.root, os.path.join(self.d, "j"), os.path.join(self.d, "l.db"))
        legacy = CanonicalEffect("t1", "srv-files", "sess-1", "agent-a", "write", "file", os.path.join(self.root, "a.txt"), {"sha256": "ab"})
        with self.assertRaises(IssuerDenied): g.issuer.mint(legacy)

    @unittest.expectedFailure   # closes: PR-04/M3 (external anchor mandatory for journal head)
    def test_journal_tail_truncation_is_detected_without_caller_supplied_anchor(self):
        j = os.path.join(self.d, "j"); s = FileSink(self.root, j)
        s.write(os.path.join(self.root, "a.txt"), b"1", "e1"); s.write(os.path.join(self.root, "b.txt"), b"2", "e2")
        lines = open(j).read().splitlines(True); open(j, "w").writelines(lines[:-1])
        ok = s.verify_chain(); self.assertFalse(ok[0] if isinstance(ok, tuple) else ok)


if __name__ == "__main__": unittest.main()
