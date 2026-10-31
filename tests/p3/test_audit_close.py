import os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from horizon.service.audit import AuditLog


class AuditCloseTests(unittest.TestCase):
    def test_close_releases_fd_is_idempotent_and_fails_closed(self):
        nfd = lambda: len(os.listdir("/proc/self/fd")); d = tempfile.mkdtemp(); before = nfd(); a = AuditLog(os.path.join(d, "a.jsonl")); a.write({"ev": "x"}); self.assertEqual(nfd(), before + 1)
        a.close(); a.close(); self.assertEqual(nfd(), before); self.assertFalse(a.writable())
        with self.assertRaises(OSError): a.write({"ev": "y"})
    def test_garbage_collection_releases_fd(self):
        nfd = lambda: len(os.listdir("/proc/self/fd")); d = tempfile.mkdtemp(); before = nfd(); a = AuditLog(os.path.join(d, "a.jsonl")); del a; self.assertEqual(nfd(), before)
    def test_chain_still_verifies_after_close_and_reopen(self):
        from horizon.service.audit import verify_audit
        p = os.path.join(tempfile.mkdtemp(), "a.jsonl"); a = AuditLog(p); a.write({"ev": 1}); a.close(); b = AuditLog(p); b.write({"ev": 2}); b.close(); self.assertTrue(verify_audit(p)[0])


if __name__ == "__main__": unittest.main()
