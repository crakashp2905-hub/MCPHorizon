import os, tempfile, unittest, hashlib
from horizon.authz.issuer import LocalIssuer, ProcessIssuer, IssuerDenied, _wrap, FIELDS, root_policy
from horizon.effects.canonical import CanonicalEffect
from horizon.effects.mcp_gateway import Gateway

CASES = [("a.txt", True), ("sub/a.txt", False), (".hid", False), ("../x.txt", False), ("ok2.txt", True)]


def call(g, p, i): return g.call_write({"path": p, "content": "hello", "effect_id": i})


class T(unittest.TestCase):
    def mk(self, proc=False):
        d = tempfile.mkdtemp(); r = os.path.join(d, "r"); os.mkdir(r); os.mkdir(os.path.join(r, "sub"))
        iss = ProcessIssuer(os.path.realpath(r)) if proc else None
        if iss: self.addCleanup(iss.close)
        return Gateway(r, os.path.join(d, "j"), os.path.join(d, "l.db"), issuer=iss), r

    def test_decision_parity_local_vs_process_issuer(self):
        a, _ = self.mk(False); b, _ = self.mk(True)
        for n, (p, allowed) in enumerate(CASES):
            ra, rb = call(a, p, f"e{n}"), call(b, p, f"e{n}")
            self.assertEqual(ra["isError"], rb["isError"], p); self.assertEqual(not ra["isError"], allowed, p)
            self.assertEqual(ra["content"][0]["text"], rb["content"][0]["text"], p)

    def test_digest_parity_with_canonical_effect(self):
        ce = CanonicalEffect("t1", "s", "x", "p", "write", "file", "/r/a", {"sha256": "ab", "n": [1, 2]})
        w = _wrap({**{k: getattr(ce, k) for k in FIELDS}, "args": ce.args}); self.assertEqual(w.bound_args_digest(), ce.bound_args_digest())

    def test_issuer_denies_when_gateway_precheck_is_bypassed(self):
        d = tempfile.mkdtemp(); iss = LocalIssuer(root_policy(d))
        ce = CanonicalEffect("t1", "s", "x", "p", "write", "file", "/etc/passwd", {})
        with self.assertRaises(IssuerDenied): iss.mint(ce)
        pi = ProcessIssuer(d); self.addCleanup(pi.close)
        with self.assertRaises(IssuerDenied): pi.mint(ce)

    def test_process_issuer_rejects_malformed_and_unknown_effect(self):
        d = tempfile.mkdtemp(); pi = ProcessIssuer(d); self.addCleanup(pi.close)
        base = {k: "x" for k in FIELDS}; base["args"] = {}
        self.assertEqual(pi._rpc({"op": "mint", "ce": {**base, "effect": "nope"}})["code"], "UNKNOWN_EFFECT")
        self.assertEqual(pi._rpc({"op": "mint", "ce": {"tenant": "t"}})["code"], "MALFORMED")
        self.assertEqual(pi._rpc({"op": "zzz"})["code"], "BAD_OP")

    def test_gateway_object_holds_no_private_key_attribute(self):
        g, _ = self.mk(True)
        def walk(o, seen=()):
            for v in vars(o).values():
                self.assertNotEqual(type(v).__name__, "Ed25519PrivateKey"); self.assertNotEqual(type(v).__name__, "Signer")
        walk(g); walk(g.issuer)

    def test_issuer_down_fails_closed(self):
        g, r = self.mk(True); g.issuer._p.kill(); g.issuer._p.wait()
        res = call(g, "a.txt", "ez")
        self.assertTrue(res["isError"]); self.assertEqual(res["structuredContent"]["code"], "ISSUER_DOWN"); self.assertEqual(res["structuredContent"]["effect"], "DID_NOT_HAPPEN")
        self.assertFalse(os.path.exists(os.path.join(r, "a.txt")))
    def test_root_policy_hidden_and_symlink_and_traversal(self):
        d = os.path.realpath(tempfile.mkdtemp()); out = os.path.realpath(tempfile.mkdtemp()); ok = root_policy(d)
        ce = lambda p: type("C", (), {"target_raw": p})()
        self.assertTrue(ok(ce(os.path.join(d, "a.txt")))); self.assertFalse(ok(ce(os.path.join(d, ".h"))))
        os.symlink(out, os.path.join(d, "ln")); self.assertFalse(ok(ce(os.path.join(d, "ln", "x.txt"))))
        os.symlink(os.path.join(out, "t"), os.path.join(d, "lf")); self.assertFalse(ok(ce(os.path.join(d, "lf"))))     # symlink file escaping the root
        self.assertFalse(ok(ce(os.path.join(d, "sub", "..", "..", "z"))))
        open(os.path.join(d, "real.txt"), "w").close(); os.symlink(os.path.join(d, "real.txt"), os.path.join(d, "alias.txt"))
        self.assertTrue(ok(ce(os.path.join(d, "real.txt")))); self.assertFalse(ok(ce(os.path.join(d, "alias.txt"))))   # in-root alias is refused

    def test_eof_from_issuer_is_issuer_down(self):
        import subprocess
        pi = ProcessIssuer(tempfile.mkdtemp()); self.addCleanup(pi.close); pi._p.kill(); pi._p.wait()
        pi._p = subprocess.Popen(["sh", "-c", "read x; exit 0"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        with self.assertRaises(IssuerDenied) as c: pi._rpc({"op": "pub"})
        self.assertEqual(str(c.exception), "ISSUER_DOWN")
if __name__ == "__main__": unittest.main()
