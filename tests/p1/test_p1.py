import json, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(ROOT))
from horizon import schemas as S, normalize as N, authn as A
from horizon.jsonschema_lite import validate as lite
FIX = ROOT / "tests" / "fixtures"


class Corpus(unittest.TestCase):
    def test_every_fixture_has_expected_outcome(self):
        n = 0
        for status in ("valid", "invalid", "malicious"):
            for f in sorted((FIX / status).rglob("*.json")):
                kind = f.parent.name; doc = json.loads(f.read_text()); errs = S.validate(kind, doc); n += 1
                if status == "valid": self.assertEqual(errs, [], f"{f}: {errs}")
                else: self.assertTrue(errs, f"{f} should be rejected")
        self.assertGreaterEqual(n, 50)

    def test_schema_files_not_drifted(self):
        import subprocess
        self.assertEqual(subprocess.run([sys.executable, str(ROOT / "scripts/gen_schemas.py"), "--check"]).returncode, 0)

    def test_intelligible_version_errors(self):
        for v, frag in (("3.0.0", "major version 3 is not supported"), ("1.2.0", "major version 1 is not supported")):
            e = json.loads((FIX / "valid/event/basic.json").read_text()); e["schema_version"] = v
            self.assertIn(frag, S.validate("event", e)[0])
        self.assertIn("missing or malformed", S.validate("event", {})[0])
        with self.assertRaises(S.UnsupportedSchemaVersion): S.check_version({"schema_version": "9.0.0"})

    def test_validator_never_raises_on_garbage(self):
        for g in (None, 1, "x", [], [[]], {"schema_version": 2}, {"a": float("nan")}, {"schema_version": "2.0.0", "x": float("inf")}):
            for k in ("event", "decision", "capability", "artifact", "lineage_edge", "policy"):
                self.assertIsInstance(S.validate(k, g), list)

    def test_unsupported_schema_keyword_is_loud(self):
        self.assertTrue(lite({}, {"type": "object", "patternProperties": {}}))


class Lineage(unittest.TestCase):
    A = lambda s, i, parents=(), conf="PUBLIC", partial=False: {"id": i, "parents": list(parents), "confidentiality": conf, "partial_lineage": partial}

    def test_incomplete_and_conservative(self):
        a = {"a": self.A("a"), "b": self.A("b", ["a"], "SECRET"), "c": self.A("c", ["b"]), "d": self.A("d", ["zzz"]), "e": self.A("e", partial=True)}
        self.assertTrue(S.lineage_complete("a", a)); self.assertTrue(S.lineage_complete("c", a))
        self.assertFalse(S.lineage_complete("d", a)); self.assertFalse(S.lineage_complete("e", a))
        self.assertEqual(S.effective_confidentiality("c", a), "SECRET")    # model cannot relabel as PUBLIC
        self.assertEqual(S.effective_confidentiality("d", a), "SECRET")    # unknown ancestor => most restrictive
        a["x"] = self.A("x", ["y"]); a["y"] = self.A("y", ["x"])           # cycle terminates
        self.assertTrue(S.lineage_complete("x", a))


class Normalize(unittest.TestCase):
    def test_url_equivalences(self):
        same = ["HTTP://Example.COM:80/a/./b/../c", "http://example.com/a/c", "http://example.com:80/a/c#frag".replace("#frag", "")]
        self.assertEqual({N.canonical_url(u) for u in same}, {"http://example.com/a/c"})
        self.assertEqual(N.canonical_url("https://EXAMPLE.com:443"), "https://example.com/")
        self.assertEqual(N.canonical_url("http://example.com/%61/%2e%2e/b"), "http://example.com/b")

    def test_obfuscated_ip_hosts_collapse(self):
        for h in ("http://2130706433/", "http://0x7f.1/", "http://127.1/", "http://0x7f000001/", "http://[::ffff:127.0.0.1]/".replace("[::ffff:127.0.0.1]", "127.0.0.1")):
            self.assertEqual(N.canonical_url(h), "http://127.0.0.1/", h)

    def test_rejections(self):
        for bad in ("http://user:pw@example.com/", "file:///etc/passwd", "javascript:alert(1)", "http:///x", "http://exa mple.com/", "http://example.com/a\\b"):
            with self.assertRaises(ValueError, msg=bad): N.canonical_url(bad)
        for bad in ("../../etc/passwd", "a/../../b", "x\x00y", "a\\b"):
            with self.assertRaises(ValueError, msg=bad): N.canonical_file(bad, "/work")
        self.assertEqual(N.canonical_file("a/./b", "/work"), "/work/a/b")

    def test_target_identity_ignores_display(self):
        t1 = N.canonical_target("url", "HTTPS://Example.com"); t2 = N.canonical_target("url", "https://example.com:443/")
        self.assertEqual(N.target_digest(t1), N.target_digest(t2))
        self.assertNotEqual(N.target_digest(t1), N.target_digest(N.canonical_target("url", "https://example.org")))
        self.assertNotEqual(N.target_digest({"kind": "file", "canonical_id": "/a"}), N.target_digest({"kind": "resource", "canonical_id": "/a"}))

    def test_logical_ops_distinct_from_transport_and_fail_closed(self):
        self.assertEqual(N.logical_operation("utcp", "http:POST"), N.logical_operation("code_mode", "fetch:POST"))
        for (proto, native), logical in N.LOGICAL.items(): self.assertNotEqual(native, logical)
        with self.assertRaises(N.Unmapped): N.logical_operation("mcp", "tools/call", "any.tool")
        with self.assertRaises(N.Unmapped): N.logical_operation("mcp", "sampling/createMessage")
        N.TOOL_REGISTRY["docs.read_document"] = "document.read"
        self.assertEqual(N.logical_operation("mcp", "tools/call", "docs.read_document"), "document.read"); N.TOOL_REGISTRY.clear()


class Auth(unittest.TestCase):
    def ev(self, i=1, seq=1, run="r1", t="2026-10-31T12:00:00Z"):
        e = json.loads((FIX / "valid/event/basic.json").read_text()); e.update(event_id=f"e{i}", monotonic_seq=seq, run_id=run, wall_time=t); return e
    NOW = 1793448000.0  # 2026-10-31T12:00:00Z

    def test_replay_tamper_and_order(self):
        g = A.ReplayGuard({"k1": b"secret"}); e = A.sign_event(b"secret", "k1", self.ev())
        self.assertIsNone(g.verify(e, self.NOW)); self.assertEqual(g.verify(e, self.NOW), "replayed event_id")
        t = dict(self.ev(2, 2), principal_id="user:evil"); t = {**A.sign_event(b"secret", "k1", self.ev(2, 2)), "principal_id": "user:evil"}
        self.assertEqual(g.verify(t, self.NOW), "bad MAC")
        self.assertEqual(g.verify(A.sign_event(b"secret", "k1", self.ev(3, 1)), self.NOW), "non-monotonic sequence for run")
        self.assertIsNone(g.verify(A.sign_event(b"secret", "k1", self.ev(4, 9, run="r2")), self.NOW))

    def test_window_and_keys(self):
        g = A.ReplayGuard({"k1": b"secret"}, max_skew_s=30)
        self.assertEqual(g.verify(A.sign_event(b"secret", "k1", self.ev(1)), self.NOW + 120), "timestamp outside replay window")
        self.assertEqual(g.verify(A.sign_event(b"wrong", "k1", self.ev(2, 2)), self.NOW), "bad MAC")
        self.assertEqual(g.verify(A.sign_event(b"secret", "kX", self.ev(3, 3)), self.NOW), "unknown or missing key_id")
        self.assertEqual(g.verify(self.ev(4, 4), self.NOW), "unknown or missing key_id")

    def test_bounded_memory(self):
        g = A.ReplayGuard({"k": b"s"}, max_ids=10)
        for i in range(50): g.verify(A.sign_event(b"s", "k", self.ev(i, i, run=f"r{i}")), self.NOW)
        self.assertLessEqual(len(g.ids), 10)


if __name__ == "__main__":
    unittest.main()
