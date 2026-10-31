"""P10 tests: credential binding, secrets, approvals, key lifecycle/stamps, resource guard, fail-closed drills, peer auth, telemetry privacy, versioning, supply-chain scripts."""
import json, os, socket, sys, tempfile, threading, time, unittest, socketserver, stat
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from horizon.ops import audience as A, secrets as SE, approvals as AP, keys as K, guard as G, otel as O, peer as PE, version as V
from horizon.service.audit import AuditLog, verify_audit


class Clock:
    def __init__(self, t=1_000_000.0): self.t = t
    def __call__(self): return self.t


class AudienceTests(unittest.TestCase):
    def setUp(self): self.c = Clock(); self.key = b"k" * 32; self.v = A.Validator(issuer="idp", audience="mcp://svc-a", keys={"k1": self.key}, clock=self.c)
    def tok(self, **kw): d = dict(iss="idp", aud="mcp://svc-a", sub="u", tenant="T1", scopes=("read",), now=self.c()); d.update(kw); return A.mint(self.key, "k1", **d)
    def code(self, t, **kw):
        with self.assertRaises(A.AuthError) as e: self.v.validate(t, **kw)
        return e.exception.code
    def test_valid_and_scopes(self):
        p = self.v.validate(self.tok(), need_scopes=("read",)); self.assertEqual((p["tenant"], p["sub"]), ("T1", "u")); self.assertEqual(self.code(self.tok(), need_scopes=("write",)), "INSUFFICIENT_SCOPE")
    def test_audience_binding_blocks_token_passthrough(self): self.assertEqual(self.code(self.tok(aud="mcp://svc-b")), "BAD_AUDIENCE"); self.assertEqual(self.code(self.tok(aud="mcp://svc-a/")), "BAD_AUDIENCE")
    def test_issuer_binding(self): self.assertEqual(self.code(self.tok(iss="evil")), "BAD_ISSUER")
    def test_signature_kid_alg(self):
        t = self.tok(); h, p, s = t.split("."); self.assertEqual(self.code(".".join([h, p, s[:-2] + ("AA" if s[-2:] != "AA" else "BB")])), "BAD_SIGNATURE")
        other = A.mint(b"x" * 32, "k1", iss="idp", aud="mcp://svc-a", sub="u", tenant="T1", now=self.c()); self.assertEqual(self.code(other), "BAD_SIGNATURE")
        self.assertEqual(self.code(A.mint(self.key, "nokid", iss="idp", aud="mcp://svc-a", sub="u", tenant="T1", now=self.c())), "UNKNOWN_KEY")
        none = A._b64(json.dumps({"alg": "none", "kid": "k1"}).encode()) + "." + p + "."; self.assertEqual(self.code(none), "BAD_ALG")
        h2 = A._b64(json.dumps({"alg": "HS512", "kid": "k1"}).encode()); self.assertEqual(self.code(h2 + "." + p + "." + s), "BAD_ALG")
    def test_time_claims(self):
        t = self.tok(ttl_s=60); self.c.t += 30; self.v.validate(t); self.c.t += 100; self.assertEqual(self.code(t), "EXPIRED")
        self.c.t = 1_000_000.0; self.assertEqual(self.code(self.tok(now=self.c() + 500)), "NOT_YET_VALID"); self.assertEqual(self.code(self.tok(ttl_s=99999)), "TTL_TOO_LONG")
    def test_malformed_inputs(self):
        for bad in ("", "a.b", "a.b.c.d", "!!.@@.##", None, 12, A._b64(b"[]") + "." + A._b64(b"[]") + ".x"): self.assertEqual(self.code(bad), "MALFORMED", bad)
    def test_revocation_and_missing_claims(self):
        t = self.tok(); self.v.revoked.add(A.digest(t)); self.assertEqual(self.code(t), "REVOKED"); self.assertEqual(self.code(self.tok(sub="")), "MALFORMED"); self.assertEqual(self.code(self.tok(tenant="")), "MALFORMED")
    def test_key_removal_revokes_all_tokens_for_that_kid(self): t = self.tok(); self.v.keys.pop("k1"); self.assertEqual(self.code(t), "UNKNOWN_KEY")


class SecretTests(unittest.TestCase):
    def test_secret_never_renders(self):
        s = SE.Secret("env:X", "hunter2-very-secret"); import pickle, copy
        for r in (repr(s), str(s), f"{s}", "%s" % s, f"{s!r}", json.dumps({"k": repr(s)})): self.assertNotIn("hunter2", r)
        with self.assertRaises(TypeError): pickle.dumps(s)
        self.assertEqual(s.reveal(), "hunter2-very-secret"); self.assertTrue(s == SE.Secret("a", "hunter2-very-secret")); self.assertFalse(s == SE.Secret("a", "other")); self.assertFalse(s == "hunter2-very-secret")
        with self.assertRaises(TypeError): hash(s)
    def test_env_allowlist(self):
        p = SE.SecretProvider(env_allow={"A"}, environ={"A": "1", "B": "2"}); self.assertEqual(p.get("env:A").reveal(), "1")
        for ref in ("env:B", "env:MISSING", "vault:x", "file:x"):
            with self.assertRaises(SE.SecretError): p.get(ref)
    def test_file_provider_rules(self):
        d = Path(tempfile.mkdtemp()); (d / "ok").write_text("val\n"); os.chmod(d / "ok", 0o600); (d / "open").write_text("v"); os.chmod(d / "open", 0o644); os.symlink(d / "ok", d / "ln"); p = SE.SecretProvider(file_root=str(d))
        self.assertEqual(p.get("file:ok").reveal(), "val")
        for name in ("open", "ln", "../etc/passwd", "missing", "sub/../../x"):
            with self.assertRaises(SE.SecretError, msg=name): p.get("file:" + name)
        (d / "dir").mkdir()
        with self.assertRaises(SE.SecretError): p.get("file:dir")
    def test_honeytokens_found_in_every_encoding_and_clean_files_pass(self):
        import base64, binascii
        t = SE.make_honeytokens(2); self.assertEqual(len(set(t)), 2); d = Path(tempfile.mkdtemp())
        (d / "clean.log").write_text("nothing here"); self.assertEqual(SE.assert_absent(t, [str(d)]), [])
        for i, enc in enumerate((lambda b: b, base64.b64encode, base64.urlsafe_b64encode, binascii.hexlify, lambda b: b[::-1])):
            (d / f"leak{i}.log").write_bytes(b"x " + enc(t[0].encode()) + b" y")
        self.assertEqual(len(SE.assert_absent(t, [str(d)])), 5); self.assertEqual(SE.assert_absent(t, [], [t[1], "fine"]), ["text[0]"])


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.ap = AP.ApprovalLog(os.path.join(self.d, "a.jsonl"), {"alice": "requester", "bob": "approver", "carol": "approver", "root": "admin", "mallory": "nobody"}, two_person={"policy_change"}); self.addCleanup(self.ap.close)
    def code(self, f, *a):
        with self.assertRaises(AP.ApprovalError) as e: f(*a)
        return e.exception.code
    def test_flow_and_separation(self):
        r = self.ap.request("alice", "manual_update", "sha256:x", "why"); self.assertEqual(self.code(self.ap.decide, "alice", r, True, "sha256:x"), "ROLE_FORBIDDEN")
        self.assertEqual(self.code(self.ap.request, "bob", "k", "d", "r"), "ROLE_FORBIDDEN"); self.assertEqual(self.code(self.ap.request, "mallory", "k", "d", "r"), "ROLE_FORBIDDEN")
        self.assertEqual(self.code(self.ap.decide, "bob", r, True, "sha256:OTHER"), "DIGEST_MISMATCH"); self.assertFalse(self.ap.is_approved(r, "sha256:x")); self.assertEqual(self.ap.decide("bob", r, True, "sha256:x"), "APPROVED")
        self.assertTrue(self.ap.is_approved(r, "sha256:x")); self.assertFalse(self.ap.is_approved(r, "sha256:y")); self.assertEqual(self.code(self.ap.decide, "carol", r, True, "sha256:x"), "NOT_PENDING")
    def test_admin_cannot_approve_their_own_request(self):
        r = self.ap.request("root", "manual_update", "d", "x"); self.assertEqual(self.code(self.ap.decide, "root", r, True, "d"), "SELF_APPROVAL"); self.assertEqual(self.code(self.ap.decide, "root", r, False, "d"), "SELF_APPROVAL"); self.assertEqual(self.ap.decide("bob", r, True, "d"), "APPROVED")
    def test_two_person_rule_and_duplicate_approver(self):
        r = self.ap.request("alice", "policy_change", "d1", "x"); self.assertEqual(self.ap.decide("bob", r, True, "d1"), "PENDING"); self.assertEqual(self.code(self.ap.decide, "bob", r, True, "d1"), "DUPLICATE_APPROVER"); self.assertEqual(self.ap.decide("carol", r, True, "d1"), "APPROVED")
    def test_reject_and_revoke_and_chain(self):
        r = self.ap.request("alice", "k", "d", "x"); self.assertEqual(self.ap.decide("bob", r, False, "d"), "REJECTED"); self.assertEqual(self.code(self.ap.decide, "carol", r, True, "d"), "NOT_PENDING")
        r2 = self.ap.request("alice", "k", "d", "x"); self.ap.decide("bob", r2, True, "d"); self.assertEqual(self.code(self.ap.revoke, "bob", r2), "ROLE_FORBIDDEN"); self.ap.revoke("root", r2); self.assertFalse(self.ap.is_approved(r2, "d"))
        self.assertTrue(verify_audit(os.path.join(self.d, "a.jsonl"))[0]); self.assertEqual(self.code(self.ap.decide, "bob", "nope", True, "d"), "UNKNOWN")
        lines = [json.loads(x)["ev"] for x in open(os.path.join(self.d, "a.jsonl"))]; self.assertEqual(lines.count("approval_request"), 2); self.assertIn("approval_revoke", lines)


class KeyTests(unittest.TestCase):
    def test_rotation_retire_revoke(self):
        c = Clock(); r = K.KeyRing(c); k1 = r.rotate(); s = r.sign(b"m"); self.assertTrue(r.verify(b"m", s)); self.assertFalse(r.verify(b"x", s)); k2 = r.rotate(); self.assertNotEqual(k1, k2)
        self.assertTrue(r.verify(b"m", s)); self.assertEqual(r.sign(b"m")["kid"], k2); r.revoke(k1); self.assertFalse(r.verify(b"m", s)); self.assertEqual(r.k[k1]["key"], b"")
        self.assertFalse(r.verify(b"m", {"kid": "nope", "mac": "00"})); self.assertFalse(r.verify(b"m", {}))
    def test_no_active_key_and_due(self):
        c = Clock(); r = K.KeyRing(c); self.assertTrue(r.due_for_rotation(10))
        with self.assertRaises(K.KeyError_): r.sign(b"x")
        r.rotate(); self.assertFalse(r.due_for_rotation(10)); c.t += 11; self.assertTrue(r.due_for_rotation(10))
    def test_audit_stamp_detects_truncation_rewrite_and_key_revocation(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "a.jsonl"); a = AuditLog(p); [a.write({"ev": i}) for i in range(5)]; a.close(); r = K.KeyRing(); r.rotate(); st = K.audit_stamp(r, p)
        self.assertEqual(K.verify_stamp(r, st, p), (True, "ok")); b = AuditLog(p); b.write({"ev": 5}); b.close(); self.assertTrue(K.verify_stamp(r, st, p)[0])                     # appending is fine
        lines = open(p).read().splitlines(); open(p, "w").write("\n".join(lines[:3]) + "\n"); self.assertEqual(K.verify_stamp(r, st, p)[1], "audit log truncated since stamp")
        q = os.path.join(d, "b.jsonl"); c = AuditLog(q); [c.write({"ev": "other", "i": i}) for i in range(6)]; c.close(); self.assertEqual(K.verify_stamp(r, st, q)[1], "audit history rewritten since stamp")
        forged = dict(st, count=1); self.assertFalse(K.verify_stamp(r, forged, p)[0]); r.rotate(); self.assertFalse(K.verify_stamp(r, st, q)[0] is True and False); r.revoke("k1"); self.assertFalse(K.verify_stamp(r, st, p)[0])


class GuardTests(unittest.TestCase):
    def test_size_rate_tenant_and_inflight_bounds(self):
        c = Clock(); g = G.ResourceGuard(rate=1, burst=2, max_event_bytes=100, max_inflight=1, max_tenants=2, clock=c)
        with self.assertRaises(G.Overload) as e: g.admit("t", "x" * 101)
        self.assertEqual(e.exception.code, "TOO_LARGE"); g.admit("t", {"a": 1}); g.admit("t", {"a": 1})
        with self.assertRaises(G.Overload) as e: g.admit("t", {"a": 1})
        self.assertEqual(e.exception.code, "RATE_LIMITED"); c.t += 5; g.admit("t", {"a": 1}); g.admit("u", {"a": 1})
        with self.assertRaises(G.Overload) as e: g.admit("v", {"a": 1})
        self.assertEqual(e.exception.code, "TENANT_LIMIT")
        with g:
            with self.assertRaises(G.Overload) as e: g.__enter__()
            self.assertEqual(e.exception.code, "BUSY")
        with g: pass
        self.assertEqual(g.inflight, 0)
    def test_per_tenant_isolation_of_rate_limit(self):
        c = Clock(); g = G.ResourceGuard(rate=0.001, burst=1, clock=c); g.admit("a", {}); 
        with self.assertRaises(G.Overload): g.admit("a", {})
        g.admit("b", {})
    def test_limit_process_rlimits_apply_in_child(self):
        import subprocess
        r = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0,%r); from horizon.ops.guard import limit_process; limit_process(cpu_s=1, mem_mb=512, files=64); import resource; print(resource.getrlimit(resource.RLIMIT_CPU)[0], resource.getrlimit(resource.RLIMIT_NOFILE)[0])" % str(REPO)], capture_output=True, text=True); self.assertEqual(r.stdout.split(), ["1", "64"], r.stderr)
        r = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0,%r); from horizon.ops.guard import limit_process; limit_process(cpu_s=5, mem_mb=200); x = bytearray(400<<20)" % str(REPO)], capture_output=True, text=True); self.assertNotEqual(r.returncode, 0); self.assertIn("MemoryError", r.stderr)


class FailClosedDrills(unittest.TestCase):
    ALLOW = {"verdict": "ALLOW", "reason_codes": []}
    send = {"effect": "send", "tool_id": "s/post"}; read = {"effect": "read", "tool_id": "resources/read"}
    def test_healthy_passthrough(self): f = G.FailClosed(lambda b: self.ALLOW); self.assertEqual(f(self.send)["verdict"], "ALLOW")
    def test_exception_timeout_and_malformed_all_deny(self):
        def boom(b): raise RuntimeError("down")
        self.assertEqual(G.FailClosed(boom)(self.send)["reason_codes"], ["POLICY_SERVICE_ERROR"])
        slow = G.FailClosed(lambda b: (time.sleep(1.0), self.ALLOW)[1], timeout_s=0.1); t0 = time.time(); self.assertEqual(slow(self.send)["reason_codes"], ["POLICY_SERVICE_TIMEOUT"]); self.assertLess(time.time() - t0, 0.8)
        for bad in (None, "ALLOW", {}, {"verdict": "MAYBE"}, {"verdict": None}, []): self.assertEqual(G.FailClosed(lambda b, bad=bad: bad)(self.send)["reason_codes"], ["POLICY_SERVICE_MALFORMED"], bad)
    def test_emergency_mode_blocks_everything_except_allowlisted_reads(self):
        f = G.FailClosed(lambda b: self.ALLOW, emergency_read_allow={"resources/read"}); f.engage()
        self.assertEqual(f(self.send)["reason_codes"], ["EMERGENCY_MODE"]); self.assertEqual(f({"effect": "read", "tool_id": "other"})["verdict"], "DENY"); self.assertEqual(f({"effect": "execute", "tool_id": "resources/read"})["verdict"], "DENY"); self.assertEqual(f(self.read)["verdict"], "ALLOW")
        f.release(); self.assertEqual(f(self.send)["verdict"], "ALLOW"); self.assertEqual(f.stats["failclosed"], 3)
    def test_real_service_outage_drill_audit_unwritable_denies_protected(self):
        from bench.secbench.world import POLICY
        from horizon.service.core import Service
        d = tempfile.mkdtemp(); s = Service({"ta": {"tenant": "T1", "principal": "a", "role": "adapter"}, "adm": {"tenant": "T1", "principal": "adm", "role": "admin"}}, os.path.join(d, "a.jsonl"), b"k" * 32); self.addCleanup(s.close)
        self.assertEqual(s.handle("POST", "/v2/policies", "adm", {"policy": POLICY})[0], 200)
        body = {"protocol": "utcp", "native_operation": "http:POST", "tool_id": "m/post", "effect": "send", "args_digest": "sha256:" + "0" * 64, "target": {"kind": "url", "raw": "https://api.example.com/v1/notes"}, "sink_zone": "partner", "purpose": "p", "input_artifacts": [], "idempotency_key": "k" * 20, "event_id": "e1"}
        st, out = s.handle("POST", "/v2/decisions", "ta", body); self.assertEqual((st, out.get("verdict")), (200, "ALLOW"), out)
        s.close(); body["event_id"] = "e2"; body["idempotency_key"] = "j" * 20; st, out = s.handle("POST", "/v2/decisions", "ta", body)
        self.assertNotEqual(out.get("verdict"), "ALLOW", (st, out)); self.assertFalse(s.health()["audit_writable"])


class PeerAuthTests(unittest.TestCase):
    class H(socketserver.BaseRequestHandler):
        def handle(self): self.request.sendall(b"hello")
    def talk(self, path):
        c = socket.socket(socket.AF_UNIX); c.settimeout(2)
        try: c.connect(path); return c.recv(10)
        except OSError: return b""
        finally: c.close()
    def test_allowed_uid_served_and_others_dropped(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "s.sock")
        for uids, want in (({os.getuid()}, b"hello"), ({os.getuid() + 12345}, b"")):
            srv = PE.PeerAuthUnixServer(p, self.H, allowed_uids=uids); threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                self.assertEqual(self.talk(p), want); self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
                if not want: self.assertGreaterEqual(srv.rejected, 1)
            finally: srv.shutdown(); srv.server_close()
    def test_peer_cred_reports_own_uid(self):
        a, b = socket.socketpair(socket.AF_UNIX); self.assertEqual(PE.peer_cred(a)[1], os.getuid()); a.close(); b.close()
        s = socket.socket(socket.AF_INET)
        try:
            with self.assertRaises(OSError): PE.peer_cred(s)
        finally: s.close()


class TelemetryPrivacy(unittest.TestCase):
    def test_only_allowlisted_and_hashed(self):
        salt = b"s" * 8; spans = [{"name": "/v2/decisions", "trace_id": "ab" * 16, "start": 1.0, "end": 2.0, "attrs": {"tenant": "acme-corp", "principal": "alice@example.com", "verdict": "DENY", "args": {"q": "SECRET-QUERY"}, "url": "https://x/?k=SECRET", "reason_code": "R" * 200, "authorization": "Bearer abc"}}]
        doc = O.to_otlp_spans(spans, salt); txt = json.dumps(doc)
        for banned in ("acme-corp", "alice@example.com", "SECRET", "Bearer", "args", "url"): self.assertNotIn(banned, txt)
        self.assertIn("tenant_h", txt); self.assertIn("DENY", txt); self.assertNotIn("R" * 200, txt)
        self.assertEqual(json.dumps(O.to_otlp_spans(spans, salt)), txt); self.assertNotEqual(json.dumps(O.to_otlp_spans(spans, b"other-salt")), txt)
        sp = doc["resourceSpans"][0]["scopeSpans"][0]["spans"][0]; self.assertEqual((len(sp["traceId"]), len(sp["spanId"])), (32, 16))
    def test_metrics_shape(self):
        m = O.to_otlp_metrics({"requests": 5, "errors": 1, "decisions": {"ALLOW": 3, "DENY": 2}}, 10.0)["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]; self.assertEqual({x["name"] for x in m}, {"mcphorizon.requests", "mcphorizon.errors", "mcphorizon.decisions"}); self.assertEqual(len(m), 4)


class VersionTests(unittest.TestCase):
    def test_parse_compat(self):
        self.assertEqual(V.parse("2.10.3"), (2, 10, 3))
        for bad in ("2.0", "01.0.0", "2.0.0-rc1", "v2.0.0", ""):
            with self.assertRaises(ValueError): V.parse(bad)
        self.assertTrue(V.compatible("2.3.0", "2.1.5")); self.assertFalse(V.compatible("2.0.0", "2.1.0")); self.assertFalse(V.compatible("3.0.0", "2.0.0")); self.assertFalse(V.compatible("0.2.0", "0.1.0")); self.assertTrue(V.compatible("0.1.4", "0.1.2"))
    def test_migrations(self):
        m = V.Migrations(); m.register("1.0.0", "1.1.0", lambda d: {**d, "a": 1}); m.register("1.1.0", "2.0.0", lambda d: {**{k: v for k, v in d.items() if k != "old"}, "b": 2})
        self.assertEqual(m.migrate({"schema_version": "1.0.0", "old": 1}, "2.0.0"), {"schema_version": "2.0.0", "a": 1, "b": 2}); self.assertEqual(m.migrate({"schema_version": "1.0.0"}, "1.1.0")["schema_version"], "1.1.0")
        src = {"schema_version": "1.0.0"}; m.migrate(src, "2.0.0"); self.assertEqual(src, {"schema_version": "1.0.0"})
        for doc, tgt in (({"schema_version": "2.0.0"}, "1.0.0"), ({}, "2.0.0"), ({"schema_version": "0.9.0"}, "2.0.0"), ({"schema_version": "1.0.0"}, "1.5.0")):
            with self.assertRaises(ValueError): m.migrate(doc, tgt)
        with self.assertRaises(ValueError): m.register("1.0.0", "1.2.0", lambda d: d)
        with self.assertRaises(ValueError): m.register("3.0.0", "2.0.0", lambda d: d)
        self.assertEqual(V.parse(V.CURRENT)[0], 2)


class SupplyChainScripts(unittest.TestCase):
    def test_repo_is_clean_and_scanner_detects_planted_secrets(self):
        import importlib.util
        sp = importlib.util.spec_from_file_location("secret_scan", REPO / "scripts/secret_scan.py"); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
        self.assertGreater(len(m.tracked_files(str(REPO))), 100); self.assertEqual(m.scan(str(REPO)), [])
        with self.assertRaises(RuntimeError): m.scan(tempfile.mkdtemp())                                       # empty input must not look like a clean pass
        d = Path(tempfile.mkdtemp())
        plants = {"a.py": "AWS='AKIA" + "ABCDEFGHIJKLMNOP'", "b.txt": "-----BEGIN " + "RSA PRIVATE KEY-----", "c.py": "password = '" + "Zx9Qw2Er7Ty4Ui8Op3As6Df1'", "d.py": "t='gh" + "p_" + "A" * 36 + "'", "e.py": "x='" + "".join(chr(33 + (i * 37) % 90) for i in range(0, 0)) + "aB3dE5gH7jK9mN1pQ3sT5vX7zC9fH2kM4nR6uW8yB0'"}
        for n, t in plants.items(): (d / n).write_text(t)
        (d / "ok.py").write_text("x = 'hello world'  # nothing"); (d / "ign.py").write_text("t='aB3dE5gH7jK9mN1pQ3sT5vX7zC9fH2kM4nR6uW8yB0'  # secret-scan:ignore")
        found = {n for n, _, _ in m.scan(str(d), files=list(plants) + ["ok.py", "ign.py"])}; self.assertEqual(found, set(plants))
    def test_sbom_is_cyclonedx_with_pinned_components(self):
        import importlib.util
        sp = importlib.util.spec_from_file_location("sbom", REPO / "scripts/sbom.py"); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m); d = m.build(str(REPO))
        self.assertEqual((d["bomFormat"], d["specVersion"]), ("CycloneDX", "1.5")); self.assertTrue(d["components"]); self.assertTrue(all(c["version"] and c["purl"].startswith("pkg:") for c in d["components"]))
        self.assertTrue(any(c["name"] == "isolated-vm" for c in d["components"]))


class DocsPresent(unittest.TestCase):
    def test_required_documents_state_their_limits(self):
        need = {"docs/security/THREAT_MODEL.md": ("Non-goals", "No independent security review"), "docs/operations/INCIDENT_RESPONSE.md": ("Block", "Rotate", "has **not** been run"), "docs/operations/POLICY_AUTHORING_GUIDE.md": ("false positives", "maximum_input_label"),
                "docs/operations/PLATFORM_CAVEATS.md": ("not configured", "Linux"), "docs/operations/VERSIONING.md": ("Semantic versioning", "SBOM")}
        for f, words in need.items():
            t = (REPO / f).read_text()
            for w in words: self.assertIn(w.lower(), t.lower(), (f, w))


if __name__ == "__main__": unittest.main()
