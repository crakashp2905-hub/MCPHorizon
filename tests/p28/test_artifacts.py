import json, os, time, unittest
from horizon.authz.keys import Signer
from horizon.runtime import artifacts as A, provenance as PV, sandbox as S
OK = os.geteuid() == 0 and S.landlock_abi() >= 4
DB = {"advisories": [{"id": "HZ-2026-0001", "package": "libfoo", "introduced": "1.0.0", "fixed": "1.2.0", "severity": "HIGH"}, {"id": "HZ-2026-0002", "package": "libbar", "introduced": "0.1.0", "fixed": "0.5.0", "severity": "LOW"}]}
DG = A.sha(A._msg(DB["advisories"]))
GOOD_DEPS = "libfoo==1.3.0 --hash=sha256:" + "a" * 64 + "\nlibbar==0.4.0\n"
def ev(name, variant, deps=GOOD_DEPS): return A.evidence(A.fixture(name, variant), deps_text=deps, db=DB, db_digest=DG)

class Static(unittest.TestCase):
    def test_requirements_policy(self):
        for text, code in [("libfoo>=1.0", "UNPINNED"), ("libfoo", "UNPINNED"), ("libfoo==1.0 @ https://evil.example/x.whl", "UNAUTHORIZED_SOURCE"), ("--index-url http://evil.example/simple\nlibfoo==1.0", "UNAUTHORIZED_SOURCE"), ("git+https://x/y.git", "UNAUTHORIZED_SOURCE"), ("-e .", "UNAUTHORIZED_SOURCE"), ("./local.whl", "UNAUTHORIZED_SOURCE"), ("--extra-index-url https://x\nlibfoo==1.0", "UNAUTHORIZED_SOURCE")]:
            r = A.parse_requirements(text); self.assertFalse(r["ok"], text); self.assertIn(code, {p["code"] for p in r["problems"]}, text)
        r = A.parse_requirements(GOOD_DEPS + "# comment\n"); self.assertTrue(r["ok"]); self.assertEqual([d["name"] for d in r["deps"]], ["libfoo", "libbar"])
    def test_sbom(self):
        b = A.sbom(A.parse_requirements(GOOD_DEPS)["deps"], "ab" * 32); self.assertEqual(b["components"][0]["purl"], "pkg:pypi/libfoo@1.3.0"); self.assertEqual(b["metadata"]["component_sha256"], "ab" * 32)
    def test_sca_pinned_snapshot_and_ranges(self):
        d = lambda v: [{"name": "libfoo", "version": v, "hashed": False}]
        self.assertEqual([h["advisory"] for h in A.sca(d("1.1.0"), DB, DG)["findings"]], ["HZ-2026-0001"]); self.assertEqual(A.sca(d("1.2.0"), DB, DG)["findings"], []); self.assertEqual(A.sca(d("0.9.9"), DB, DG)["findings"], []); self.assertTrue(A.sca(d("1.0.0"), DB, DG)["blocking"])
        low = A.sca([{"name": "libbar", "version": "0.2.0", "hashed": False}], DB, DG); self.assertTrue(low["findings"] and not low["blocking"])
        tampered = json.loads(json.dumps(DB)); tampered["advisories"][0]["fixed"] = "9.9.9"; r = A.sca(d("1.3.0"), tampered, DG); self.assertFalse(r["available"])           # DB snapshot digest pinned
    def test_secret_scan_descends_into_archives(self):
        import io, zipfile, tarfile
        z = io.BytesIO(); zf = zipfile.ZipFile(z, "w"); zf.writestr("a/b.txt", "x TEST_CANARY_NOT_SECRET y"); zf.close()
        t = io.BytesIO(); tf = tarfile.open(fileobj=t, mode="w"); i = tarfile.TarInfo("k.env"); data = b"token=abcdef123456789"; i.size = len(data); tf.addfile(i, io.BytesIO(data)); tf.close()
        hits = A.scan_secrets({"p.zip": z.getvalue(), "q.tar": t.getvalue(), "clean.txt": b"nothing here"}); self.assertEqual({(h["where"], h["kind"]) for h in hits}, {("p.zip!a/b.txt", "CANARY"), ("q.tar!k.env", "KV_SECRET")})
    def test_gate_unknown_when_evidence_missing(self):
        e = {"scanner": {"sast": {"available": False}, "sca": {"available": True, "blocking": []}, "secrets": [], "deps": {"ok": True, "problems": []}}, "oracle": {"available": False}}; self.assertEqual(A.gate(e)["decision"], "UNKNOWN")
        e["scanner"]["sast"] = {"available": True, "blocking": []}; e["scanner"]["sca"] = {"available": False}; self.assertEqual(A.gate(e)["decision"], "UNKNOWN")
    def test_permit_and_registry(self):
        s = Signer.generate("rel", "t"); reg = A.MockRegistry("registry.test/prod", s.public_raw(), clock=lambda: 1000.0); art = b"artifact-bytes"; sh = A.sha(art)
        mk = lambda **k: A.issue_permit(s, **{**dict(artifact_sha256=sh, destination="registry.test/prod", evidence_digest="e", ttl_s=60, now=1000), **k})
        self.assertEqual(reg.publish(art, None)["code"], "NO_PERMIT"); self.assertEqual(reg.publish(art, mk(destination="registry.test/dev"))["code"], "WRONG_DESTINATION"); self.assertEqual(reg.publish(art + b"x", mk())["code"], "ARTIFACT_DIGEST_MISMATCH")
        self.assertEqual(reg.publish(art, mk(now=900))["code"], "PERMIT_EXPIRED"); other = A.issue_permit(Signer.generate("evil", "t"), artifact_sha256=sh, destination="registry.test/prod", evidence_digest="e", now=1000); self.assertEqual(reg.publish(art, other)["code"], "BAD_PERMIT_SIGNATURE")
        p = mk(); p["body"]["destination"] = "registry.test/prod"; p["body"]["exp"] += 10 ** 6; self.assertEqual(reg.publish(art, p)["code"], "BAD_PERMIT_SIGNATURE"); self.assertEqual(reg.releases, []); self.assertTrue(reg.publish(art, mk())["ok"]); self.assertEqual(len(reg.releases), 1)
    def test_exception_requires_authenticated_admin(self):
        rel, adm = Signer.generate("rel", "t"), Signer.generate("adm", "t"); sh = "ab" * 32; kw = dict(artifact_sha256=sh, destination="registry.test/prod")
        mk = lambda role: PV.issue_approval(adm, approver="carol", role=role, policy_digest="P", scope=kw, ttl_s=60, now=1000)
        p = A.exception_permit(rel, mk("admin"), adm.public_raw(), evidence_digest="e", policy_digest="P", now=1010, **kw); self.assertEqual(p["body"]["exception"], {"approver": "carol", "role": "admin"})
        with self.assertRaises(PV.ApprovalError): A.exception_permit(rel, mk("user"), adm.public_raw(), evidence_digest="e", policy_digest="P", now=1010, **kw)       # a user is not an admin
        with self.assertRaises(PV.ApprovalError): PV.issue_approval(adm, approver="agent", role="agent", policy_digest="P", scope=kw)
        with self.assertRaises(PV.ApprovalError): A.exception_permit(rel, mk("admin"), adm.public_raw(), evidence_digest="e", policy_digest="P", now=2000, **kw)         # expired
        with self.assertRaises(PV.ApprovalError): A.exception_permit(rel, mk("admin"), adm.public_raw(), evidence_digest="e", policy_digest="P", now=1010, artifact_sha256="cd" * 32, destination="registry.test/prod")  # other artifact

@unittest.skipUnless(OK, "UNSUPPORTED environment: root + Landlock needed (HR-G6 not exercised)")
class Live(unittest.TestCase):
    def test_vulnerable_exploited_patched_not_with_same_functionality(self):
        for n in ("sqli", "traversal", "cmdinj", "authz"):
            v, p = ev(n, "vulnerable"), ev(n, "patched")
            self.assertTrue(v["oracle"]["exploited"], n); self.assertFalse(p["oracle"]["exploited"], n); self.assertTrue(v["oracle"]["functional_ok"] and p["oracle"]["functional_ok"], n)      # same behavior on benign cases
            self.assertEqual(A.gate(v)["decision"], "BLOCK", n); self.assertEqual(A.gate(p)["decision"], "ALLOW", n)
    def test_scanner_and_oracle_are_separate_evidence_and_scan_only_misses(self):
        miss = {n: (ev(n, "vulnerable")["scanner"]["sast"]["blocking"] == []) and ev(n, "vulnerable")["oracle"]["exploited"] for n in ("sqli", "traversal", "authz", "cmdinj")}
        self.assertTrue(miss["traversal"] and miss["authz"] and miss["sqli"])                    # HAA-24: scan-only would have shipped these three
        self.assertFalse(miss["cmdinj"])                                                         # bandit B602 (HIGH) does flag the shell=True injection
        e = ev("authz", "vulnerable"); self.assertTrue(set(e) >= {"scanner", "oracle"}); self.assertNotIn("exploited", json.dumps(e["scanner"]))
    def test_dependency_policy_blocks_in_gate(self):
        for deps, reason in [("libfoo==1.1.0\n", "SCA_BLOCKING"), ("libfoo>=1.3\n", "DEPENDENCY_POLICY:UNPINNED"), ("libfoo==1.3.0 @ https://evil.example/f.whl\n", "DEPENDENCY_POLICY:UNAUTHORIZED_SOURCE")]:
            g = A.gate(ev("sqli", "patched", deps)); self.assertEqual(g["decision"], "BLOCK", deps); self.assertIn(reason, g["reasons"])
        self.assertEqual(A.gate(ev("sqli", "patched", GOOD_DEPS))["decision"], "ALLOW")
    def test_build_is_sandboxed_deterministic_and_signed(self):
        src = {"a.py": "print(1)\n", "pkg/b.py": "X = 2\n"}; b1, b2 = A.build(src), A.build(src); self.assertEqual(b1["network"], "denied"); self.assertEqual(b1["artifact_sha256"], b2["artifact_sha256"])
        s = Signer.generate("b", "t"); m = A.make_manifest(b1, s); self.assertTrue(A.verify_manifest(m, s.public_raw(), b1["artifact"])); self.assertFalse(A.verify_manifest(m, s.public_raw(), b1["artifact"] + b"x")); self.assertFalse(A.verify_manifest(m, Signer.generate("z", "t").public_raw(), b1["artifact"]))
        self.assertEqual(m["body"]["builder"]["policy_digest"], b1["policy_digest"]); self.assertEqual(set(m["body"]["files"]), {"a.py", "pkg/b.py"}); self.assertEqual(b1["profile"]["nonewprivs"], "1")
        with self.assertRaises(RuntimeError): A.build({"bad.py": "def (:\n"})                         # build failure is reported, not hidden
    def test_secret_in_build_output_detected_and_leak_blocked(self):
        b = A.build({"app.py": "x=1\n", "conf.txt": "key TEST_CANARY_NOT_SECRET-registry\n"}); hits = A.scan_secrets({"dist.zip": b["artifact"]}); self.assertEqual([h["kind"] for h in hits], ["CANARY"]); self.assertIn("dist.zip!conf.txt", hits[0]["where"])
        clean = A.build({"app.py": "x=1\n"}); self.assertEqual(A.scan_secrets({"dist.zip": clean["artifact"]}), [])
    def test_end_to_end_release_cannot_bypass_gate(self):
        s = Signer.generate("rel", "t"); reg = A.MockRegistry("registry.test/prod", s.public_raw())
        for name, variant in (("sqli", "vulnerable"), ("sqli", "patched")):
            fx = A.fixture(name, variant); b = A.build(fx["files"]); e = A.evidence(fx, deps_text=GOOD_DEPS, db=DB, db_digest=DG); g = A.gate(e)
            permit = A.issue_permit(s, artifact_sha256=b["artifact_sha256"], destination="registry.test/prod", evidence_digest=e["digest"]) if g["decision"] == "ALLOW" else None
            r = reg.publish(b["artifact"], permit); self.assertEqual(r["ok"], variant == "patched", variant)
        self.assertEqual(len(reg.releases), 1); self.assertEqual(reg.rejections, ["NO_PERMIT"])
        # a permit for the patched build cannot be reused for the vulnerable build
        pb = A.build(A.fixture("sqli", "patched")["files"]); vb = A.build(A.fixture("sqli", "vulnerable")["files"]); pp = A.issue_permit(s, artifact_sha256=pb["artifact_sha256"], destination="registry.test/prod", evidence_digest="e"); self.assertEqual(reg.publish(vb["artifact"], pp)["code"], "ARTIFACT_DIGEST_MISMATCH")
    def test_sandboxed_code_cannot_reach_registry_or_network(self):
        r = S.launch("import socket,json\nres=[]\nfor h,p in [('127.0.0.1',1),('pypi.org',443),('169.254.169.254',80)]:\n  try: socket.create_connection((h,p),timeout=1); res.append('REACHED')\n  except OSError as e: res.append(e.errno or 0)\nprint(json.dumps(res))", run_id="np"); self.assertNotIn("REACHED", r.stdout)
    def test_false_positive_report_on_benign_apps_and_changed_deps(self):
        benign = [("benign_a", "patched"), ("benign_b", "patched"), ("benign_c", "patched"), ("sqli", "patched"), ("traversal", "patched"), ("cmdinj", "patched"), ("authz", "patched")]; blocked = []
        for n, v in benign:
            fx = A.fixture(n, v); g = A.gate(A.evidence(fx, deps_text=GOOD_DEPS, db=DB, db_digest=DG))
            if g["decision"] != "ALLOW": blocked.append((n, g["reasons"]))
        self.assertEqual(blocked, [], blocked)                                                  # 0/7 verified false blocks (denominator 7; small sample, not a rate claim)
        changed = [("libfoo==1.2.0\nlibbar==0.5.0\n", "ALLOW"), ("libfoo==1.3.5\n", "ALLOW"), ("libfoo==1.0.0\n", "BLOCK")]
        for deps, want in changed: self.assertEqual(A.gate(ev("benign_a", "patched", deps))["decision"], want, deps)
    def test_cost_measured(self):
        t = time.time(); e = ev("traversal", "vulnerable"); dt = time.time() - t; self.assertLess(dt, 30); self.assertGreater(e["scanner"]["sast"]["seconds"], 0); self.assertTrue(e["scanner"]["sast"]["loc"] > 0); self.assertGreater(e["scanner"]["sast"]["peak_rss_kb"], 0)
if __name__ == "__main__": unittest.main()
