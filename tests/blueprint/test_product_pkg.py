import copy, io, json, os, shutil, stat, subprocess, sys, tarfile, tempfile, threading, unittest, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from horizon.product import cli, codingagent as C, dashboard as D, home as H, model as M
from horizon.runtime import runner as R, sandbox as S

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CAN = os.geteuid() == 0 and S.landlock_abi() >= 4


def mk_home(t):
    d = tempfile.mkdtemp(); t.addCleanup(shutil.rmtree, d, True); h = H.Home(os.path.join(d, "h")); h.init(dev_keys=True); return h, d


def mk_repo(t, d):
    r = os.path.join(d, "repo"); C.make_repo(r); return r


class Pure(unittest.TestCase):
    def test_init_refuses_to_invent_key_custody_and_to_reinitialise_and_protects_the_key(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True); h = H.Home(os.path.join(d, "h"))
        with self.assertRaises(H.ProductError) as c: h.init()
        self.assertEqual(c.exception.code, "KEY_REQUIRED"); self.assertFalse(os.path.exists(h.p("config.json")))
        h.init(dev_keys=True); self.assertEqual(stat.S_IMODE(os.stat(h.p("keys", "evidence.pem")).st_mode), 0o600); self.assertIn("DEV-GRADE", json.load(open(h.p("config.json")))["key_custody"])
        with self.assertRaises(H.ProductError): h.init(dev_keys=True)
        self.assertNotIn("private", open(h.p("keys", "trust.json")).read().lower())
    def test_profiles_are_digested_and_validated(self):
        self.assertEqual(H.profile_digest("strict-repo"), H.profile_digest("strict-repo")); self.assertNotEqual(H.profile_digest("strict-repo"), H.profile_digest("standard-repo"))
    def test_run_refuses_bad_inputs_before_touching_anything(self):
        h, d = mk_home(self); r = mk_repo(self, d); before = H.tree_digest(r)
        for kw, code in (({"profile": "nope"}, "UNKNOWN_PROFILE"), ({"allow": (".github/*",)}, "GLOB_TOO_BROAD"), ({"allow": ("*",)}, "GLOB_TOO_BROAD"), ({"profile": "standard-repo", "allow": ("x/*",)}, "PROFILE_FIXED"), ({"run_id": "../x"}, "BAD_RUN_ID")):
            with self.assertRaises(H.ProductError, msg=str(kw)) as c: H.run_agent(h, r, "print(1)", **kw)
            self.assertEqual(c.exception.code, code)
        self.assertEqual(H.tree_digest(r), before); self.assertEqual(h.run_ids(), [])
    def test_cannot_confine_means_refused_never_unconfined(self):
        h, d = mk_home(self); r = mk_repo(self, d); before = H.tree_digest(r); orig = R.ConfinedRunner.run
        try:
            R.ConfinedRunner.run = lambda self_, code, **kw: R.RunReport(kw["run_id"], False, "UNSUPPORTED: needs root/CAP_SYS_ADMIN", None, "", "", False, "d", {})
            with self.assertRaises(H.ProductError) as c: H.run_agent(h, r, C.LEGIT, allow=("calc/*",), apply=True)
        finally: R.ConfinedRunner.run = orig
        self.assertEqual(c.exception.code, "CANNOT_CONFINE"); self.assertEqual(h.run_ids(), []); self.assertEqual(H.tree_digest(r), before)
    def test_bundle_signature_tamper_wrong_key_and_role(self):
        h, d = mk_home(self); body = {"kind": "hzd-evidence-v1", "changes": [], "enforcer_trust": {}}; doc = H.sign_bundle(body, h.signer()); tr = h.trust(); self.assertTrue(H.verify_bundle(doc, tr)["ok"])
        t = copy.deepcopy(doc); t["body"]["kind"] = "x"; self.assertFalse(H.verify_bundle(t, tr)["ok"]); self.assertFalse(H.verify_bundle({**doc, "sig": "00" * 64}, tr)["ok"]); self.assertFalse(H.verify_bundle({"body": {}}, tr)["ok"]); self.assertFalse(H.verify_bundle({}, tr)["ok"]); self.assertFalse(H.verify_bundle("x", tr)["ok"])
        other, _ = mk_home(self); self.assertFalse(H.verify_bundle(doc, other.trust())["ok"])                       # a different install's key does not vouch for it
        from horizon.authz.keys import Signer, TrustStore
        w = Signer.generate("ev1", "assurance-issuer"); ts = TrustStore(); ts.add("ev1", "assurance-issuer", w.public_raw(), not_before=0, not_after=2 ** 40); self.assertFalse(H.verify_bundle(H.sign_bundle(body, w), ts)["ok"])      # right kid, wrong role

    def test_dashboard_is_loopback_only_readonly_escaped_and_flags_bad_bundles(self):
        h, d = mk_home(self)
        with self.assertRaises(H.ProductError): D.serve(h, "0.0.0.0")
        evil = {"kind": "hzd-evidence-v1", "run_id": "rX", "mode": "apply", "profile": {"name": "<img src=x onerror=alert(1)>", "allow_globs": []}, "runner": {"agent_exit": 0, "confined": True}, "changes": [{"path": "<script>alert(1)</script>.py", "op": "create", "status": "ALLOW_COMMITTED", "code": None}],
                "journal": {"chain_ok": True, "records": 0}, "limits": ["<b>x</b>"], "enforcer_trust": {}}
        os.makedirs(h.p("runs", "rX")); json.dump(H.sign_bundle(evil, h.signer()), open(h.p("runs", "rX", "bundle.json"), "w"))
        good = H.sign_bundle({**evil, "run_id": "rY"}, h.signer()); good["body"]["mode"] = "tampered"; os.makedirs(h.p("runs", "rY")); json.dump(good, open(h.p("runs", "rY", "bundle.json"), "w"))
        srv = D.serve(h); th = threading.Thread(target=srv.serve_forever, daemon=True); th.start(); self.addCleanup(lambda: (srv.shutdown(), srv.server_close())); base = f"http://127.0.0.1:{srv.server_address[1]}"
        get = lambda p: urllib.request.urlopen(base + p, timeout=5)
        r = get("/run/rX"); t = r.read().decode(); self.assertNotIn("<script>", t); self.assertNotIn("<img src=x", t); self.assertIn("&lt;script&gt;", t); self.assertIn("default-src 'none'", r.headers["Content-Security-Policy"]); self.assertNotIn("<script", get("/").read().decode().lower())
        self.assertIn("VERIFICATION FAILED", get("/run/rY").read().decode()); self.assertEqual({x["run_id"]: x["verified"] for x in json.loads(get("/api/runs.json").read())}, {"rX": False, "rY": False})        # rX is validly signed but claims a landed edit with no receipt, so it must NOT verify; rY is tampered after signing
        for p in ("/run/..%2f..%2fconfig.json", "/run/", "/nope"):
            with self.assertRaises(urllib.error.HTTPError) as c: get(p)
            self.assertEqual(c.exception.code, 404)
        with self.assertRaises(urllib.error.HTTPError) as c: urllib.request.urlopen(urllib.request.Request(base + "/", data=b"x", method="POST"), timeout=5)
        self.assertEqual(c.exception.code, 405)

    def test_model_hook_refuses_remote_endpoints_and_extracts_only_a_code_block(self):
        with self.assertRaises(M.ModelError) as c: M.propose_program("http://example.com:11434", "m", "t", ".")
        self.assertEqual(str(c.exception), "REMOTE_ENDPOINT_REFUSED")
        self.assertEqual(M.extract_program("hi\n```python\nx=1\n```\nbye"), "x=1\n")
        for bad in ("no code", "```python\n\n```", None): 
            with self.assertRaises(M.ModelError): M.extract_program(bad)
        with self.assertRaises(M.ModelError): M.propose_program("http://127.0.0.1:9", "m", "t", ".", timeout=1)       # nothing listening: explicit error, no fallback

    def test_cli_exit_codes_and_offline_verify(self):
        h, d = mk_home(self); doc = H.sign_bundle({"kind": "hzd-evidence-v1", "changes": [], "enforcer_trust": {}}, h.signer()); p = os.path.join(d, "b.json"); json.dump(doc, open(p, "w"))
        self.assertEqual(cli.main(["--home", h.path, "verify", p]), 0); doc["body"]["kind"] = "x"; json.dump(doc, open(p, "w")); self.assertEqual(cli.main(["--home", h.path, "verify", p]), 1)
        self.assertEqual(cli.main(["--home", os.path.join(d, "none"), "run", "--repo", d, "--program", p]), 1); self.assertEqual(cli.main(["--home", os.path.join(d, "new"), "init"]), 1)
        with self.assertRaises(SystemExit) as c: cli.main(["bogus"])
        self.assertEqual(c.exception.code, 2)

    # ----- packaging
    def test_release_build_is_byte_reproducible_and_install_is_verifiable_offline(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True); outs = []
        for i in (1, 2): outs.append(subprocess.run([sys.executable, "-B", os.path.join(ROOT, "scripts/build_dist.py"), "--out", os.path.join(d, f"o{i}")], capture_output=True, text=True, check=True).stdout.split()[-1])
        self.assertEqual(outs[0], outs[1]); tgz = os.path.join(d, "o1", "hzd-%s.tar.gz" % H.VERSION); self.assertEqual(open(tgz + ".sha256").read().split()[0], outs[0]); self.assertEqual(open(os.path.join(d, "o1", "hzd-%s.tar.gz" % H.VERSION), "rb").read()[4:8], b"\0\0\0\0")      # gzip mtime 0
        tarfile.open(tgz).extractall(os.path.join(d, "x"), filter="data"); rel = os.path.join(d, "x", "hzd-" + H.VERSION); prefix = os.path.join(d, "prefix")
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin"}; inst = lambda *a, **k: subprocess.run([sys.executable, os.path.join(rel, "install.py"), *a], capture_output=True, text=True, env=env, **k)
        r = inst("--prefix", prefix); self.assertEqual(r.returncode, 0, r.stdout + r.stderr); self.assertTrue(json.loads(r.stdout)["ok"])
        v = subprocess.run([os.path.join(prefix, "bin", "hzd"), "version"], capture_output=True, text=True, env=env, cwd=d); self.assertEqual((v.returncode, json.loads(v.stdout)["hzd"]), (0, H.VERSION), v.stderr)      # the INSTALLED copy runs on its own
        ok = lambda: subprocess.run([sys.executable, os.path.join(rel, "install.py"), "--verify-only", prefix], capture_output=True, text=True, env=env)
        self.assertEqual(ok().returncode, 0); self.assertEqual(inst("--prefix", prefix).returncode, 1)                       # refuses to overwrite
        open(os.path.join(prefix, "lib", "horizon", "product", "cli.py"), "a").write("# edit\n"); open(os.path.join(prefix, "lib", "horizon", "extra.py"), "w").write("x=1\n"); r = ok(); self.assertEqual(r.returncode, 1)
        self.assertIn("modified:horizon/product/cli.py", r.stdout); self.assertIn("unexpected:horizon/extra.py", r.stdout)
        open(os.path.join(rel, "horizon", "product", "home.py"), "a").write("# tampered release\n"); r = inst("--prefix", os.path.join(d, "p2")); self.assertEqual(r.returncode, 1); self.assertIn("modified:horizon/product/home.py", r.stdout); self.assertFalse(os.path.exists(os.path.join(d, "p2")))


@unittest.skipUnless(CAN, "needs root + Landlock ABI>=4 (NOT a pass)")
class Live(unittest.TestCase):
    def test_apply_run_lands_legit_edits_blocks_the_rest_and_the_bundle_verifies_offline(self):
        h, d = mk_home(self); r = mk_repo(self, d); doc = H.run_agent(h, r, C.ATTACK, allow=("calc/*", "CHANGELOG.md"), apply=True, check_cmd=f"{sys.executable} -B -m unittest discover -s tests -t .", run_id="r-attack")
        b = doc["body"]; st = {c["path"]: c["status"] for c in b["changes"]}
        self.assertEqual({p: s for p, s in st.items() if s == "ALLOW_COMMITTED"}, {"CHANGELOG.md": "ALLOW_COMMITTED", "calc/ops.py": "ALLOW_COMMITTED"}); self.assertEqual({c["code"] for c in b["changes"] if c["status"] == "BLOCKED"}, {"POLICY_DENIED"}); self.assertEqual(b["check"]["exit"], 0)
        self.assertEqual(open(os.path.join(r, ".env")).read(), C.REPO[".env"]); self.assertFalse(os.path.exists(os.path.join(r, ".github"))); self.assertNotEqual(b["repo"]["before"], b["repo"]["after"]); self.assertTrue(b["journal"]["chain_ok"])
        res = H.verify_bundle(json.load(open(h.p("runs", "r-attack", "bundle.json"))), h.trust()); self.assertTrue(res["ok"], res); self.assertEqual(res["checks"]["receipt_count"], 2)
        t = json.load(open(h.p("runs", "r-attack", "bundle.json"))); t["body"]["changes"][0]["status"] = "ALLOW_COMMITTED"; t["body"]["changes"][-1]["path"] = "calc/evil.py"; self.assertFalse(H.verify_bundle(t, h.trust())["ok"])
        rc = H.recover_check(h); self.assertTrue(rc["ok"], rc)
    def test_dry_run_changes_nothing_and_readonly_profile_blocks_everything(self):
        h, d = mk_home(self); r = mk_repo(self, d); before = H.tree_digest(r)
        a = H.run_agent(h, r, C.LEGIT, allow=("calc/*", "CHANGELOG.md"))["body"]; self.assertEqual((a["mode"], {c["status"] for c in a["changes"]}, H.tree_digest(r)), ("dry-run", {"WOULD_ALLOW"}, before))
        b = H.run_agent(h, r, C.LEGIT, profile="readonly-audit", apply=True)["body"]; self.assertEqual(({c["status"] for c in b["changes"]}, H.tree_digest(r)), ({"BLOCKED"}, before))
        c = H.run_agent(h, r, C.LEGIT, profile="strict-repo", apply=True)["body"]; self.assertEqual(({x["status"] for x in c["changes"]}, H.tree_digest(r)), ({"BLOCKED"}, before))                          # strict-repo with no --allow lets nothing land
    def test_model_hook_end_to_end_against_a_stub_server_with_a_malicious_reply(self):
        reply = "Here you go:\n```python\n" + C.ATTACK + "\n```\n"
        class Stub(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"])); out = json.dumps({"choices": [{"message": {"content": reply}}]}).encode(); self.send_response(200); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
        srv = HTTPServer(("127.0.0.1", 0), Stub); threading.Thread(target=srv.serve_forever, daemon=True).start(); self.addCleanup(lambda: (srv.shutdown(), srv.server_close()))
        h, d = mk_home(self); r = mk_repo(self, d); rc = cli.main(["--home", h.path, "model-run", "--repo", r, "--endpoint", f"http://127.0.0.1:{srv.server_address[1]}", "--model", "stub", "--task", "fix mean", "--allow", "calc/*", "--allow", "CHANGELOG.md", "--apply"])
        self.assertEqual(rc, 0); b = h.load_bundle(h.run_ids()[0])["body"]; self.assertEqual(b["agent"]["id"], "model-agent"); self.assertEqual(sorted(c["path"] for c in b["changes"] if c["status"] == "ALLOW_COMMITTED"), ["CHANGELOG.md", "calc/ops.py"]); self.assertFalse(os.path.exists(os.path.join(r, ".github")))
    def test_backup_restore_and_recovery_checks(self):
        h, d = mk_home(self); r = mk_repo(self, d); H.run_agent(h, r, C.LEGIT, allow=("calc/*", "CHANGELOG.md"), apply=True, run_id="r1"); self.assertTrue(H.recover_check(h)["ok"])
        bk, sha = H.backup(h); self.assertNotIn("evidence.pem", " ".join(m.name for m in tarfile.open(bk).getmembers())); self.assertTrue(all(m.mtime == 0 for m in tarfile.open(bk).getmembers()))
        with self.assertRaises(H.ProductError) as c: H.backup(h, bk)
        self.assertEqual(c.exception.code, "EXISTS")
        dst = H.Home(os.path.join(d, "restored")); 
        with self.assertRaises(H.ProductError) as c: H.restore(bk, dst, "sha256:" + "0" * 64)
        self.assertEqual(c.exception.code, "HASH_MISMATCH"); self.assertFalse(os.path.exists(dst.path))
        rep = H.restore(bk, dst, sha); self.assertTrue(rep["ok"]); self.assertEqual(dst.run_ids(), ["r1"])
        with self.assertRaises(H.ProductError) as c: H.restore(bk, dst, sha)
        self.assertEqual(c.exception.code, "EXISTS")
        # tail truncation of the journal is detected; a corrupted bundle is detected; both on the live home
        j = h.p("state", "journal"); lines = open(j).read().splitlines(True); open(j, "w").writelines(lines[:-1]); rc = H.recover_check(h); self.assertFalse(rc["ok"]); self.assertEqual(rc["journal"]["status"], "FAILED")
        open(j, "w").writelines(lines); bp = h.p("runs", "r1", "bundle.json"); t = json.load(open(bp)); t["body"]["mode"] = "x"; json.dump(t, open(bp, "w")); rc = H.recover_check(h); self.assertEqual((rc["bundles"]["status"], rc["bundles"]["failed"]), ("FAILED", ["r1"]))
    def test_a_corrupt_backup_or_one_with_unsafe_members_is_refused_and_leaves_nothing(self):
        h, d = mk_home(self); bk, sha = H.backup(h); import gzip
        for name, data in (("../evil.txt", b"x"), ("keys/evidence.pem", b"x")):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as t: ti = tarfile.TarInfo(name); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
            raw = gzip.compress(buf.getvalue(), mtime=0); p = os.path.join(d, "bad.tgz"); open(p, "wb").write(raw); dst = H.Home(os.path.join(d, "r-" + str(len(name))))
            with self.assertRaises(H.ProductError) as c: H.restore(p, dst, H.sha256(raw))
            self.assertEqual(c.exception.code, "BAD_MEMBER"); self.assertFalse(os.path.exists(dst.path))
        open(os.path.join(d, "junk.tgz"), "wb").write(b"junk")
        with self.assertRaises(H.ProductError) as c: H.restore(os.path.join(d, "junk.tgz"), H.Home(os.path.join(d, "r3")), H.sha256(b"junk"))
        self.assertEqual(c.exception.code, "BAD_ARCHIVE")
if __name__ == "__main__": unittest.main()
