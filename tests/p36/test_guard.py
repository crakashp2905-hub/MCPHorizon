import glob, json, os, tempfile, time, unittest
from horizon.authz.keys import Signer
from horizon.infraguard import guard as G
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); IAC = os.path.join(ROOT, "benchmarks/hieb/iac")
def lint_file(n, **kw): p = os.path.join(IAC, n); return G.lint_text(open(p).read(), os.path.relpath(p, ROOT), **kw)
def rules(fs): return sorted({f["rule"] for f in fs})
class Boundary(unittest.TestCase):
    def test_integrate_vs_build_boundary_documented(self):
        t = open(os.path.join(ROOT, "docs/evidence/p36/INTEGRATE_VS_BUILD.md")).read()
        for k in ("Integrate", "Build narrowly", "Forbidden by default", "Non-goals"): self.assertIn(k, t)
class LocalOnly(unittest.TestCase):
    def test_scan_allowed_default_deny(self):
        for h in ("127.0.0.1", "localhost", "::1", "[::1]", "svc.test", "a.example", "x.localhost"): self.assertTrue(G.scan_allowed(h), h)
        for h in ("8.8.8.8", "10.0.0.5", "169.254.169.254", "example.com", "evil.com", "0.0.0.0", "192.168.1.1"): self.assertFalse(G.scan_allowed(h), h)
        with self.assertRaises(G.ScanForbidden): G.http_call("8.8.8.8", 80, "/")
    def test_service_binds_loopback_only(self):
        with G.SyntheticService() as s: self.assertEqual(s.srv.server_address[0], "127.0.0.1")
class IaC(unittest.TestCase):
    def test_known_bad_fixtures_each_trip_expected_rules(self):
        self.assertEqual(rules(lint_file("bad_public_db.yml")), ["IG001", "IG002", "IG003", "IG005", "IG009"]); self.assertEqual(rules(lint_file("bad_admin_exposed.yml", admin_allowlist=["/admin/config"])), ["IG001", "IG004", "IG009"])
        self.assertEqual(rules(lint_file("bad_secret_env.yml")), ["IG005"]); self.assertEqual(rules(lint_file("bad_logui_retention_roles.yml")), ["IG006", "IG007", "IG008"])
    def test_clean_control_passes(self):
        self.assertEqual(lint_file("good_db.yml", admin_allowlist=["/admin/config"]), []); self.assertEqual(G.deployment_report([])["decision"], "ALLOW")
    def test_blocking_report_cites_path_rule_and_hides_values(self):
        f = lint_file("bad_secret_env.yml"); r = G.deployment_report(f); self.assertEqual(r["decision"], "BLOCK"); self.assertEqual(f[0]["source"], "benchmarks/hieb/iac/bad_secret_env.yml"); self.assertEqual(f[0]["location"], "/services/api/environment/API_TOKEN"); self.assertEqual(f[0]["rule"], "IG005")
        self.assertNotIn("abcd1234efgh5678", json.dumps(r)); self.assertIn("exact", "exact") 
        f = lint_file("bad_public_db.yml"); self.assertTrue(any(x["rule"] == "IG001" and x["location"] == "/services/db/ports/0" and "0.0.0.0:5432" in x["detail"] for x in f))
    def test_port_forms_and_unparsable_is_unknown_blocking(self):
        d = lambda p: G.lint({"services": {"s": {"ports": [p], "x-auth": {"mode": "token"}, "x-tls": True}}})
        self.assertEqual([x["rule"] for x in d("5432:5432")], ["IG001"]); self.assertEqual([x["rule"] for x in d("5432")], ["IG001"]); self.assertEqual(d("127.0.0.1:5432:5432"), []); self.assertEqual([x["rule"] for x in d({"target": 5432, "published": 5432, "host_ip": "0.0.0.0"})], ["IG001"])
        bad = G.lint_text("services: [unclosed", "x.yml"); self.assertEqual(bad[0]["rule"], "IG000"); self.assertEqual(G.deployment_report(bad)["decision"], "BLOCK")
    def test_env_list_form_and_secret_refs_allowed(self):
        self.assertEqual(rules(G.lint({"services": {"s": {"environment": ["DB_PASSWORD=hunter2hunter2"], "x-auth": {"mode": "token"}}}})), ["IG005"]); self.assertEqual(G.lint({"services": {"s": {"environment": {"DB_PASSWORD": "env://DB_PW"}, "x-auth": {"mode": "token"}}}}), [])
    def test_baked_image_secrets_flagged_clean_image_passes(self):      # P36-10
        bad = G.image_secret_scan({"app/.env": b"K=AKIA" + b"A" * 16 + b"\n", "etc/x.conf": b"token=ghp_" + b"b" * 24}); self.assertTrue(bad); self.assertTrue(all(x["detail"] == "value redacted" for x in bad)); self.assertNotIn("AKIA" + "A" * 16, json.dumps(bad)); self.assertEqual(G.image_secret_scan({"app/main.py": b"print('hi')\n"}), [])
class Dynamic(unittest.TestCase):
    def test_anonymous_vs_authenticated_separate_fixtures(self):
        with G.SyntheticService(require_auth=True) as good: r = G.probe_auth("127.0.0.1", good.port, user_token="tok-t1")
        self.assertFalse(r["anonymous_data_exposed"]); self.assertEqual(r["anonymous"]["status"], 401); self.assertTrue(r["benign_ok"])
        with G.SyntheticService(require_auth=False) as bad: r = G.probe_auth("127.0.0.1", bad.port, user_token="tok-t1")
        self.assertTrue(r["anonymous_data_exposed"]); self.assertEqual(r["anonymous"]["rows_returned"], 1)
    def test_endpoint_inventory_vs_allowlist(self):
        inv = ["/query", "/admin/config", "/logs/t1"]
        with G.SyntheticService(require_auth=True) as s: r = G.probe_endpoints("127.0.0.1", s.port, inventory=inv, allowlist=[]); self.assertEqual(r["unallowlisted_anonymous"], []); self.assertIn("/admin/config", r["responding"]); self.assertEqual(r["undeclared"], ["/metrics"])
        with G.SyntheticService(require_auth=False, metrics_public=True) as s: r = G.probe_endpoints("127.0.0.1", s.port, inventory=inv, allowlist=[]); self.assertIn("/metrics", r["unallowlisted_anonymous"]); self.assertIn("/admin/config", r["unallowlisted_anonymous"])
        with G.SyntheticService(require_auth=True, metrics_public=True) as s: r = G.probe_endpoints("127.0.0.1", s.port, inventory=inv, allowlist=["/metrics"]); self.assertEqual(r["unallowlisted_anonymous"], [])
    def test_log_ui_auth_and_tenant_isolation(self):
        with G.SyntheticService() as ok: r = G.check_log_ui("127.0.0.1", ok.port)
        self.assertTrue(r["auth_ok"] and r["isolation_ok"] and r["benign_ok"])
        with G.SyntheticService(logui_tenant_isolation=False) as s: self.assertFalse(G.check_log_ui("127.0.0.1", s.port)["isolation_ok"])
        with G.SyntheticService(logui_auth=False) as s: self.assertFalse(G.check_log_ui("127.0.0.1", s.port)["auth_ok"])
    def test_log_canary_scanner_never_echoes_raw_value(self):
        with G.SyntheticService() as s:
            raw = "TEST_CANARY_NOT_SECRET:logline-77"; s.add_log("t1", "ok line"); s.add_log("t1", "leak " + raw); r = G.canary_scan_logs("127.0.0.1", s.port, token="tok-t1", tenant="t1")
        self.assertEqual(r["canaries_found"], 1); self.assertNotIn(raw, json.dumps(r)); self.assertNotIn("logline-77", json.dumps(r)); self.assertEqual(len(r["evidence_sha256"][0]), 16)
    def test_retention_and_access_controlled_deletion(self):
        with G.SyntheticService(retention_s=60) as s:
            s.add_log("t1", "old", t=time.time() - 3600); s.add_log("t1", "new"); r = G.check_retention("127.0.0.1", s.port, token_user="tok-t1", token_admin="tok-admin", expired_present=True)
            self.assertTrue(r["access_controlled"]); self.assertTrue(r["expired_removed"]); self.assertEqual([l["line"] for l in s.logs["t1"]], ["new"])
class Evidence(unittest.TestCase):
    def test_signed_evidence_into_risk_view_agent_cannot_forge(self):
        sg = Signer.generate("posture", "infraguard"); rv = G.RiskView(sg.public_raw(), clock=lambda: 1000.0)
        rep = G.deployment_report(lint_file("bad_public_db.yml")); ev = G.sign_evidence(sg, rep, subject="db", now=1000.0); self.assertTrue(rv.ingest(ev)); self.assertEqual(rv.risk("db")["state"], "BLOCKED")
        forged = G.sign_evidence(Signer.generate("agent", "x"), G.deployment_report([]), subject="db", now=1000.0); self.assertFalse(rv.ingest(forged)); self.assertEqual(rv.risk("db")["state"], "BLOCKED")
        t = dict(ev, decision="ALLOW"); self.assertFalse(rv.ingest(t)); self.assertEqual(rv.risk("unknown-svc")["state"], "UNKNOWN"); rv2 = G.RiskView(sg.public_raw(), clock=lambda: 9999999.0); rv2.ingest(ev); self.assertEqual(rv2.risk("db")["state"], "UNKNOWN")
        self.assertFalse([m for m in dir(rv) if any(w in m.lower() for w in ("deploy", "apply", "admin", "delete", "scan"))])      # no authority methods on the view
class Comparison(unittest.TestCase):
    def test_committed_comparison_is_honest_and_consistent(self):
        import hashlib
        d = os.path.join(ROOT, "results/v2/p36-checkov-compare"); m = json.load(open(d + "/manifest.json")); self.assertEqual(hashlib.sha256(open(d + "/result.json", "rb").read()).hexdigest(), m["files"]["result.json"])
        r = json.load(open(d + "/result.json")); self.assertEqual((r["n_bad"], r["n_good"]), (4, 1)); self.assertEqual(r["infraguard_detected"], 4); self.assertEqual(r["infraguard_false_positives"], 0); self.assertLess(r["checkov_detected"], r["infraguard_detected"])
        self.assertGreaterEqual(r["checkov_unsupported_format"], 4); self.assertTrue(any("favours InfraGuard" in c for c in r["caveats"]))
        live = {x["fixture"]: sorted({f["rule"] for f in G.lint_text(open(os.path.join(IAC, x["fixture"])).read(), x["fixture"], admin_allowlist=["/admin/config"])}) for x in r["rows"]}; self.assertEqual(live, {x["fixture"]: x["infraguard_rules"] for x in r["rows"]})      # the stored comparison still matches the current rule engine
        t = open(os.path.join(ROOT, "docs/evidence/p36/COMPARISON.md")).read(); self.assertIn("unsupported", t); self.assertIn("favours InfraGuard", t)
class MG(unittest.TestCase):
    def test_mg_g10_all_known_bad_rejected_good_passes_and_no_external(self):
        bad = [f for f in sorted(glob.glob(os.path.join(IAC, "bad_*.yml")))]; self.assertGreaterEqual(len(bad), 4)
        for f in bad: self.assertEqual(G.deployment_report(G.lint_text(open(f).read(), f, admin_allowlist=["/admin/config"]))["decision"], "BLOCK", f)
        self.assertEqual(G.deployment_report(lint_file("good_db.yml", admin_allowlist=["/admin/config"]))["decision"], "ALLOW")
        import re; src = open(os.path.join(ROOT, "horizon/infraguard/guard.py")).read(); self.assertFalse(re.findall(r"https?://(?!\{host)[a-z0-9.-]+\.(com|net|org|io)", src))
if __name__ == "__main__": unittest.main()
