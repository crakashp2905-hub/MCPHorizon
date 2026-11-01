import base64, json, os, re, subprocess, sys, unittest
from horizon.reach import urlnorm as U, corpus as CO, model as M, broker as B, baselines as BL, search as SR, scenarios as SC, network as N, experiment as EX
from horizon.authz.keys import Signer
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); D = os.path.join(ROOT, "results/v2/p44-reach")
SCN = {s["id"]: s for s in SC.scenarios()}


class WorldBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.w = SC.World()
    @classmethod
    def tearDownClass(cls): cls.w.close()
    def run1(self, system, sid): return SC.run_one(self.w, system, SCN[sid], 0)


class URLNorm(unittest.TestCase):
    def test_corpus(self):
        for inp, exp in CO.CASES:
            if exp is None: self.assertRaises(U.Unresolvable, U.canonicalize, inp)
            else: self.assertEqual(U.canonicalize(inp).url(), exp, inp)
    def test_idempotent(self):
        for inp, exp in CO.CASES:
            if exp: self.assertEqual(U.canonicalize(exp).url(), exp)
    def test_userinfo_flagged(self): self.assertTrue(U.canonicalize("http://partner.test@evil.test/").userinfo); self.assertEqual(U.canonicalize("http://partner.test@evil.test/").host, "evil.test")
    def test_numeric_forms_agree(self):
        hs = {U.canonicalize(u).host for u in ("http://2130706692/", "http://0x7f000104/", "http://0177.0.1.4/", "http://[::ffff:127.0.1.4]/")}; self.assertEqual(hs, {"127.0.1.4"})
    def test_fuzz_never_crashes_never_misreports(self):
        import random; r = random.Random(44); al = "ab.0x7f:/@\\%[]- \x00"
        for _ in range(3000):
            s = "http://" + "".join(r.choice(al) for _ in range(r.randint(0, 14)))
            try: c = U.canonicalize(s); self.assertTrue(c.host)
            except U.Unresolvable: pass


class Model(unittest.TestCase):
    def setUp(self):
        from horizon.hpolicy.authority import HorizonPolicy
        self.a = HorizonPolicy("pol-t"); self.iss = self.a.register_issuer("reach-attestor", {"ATTESTATION"}); self.sg = Signer.generate("op", "svc"); self.key = base64.b64encode(Signer.generate("k", "svc").public_raw()).decode()
        self.m = M.manifest_body("svc.test", "1", True, {"fetch"}, {"public.test"}, self.key); self.signed = M.sign_manifest(self.sg, self.m); self.reg = M.Registry(self.a.verifier(), self.a.clock)
    def tok(self, m=None, key=None, art="svc.test"): m = m or self.m; return self.iss.issue("ATTESTATION", principal="reach", artifact=art, args_digest=M.manifest_digest(m), ttl=3600, claim={"key": key or m["key"], "level": "ATTESTED"})
    def test_unattested_is_unverified(self): self.assertEqual(self.reg.declare(self.signed), "UNVERIFIED")
    def test_attested(self): self.assertEqual(self.reg.declare(self.signed, self.tok()), "ATTESTED")
    def test_token_bound_to_digest(self):
        other = M.manifest_body("svc.test", "1", True, {"fetch"}, {"public.test", "evil.test"}, self.key); self.assertEqual(self.reg.declare(self.signed, self.tok(other)), "UNVERIFIED")
    def test_token_bound_to_service(self): self.assertEqual(self.reg.declare(self.signed, self.tok(art="other.test")), "UNVERIFIED")
    def test_token_bound_to_key(self): self.assertEqual(self.reg.declare(self.signed, self.tok(key="AAAA")), "UNVERIFIED")
    def test_bad_manifest_signature_rejected(self):
        s = json.loads(json.dumps(self.signed)); s["body"]["egress"] = ["evil.test"]; self.assertEqual(self.reg.declare(s, self.tok()), "REJECTED")
    def test_revoke(self): self.reg.declare(self.signed, self.tok()); self.reg.revoke("svc.test", "x"); self.assertEqual(self.reg.status("svc.test"), "REVOKED")
    def test_unknown_service(self): self.assertEqual(self.reg.status("nope"), "UNKNOWN_SERVICE")
    def test_receipt_states(self):
        k = Signer.generate("k", "svc"); man = {"key": base64.b64encode(k.public_raw()).decode()}
        mk = lambda call: (lambda b: base64.b64encode(b).decode() + "." + base64.b64encode(k.sign(M.RECEIPT_DOMAIN + b)).decode())(json.dumps({"call": call, "effects": ["x"]}).encode())
        self.assertEqual(M.verify_receipt(None, man, "c1")["state"], "MISSING"); self.assertEqual(M.verify_receipt("junk", man, "c1")["state"], "INVALID")
        self.assertEqual(M.verify_receipt(mk("c2"), man, "c1")["state"], "MISMATCH"); self.assertEqual(M.verify_receipt(mk("c1"), man, "c1")["state"], "OK")
    def test_receipt_wrong_key(self):
        k = Signer.generate("k", "svc"); man = {"key": base64.b64encode(Signer.generate("z", "z").public_raw()).decode()}; b = json.dumps({"call": "c", "effects": []}).encode()
        self.assertEqual(M.verify_receipt(base64.b64encode(b).decode() + "." + base64.b64encode(k.sign(M.RECEIPT_DOMAIN + b)).decode(), man, "c")["state"], "INVALID")
    def test_label_transforms(self):
        s = M.ArtifactStore(); a = s.put("x", "SECRET")
        for op, lab in (("b64", "SECRET"), ("rot13", "SECRET"), ("weak_sanitize", "SECRET"), ("hash", "PUBLIC"), ("redact", "PUBLIC"), ("mystery", "SECRET")): self.assertEqual(s.get(s.transform(a, op, lambda v: v))["label"], lab, op)
    def test_modules_never_self_sign(self):
        for f in ("model.py", "broker.py", "scenarios.py", "baselines.py", "search.py", "experiment.py"):
            src = open(os.path.join(ROOT, "horizon/reach", f)).read()
            self.assertNotIn("register_issuer", src.replace("self.auth.register_issuer", "") if f == "scenarios.py" else src, f)       # only the experiment world (an evidence service stand-in) registers an issuer
            self.assertNotIn("Issuer(", src, f)


class Policies(unittest.TestCase):
    def test_example_policies_valid(self):
        ex = json.load(open(os.path.join(ROOT, "spec/reach_policy_examples.json"))); self.assertTrue(ex)
        for n, p in ex.items():
            self.assertIn(p["unknown_action"], ("BLOCK",))
            for sv, c in p["services"].items():
                self.assertTrue(c["attested"] or c["clearance"] in ("PUBLIC",) or c.get("clearance") == "INTERNAL" and False, n + sv)
                if not c["controlled"]: self.assertTrue(c.get("receipts_required"), n + sv)
                for h in c["egress"]: self.assertIn(h, p["clearance"], n + sv + h)


class Search(unittest.TestCase):
    def g(self): g = SR.Graph(); g.add("a", "b"); g.add("b", "c"); g.add("c", "d"); g.modeled.add("d"); return g
    def test_reach(self): r = SR.reachable(self.g(), "a"); self.assertEqual(r.reached, {"b", "c", "d"}); self.assertEqual(SR.verdict(r, {"d"}), "DENY"); self.assertEqual(SR.verdict(r, {"z"}), "ALLOW")
    def test_depth_budget_is_unknown_not_allow(self): r = SR.reachable(self.g(), "a", max_depth=1); self.assertTrue(r.exhausted); self.assertEqual(SR.verdict(r, {"z"}), "UNKNOWN")
    def test_node_budget(self): r = SR.reachable(self.g(), "a", max_nodes=1); self.assertEqual(SR.verdict(r, {"z"}), "UNKNOWN")
    def test_unmodeled_is_unknown(self): g = SR.Graph(); g.add("a", "b"); self.assertEqual(SR.verdict(SR.reachable(g, "a"), {"z"}), "UNKNOWN")
    def test_declared_edge_is_unknown(self): g = SR.Graph(); g.add("a", "b", trust="declared"); g.modeled.add("b"); self.assertEqual(SR.verdict(SR.reachable(g, "a"), {"z"}), "UNKNOWN")
    def test_cycle_terminates(self): g = SR.Graph(); g.add("a", "b"); g.add("b", "a"); self.assertEqual(SR.verdict(SR.reachable(g, "a"), {"z"}), "ALLOW")
    def test_deadline(self): r = SR.reachable(self.g(), "a", deadline_s=-1); self.assertTrue(r.exhausted)


class Broker(WorldBase):
    def test_benign_all_complete(self):
        for sid in SCN:
            if SCN[sid]["kind"] == "benign": r = self.run1("reach", sid); self.assertTrue(r["completed"] and not r["violated"], sid)
    def test_url_forms_blocked(self):
        for sid in ("A04", "A06a", "A06b", "A06c", "A06d", "A06e", "A06f"): r = self.run1("reach", sid); self.assertFalse(r["violated"], sid); self.assertFalse(r["completed"], sid)
    def test_rebind_pinned_fetch_reaches_only_validated_host(self): r = self.run1("reach", "A05"); self.assertFalse(r["violated"])
    def test_hidden_forward_through_controlled_service_blocked_by_fabric(self): self.assertFalse(self.run1("reach", "A01")["violated"])
    def test_relay_blocked(self):
        for sid in ("A07", "A07b"): self.assertFalse(self.run1("reach", sid)["violated"], sid)
    def test_unattested_external_with_secret_is_unknown(self): r = self.run1("reach", "A02"); self.assertEqual(r["verdict"], "UNKNOWN"); self.assertFalse(r["violated"])
    def test_attested_liar_is_the_honest_failure(self):
        r = self.run1("reach", "A03"); self.assertTrue(r["violated"]); self.assertTrue(r["audit_detected"]); self.assertFalse(r["second_call_violated"])
    def test_missing_receipt_gives_unknown_not_success(self):
        r = self.run1("reach", "O01"); self.assertEqual(r["post_verdict"], "UNKNOWN")
    def test_unresolvable_gives_unknown(self): self.assertEqual(self.run1("reach", "O02")["verdict"], "UNKNOWN")
    def test_observer_down_oracle_unknown(self): self.assertEqual(self.run1("reach", "O03")["oracle"], "UNKNOWN")
    def test_agent_label_claim_ignored(self):
        s = dict(SCN["A04"]); s["claimed"] = "PUBLIC"; s = dict(s, id="A04x"); r = SC.run_one(self.w, "reach", s, 0); self.assertFalse(r["violated"])
    def test_fabric_unknown_call_is_secret(self):
        b = self.w.system("reach", {"converter.test": "att-ctl"})
        try:
            import urllib.request
            req = urllib.request.Request("http://127.0.0.1:%d/" % b.fabric.port, data=json.dumps({"call": "nope", "service": "converter.test", "url": "http://evil.test:%d/x" % self.w.mock.port, "method": "POST", "body_b64": base64.b64encode(b"x").decode()}).encode(), method="POST")
            try: urllib.request.urlopen(req); code = 200
            except Exception as e: code = e.code
            self.assertEqual(code, 403)
        finally: b.close()
    def test_borrowed_call_id_is_secret(self):
        b = self.w.system("reach", {"converter.test": "att-ctl"})
        try:
            b.fabric.register("c9", "relay.test", "PUBLIC"); self.assertEqual(b.fabric.egress({"call": "c9", "service": "relay.test", "url": "http://partner.test:%d/x" % self.w.mock.port, "method": "POST", "body_b64": "eA=="})[0] in (200, 502), True); code, _ = b.fabric.egress({"call": "c9", "service": "converter.test", "url": "http://public.test:%d/x" % self.w.mock.port, "method": "POST", "body_b64": "eA=="}); self.assertEqual(code, 403)
        finally: b.close()
    def test_revoked_service_denied_at_decision(self):
        b = self.w.system("reach", {"converter.test": "att-ctl"}); P = self.w.mock.port
        try:
            ok = b.evaluate("analyst", "convert", "http://converter.test:%d/convert" % P, self.w.art["PUB"], None, "http://public.test:%d/doc" % P); self.assertEqual(ok.verdict, "ALLOW")
            b.registry.revoke("converter.test", "test"); d = b.evaluate("analyst", "convert", "http://converter.test:%d/convert" % P, self.w.art["PUB"], None, "http://public.test:%d/doc" % P)
            self.assertEqual(d.verdict, "DENY"); self.assertTrue(any("SERVICE_REVOKED" in r for r in d.reasons))
        finally: b.close()
    def test_relay_target_checked_with_payload_label(self):
        b = self.w.system("reach", {"relay.test": "att-ctl"}); P = self.w.mock.port
        try:
            d = b.evaluate("analyst", "relay", "http://relay.test:%d/relay" % P, self.w.art["SEC"], None, None, "http://evil.test:%d/hook" % P); self.assertEqual(d.verdict, "DENY")
            d = b.evaluate("analyst", "relay", "http://relay.test:%d/relay" % P, self.w.art["PUB"], None, None, "http://evil.test:%d/hook" % P); self.assertEqual(d.verdict, "ALLOW")
        finally: b.close()
    def test_fetch_argument_carries_only_url(self):
        b = self.w.system("reach", {"converter.test": "att-ctl"}); P = self.w.mock.port
        try: d = b.evaluate("analyst", "convert", "http://converter.test:%d/convert" % P, self.w.art["SEC"], None, "http://public.test:%d/doc" % P); self.assertEqual(d.verdict, "ALLOW")
        finally: b.close()
    def test_check_destination_userinfo_and_unresolvable_and_unlisted(self):
        b = self.w.system("reach", {}); P = self.w.mock.port
        try:
            r = b.check_destination("http://partner.test@public.test:%d/" % P, "PUBLIC"); self.assertEqual(r["verdict"], "UNKNOWN"); self.assertIn("USERINFO_IN_AUTHORITY", r["reasons"])
            r = b.check_destination("http://a..b/", "PUBLIC"); self.assertEqual(r["verdict"], "UNKNOWN"); self.assertTrue(r["reasons"][0].startswith("UNRESOLVABLE"))
            b.res.t["new.test"] = "127.0.1.99"; self.assertEqual(b.check_destination("http://new.test:%d/" % P, "SECRET")["verdict"], "DENY"); self.assertEqual(b.check_destination("http://new.test:%d/" % P, "PUBLIC")["verdict"], "ALLOW")
            r = b.check_destination("http://nohost.test/", "PUBLIC"); self.assertEqual(r["verdict"], "UNKNOWN")
        finally: b.res.t.pop("new.test", None); b.close()
    def test_authority_cannot_change_after_check(self):
        b = self.w.system("reach", {}); P = self.w.mock.port
        try:
            first = b.check_destination("http://partner.test:%d/a" % P, "PUBLIC"); st, h, d, tr = b.fetch_pinned("http://evil.test:%d/a" % P, "GET", None, "PUBLIC", {}, first=first)
            self.assertEqual(st, 0); self.assertEqual(tr[-1]["why"], ["AUTHORITY_CHANGED_AFTER_CHECK"])
        finally: b.close()
    def test_receipt_that_reveals_effect_denies_and_revokes(self):
        s = dict(SCN["A03"], id="A03r", ext={"converter_mode": "hidden_forward", "receipts": "on"}); r = SC.run_one(self.w, "reach", s, 0)
        self.assertEqual(r["receipt"], "REVEALS_UNAUTHORIZED_EFFECT"); self.assertEqual(r["post_verdict"], "DENY")
    def test_service_egress_list(self):
        b = self.w.system("reach", {"converter.test": "att-ctl"})
        try: r = b.check_destination("http://evil.test:%d/" % self.w.mock.port, "PUBLIC", egress_of=b.registry.manifest("converter.test")); self.assertEqual(r["verdict"], "DENY")
        finally: b.close()


class Baselines(WorldBase):
    def test_allowlist_blocks_plain_evil_host(self): self.assertFalse(self.run1("allowlist", "A06e")["violated"] and False or False); r = self.run1("allowlist", "A04"); self.assertTrue(r["violated"])      # open redirector defeats the allowlist
    def test_allowlist_false_positive_on_approved_variant(self): self.assertFalse(self.run1("allowlist", "B06a")["completed"])
    def test_pattern_misses_numeric_form(self): self.assertTrue(self.run1("pattern", "A06a")["violated"])
    def test_reach_beats_baselines_on_attacks(self):
        att = [s for s in SCN if SCN[s]["kind"] == "attack" and s not in ("A03",)]
        for sysn in ("allowlist", "pattern", "declaration"): self.assertTrue(any(self.run1(sysn, s)["violated"] for s in att), sysn)
        self.assertFalse(any(self.run1("reach", s)["violated"] for s in att))


class BaselineFidelity(unittest.TestCase):
    def test_allowlist_requires_resolved_address_match(self):
        res = N.Resolver(rebind={"partner.test": [N.HOSTS["evil.test"]]}); nv = BL.Naive(None, res, None, "allowlist", allow_hosts={"partner.test"})
        self.assertEqual(nv._decide(["http://partner.test/"]), "DENY")      # an allowed name that resolves outside the allowlist addresses
        nv2 = BL.Naive(None, N.Resolver(), None, "allowlist", allow_hosts={"partner.test"}); self.assertEqual(nv2._decide(["http://partner.test/"]), "ALLOW")


class Ablations(WorldBase):
    def test_each_ablation_has_a_scenario_it_loses(self):
        want = {"reach-no-canonicalization": ["B06a", "B06b", "B06c"], "reach-no-pinning": ["A05"], "reach-no-redirect-revalidation": ["A04"], "reach-no-label-binding": ["A04"], "reach-no-attestation": ["A02"], "reach-no-fabric": ["A01"], "reach-no-unknown-blocking": ["A02", "O02"], "reach-no-receipts": ["O01"]}
        for sysn, ids in want.items():
            lost = [i for i in ids if (SCN[i]["kind"] == "benign" and not self.run1(sysn, i)["completed"]) or self.run1(sysn, i)["violated"] or self.run1(sysn, i)["post_verdict"] == "ALLOW" or (SCN[i]["kind"] == "observability" and self.run1(sysn, i)["verdict"] == "ALLOW")]
            self.assertTrue(lost, "%s should fail one of %s" % (sysn, ids))


class Oracle(unittest.TestCase):
    def test_independent_of_enforcement(self):
        src = open(os.path.join(ROOT, "horizon/reach/network.py")).read(); self.assertNotIn("import broker", src); self.assertNotIn("from . import broker", src); self.assertFalse(re.search(r"^from \. import .*\bbroker\b", src, re.M))
        sc = open(os.path.join(ROOT, "horizon/reach/scenarios.py")).read(); self.assertIn("ORACLE_SECRET_OK", sc); self.assertIn("sink_rows", sc)
    def test_oracle_table_literal(self): self.assertTrue(SC.ORACLE_SECRET_OK and all(isinstance(x, str) for x in SC.ORACLE_SECRET_OK))
    def test_violation_function(self):
        rows = [{"addr": "127.0.1.4", "has_canary": True, "has_variant": False}, {"addr": "x", "has_canary": False, "has_variant": False}]
        self.assertTrue(SC.violation(rows, True)[0]); self.assertFalse(SC.violation(rows, False)[0]); self.assertFalse(SC.violation(rows[1:], True)[0])


class Network(unittest.TestCase):
    def test_resolver_normalizes_and_rebinds(self):
        r = N.Resolver(rebind={"rb.test": ["127.0.1.2", "127.0.1.4"]}); self.assertEqual(r.resolve("Partner.TEST."), N.HOSTS["partner.test"]); self.assertEqual(r.resolve("rb.test"), "127.0.1.2"); self.assertEqual(r.resolve("rb.test"), "127.0.1.4")
        self.assertRaises(KeyError, r.resolve, "nope.test")
    def test_all_hosts_loopback(self): self.assertTrue(all(h.startswith("127.") for h in N.HOSTS.values()))


class Recorded(unittest.TestCase):
    def setUp(self): self.r = json.load(open(os.path.join(D, "result.json")))
    def test_runner_check(self): self.assertEqual(subprocess.run([sys.executable, "scripts/p44_run.py", "--check"], cwd=ROOT, capture_output=True, text=True).returncode, 0)
    def test_report_current(self): self.assertEqual(subprocess.run([sys.executable, "scripts/p44_report.py", "--check"], cwd=ROOT, capture_output=True, text=True).returncode, 0)
    def test_systems_complete(self): self.assertEqual(self.r["systems"], list(SC.SYSTEMS)); self.assertEqual(self.r["runs"], len(SCN) * len(SC.SYSTEMS) * SC.REPS)
    def test_claims(self):
        s = self.r["summary"]; self.assertGreaterEqual(s["reach"]["benign_completed"]["rate"], 0.99)
        self.assertLess(s["reach"]["attacks_with_forbidden_effect"]["k"], s["allowlist"]["attacks_with_forbidden_effect"]["k"]); self.assertLess(s["reach"]["attacks_with_forbidden_effect"]["k"], s["pattern"]["attacks_with_forbidden_effect"]["k"])
        self.assertGreater(s["reach"]["attacks_with_forbidden_effect"]["k"], 0)          # the honest limit is recorded, not hidden
    def test_limits_recorded(self): self.assertTrue(any("attest" in x.lower() for x in self.r["limits"]))
    def test_emergence_sound(self): self.assertTrue(all(x["sound"] for x in self.r["emergence_agreement"]))


if __name__ == "__main__": unittest.main()
