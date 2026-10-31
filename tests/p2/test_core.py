import itertools, random, sys, time, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from horizon.core import scope as sc, closure as cl, labels as lb, decide as dc, tokens as tk, runstate as rs

R = random.Random(20261031)
ATOMS = [f"cap({c})" for c in "abcdefgh"]


def rand_rules(n=8):
    out = []
    for i in range(n):
        prem = R.sample(ATOMS, R.randint(1, 3)); head = R.choice(ATOMS)
        out.append({"id": f"r{i:02d}", "premises": prem, "head": head, "code": "CODE_X"})
    return out


class Closure(unittest.TestCase):
    def test_monotone_idempotent_order_invariant(self):
        for _ in range(300):
            rules = rand_rules(); s2 = R.sample(ATOMS, R.randint(0, 6)); s1 = [a for a in s2 if R.random() < .5]
            c1, c2 = cl.closure(s1, rules), cl.closure(s2, rules)
            self.assertLessEqual(set(c1["atoms"]), set(c2["atoms"]))                        # monotone
            self.assertEqual(cl.closure(c2["atoms"], rules)["atoms"], c2["atoms"])          # idempotent
            sh, rr = s2[:], rules[:]; R.shuffle(sh); R.shuffle(rr)
            self.assertEqual(cl.closure(sh, rr), c2)                                        # deterministic regardless of input order
            for a, w in c2["witnesses"].items():
                self.assertTrue(set(w["premises"]) <= set(c2["atoms"]) and a not in s2)     # witnesses are real derivations
            self.assertTrue(set(s2) <= set(c2["atoms"]))                                    # extensive

    def test_budgets_and_shape(self):
        bad = [[{"id": "a", "premises": [], "head": "x(y)", "code": "AA"}],
               [{"id": "a", "premises": ["p(1)"] * 1 + ["q(1)", "r(1)", "s(1)", "t(1)"], "head": "x(y)", "code": "AA"}],
               [{"id": "a", "premises": ["p(1)"], "head": "x(y)", "code": "bad"}],
               [{"id": "a", "premises": ["p(1)"], "head": "x(y)", "code": "AA", "eval": "1"}],
               [{"id": "a", "premises": ["p(1)"], "head": "x(y)", "code": "AA"}] * 2,
               [{"id": f"r{i}", "premises": ["p(1)"], "head": "x(y)", "code": "AA"} for i in range(1001)]]
        for rules in bad:
            with self.assertRaises(cl.BudgetError): cl.closure([], rules)
        with self.assertRaises(cl.BudgetError): cl.closure(["not an atom"], [])


class Scope(unittest.TestCase):
    P = ["/a/*", "/a/**", "/a/b", "/a/*/c", "**", "*", "/a/?", "/b/**", "/a/b/*", "/a/b/**", "a*", "/**/c"]
    TXT = ["", "/a", "/a/", "/a/b", "/a/b/c", "/a/x/c", "/b/c", "/a/b/c/d", "abc", "a/b", "/a/b/", "/c"]

    def test_subsumption_sound(self):
        scopes = [{"kind": "glob", "value": p} for p in self.P] + [{"kind": "literal", "value": t} for t in self.TXT if t] + \
                 [{"kind": "tenant", "value": "t1"}, {"kind": "any"}, {"kind": "literal", "value": "t1/x"}, {"kind": "glob", "value": "t1/*"}]
        texts = self.TXT + ["t1", "t1/x", "t1/y/z", "t10/x"]
        for a, b in itertools.product(scopes, scopes):
            if sc.subsumes(a, b):
                for t in texts:
                    if sc.matches(b, t): self.assertTrue(sc.matches(a, t), (a, b, t))
        for a in scopes: self.assertTrue(sc.subsumes(a, a))
        for b in scopes: self.assertTrue(sc.subsumes({"kind": "any"}, b))

    def test_tenant_prefix_not_confusable(self):
        self.assertFalse(sc.matches({"kind": "tenant", "value": "t1"}, "t10/x"))
        self.assertFalse(sc.subsumes({"kind": "tenant", "value": "t1"}, {"kind": "literal", "value": "t10/x"}))

    def test_glob_semantics(self):
        m = sc.glob_match
        self.assertTrue(m("/a/*", "/a/b")); self.assertFalse(m("/a/*", "/a/b/c")); self.assertTrue(m("/a/**", "/a/b/c"))
        self.assertTrue(m("/a/?", "/a/b")); self.assertFalse(m("/a/?", "/a/")); self.assertFalse(m("/a/?", "/a//"))

    def test_unsafe_scopes_rejected_not_evaluated(self):
        for g in ("(a+)+$", "[a-z]*", "a{1,99}", "\\d", "a|b", "***", "*" * 9, "a" * 300, "x\x00"):
            with self.assertRaises(sc.ScopeError, msg=g): sc.glob_match(g, "a")
        for s in ({"kind": "regex", "value": "."}, {"kind": "any", "value": "x"}, {"kind": "glob"}, {"kind": "tenant", "value": "a/b"}):
            with self.assertRaises(sc.ScopeError): sc.validate_scope(s)

    def test_no_pathological_blowup(self):
        t0 = time.time(); sc.glob_match("*a*a*a*a*a*a*a*b", "a" * 4000); self.assertLess(time.time() - t0, 3)


class Labels(unittest.TestCase):
    def test_join_properties(self):
        for _ in range(200):
            xs = [R.choice(lb.CONF) for _ in range(R.randint(0, 5))]; ys = [R.choice(lb.CONF) for _ in range(R.randint(0, 5))]
            self.assertEqual(lb.join_conf(xs + ys), lb.join_conf([lb.join_conf(xs), lb.join_conf(ys)]))
            self.assertEqual(lb.join_conf(xs + ys), lb.join_conf(ys + xs))
            o = lb.output_label(xs, [R.choice(lb.TRUST) for _ in xs])
            self.assertTrue(all(lb.C[x] <= lb.C[o["confidentiality"]] for x in xs))              # non-downgrade

    def test_declassification_only_via_signed_path(self):
        art = {"id": "a1", "confidentiality": "SECRET"}; keys = {"decl1": b"k"}; used = set()
        req = {"artifact_id": "a1", "from": "SECRET", "to": "PUBLIC", "nonce": "n1", "declassifier": "decl1", "reason": "approved release"}
        sig = lb.sign_declassification(b"k", req)
        with self.assertRaises(PermissionError): lb.declassify(art, "PUBLIC", req, "0" * 64, keys, used)
        with self.assertRaises(PermissionError): lb.declassify(art, "PUBLIC", dict(req, to="INTERNAL"), sig, keys, used)
        with self.assertRaises(PermissionError): lb.declassify(art, "PUBLIC", dict(req, reason=""), sig, keys, used)
        out = lb.declassify(art, "PUBLIC", req, sig, keys, used); self.assertEqual(out["confidentiality"], "PUBLIC"); self.assertEqual(art["confidentiality"], "SECRET")
        with self.assertRaises(PermissionError): lb.declassify(art, "PUBLIC", req, sig, keys, used)   # replay
        up = {"id": "a1", "confidentiality": "PUBLIC"}
        r2 = {"artifact_id": "a1", "from": "PUBLIC", "to": "SECRET", "nonce": "n2", "declassifier": "decl1", "reason": "x"}
        with self.assertRaises(PermissionError): lb.declassify(up, "SECRET", r2, lb.sign_declassification(b"k", r2), keys, used)


POL = {"rules": [
    {"id": "deny-secret-egress", "when": {"effect": "send", "sink_zone": "external", "input_label_at_least": "SECRET", "authorized_flow": False}, "decision": "DENY"},
    {"id": "review-incomplete", "when": {"effect": "send", "sink_zone": "external", "lineage_complete": False}, "decision": "REVIEW"},
    {"id": "allow-public", "when": {"effect": "send", "sink_zone": "registry", "maximum_input_label": "PUBLIC", "purpose": "approved_release"}, "decision": "ALLOW"},
], "defaults": {"protected_effect": "DENY", "inspection_only": "QUARANTINE", "evaluation_timeout": "DENY"}}


def rand_ctx():
    return {"identity_valid": R.random() > .1, "mapping_complete": R.random() > .2, "interceptable": R.random() > .1,
            "protected_effect": R.random() > .3, "effect": R.choice(["send", "read", "write"]), "sink_zone": R.choice(["external", "registry", None]),
            "purpose": R.choice(["approved_release", "other", None]), "input_label": R.choice(lb.CONF), "lineage_complete": R.random() > .3,
            "authorized_flow": R.random() > .5, "approval": R.choice([None, {"valid": True}, {"valid": False}])}


class Decide(unittest.TestCase):
    def test_precedence_invariants(self):
        for _ in range(3000):
            c = rand_ctx(); d = dc.decide(POL, c); v = d["verdict"]
            if not c["identity_valid"] or not c["interceptable"]: self.assertEqual(v, "DENY")
            if not c["mapping_complete"]: self.assertNotEqual(v, "ALLOW")
            if c["identity_valid"] and c["interceptable"] and dc.rule_matches(POL["rules"][0]["when"], c): self.assertEqual(v, "DENY")   # hard deny beats approval/allow
            if v == "ALLOW": self.assertTrue(c["mapping_complete"] and c["identity_valid"] and c["interceptable"])
            if c["protected_effect"] and v == "ALLOW": self.assertEqual(d["rule"], "allow-public")
            self.assertEqual(d, dc.decide(POL, c))                                                   # pure / deterministic

    def test_adding_deny_rule_is_deny_monotone(self):
        extra = {"id": "zz", "when": {"effect": "read"}, "decision": "DENY"}
        for _ in range(1000):
            c = rand_ctx()
            if dc.decide(POL, c)["verdict"] == "DENY": self.assertEqual(dc.decide({**POL, "rules": POL["rules"] + [extra]}, c)["verdict"], "DENY")

    def test_unknown_never_clean_and_defaults(self):
        c = dict(rand_ctx(), identity_valid=True, interceptable=True, mapping_complete=False, protected_effect=False)
        self.assertEqual(dc.decide(POL, c)["verdict"], "UNKNOWN")
        c["protected_effect"] = True; self.assertEqual(dc.decide(POL, c)["verdict"], "DENY")
        c = dict(c, mapping_complete=True, protected_effect=False, effect="read", sink_zone=None, purpose=None)
        self.assertEqual(dc.decide(POL, c)["verdict"], "QUARANTINE")

    def test_incomplete_lineage_and_approval_cannot_override_hard_deny(self):
        base = {"identity_valid": True, "mapping_complete": True, "interceptable": True, "protected_effect": True, "effect": "send",
                "sink_zone": "external", "purpose": None, "input_label": "SECRET", "lineage_complete": False, "authorized_flow": False, "approval": {"valid": True}}
        self.assertEqual(dc.decide(POL, base)["verdict"], "DENY")
        ok = dict(base, input_label="INTERNAL", approval=None); self.assertEqual(dc.decide(POL, ok)["verdict"], "REVIEW")
        ok["approval"] = {"valid": True}; self.assertEqual(dc.decide(POL, ok)["verdict"], "DENY")   # approved review still needs an explicit ALLOW


class Tokens(unittest.TestCase):
    REQ = {"principal_id": "user:a", "target_digest": "sha256:" + "1" * 64, "args_digest": "sha256:" + "2" * 64, "policy_digest": "policy-sha256:x", "logical_operation": "http.send"}

    def test_binding_expiry_replay_idempotency(self):
        k = b"key"; t = tk.mint(k, self.REQ, 1000.0, ttl=60); r = tk.Redeemer(k)
        for field, val in (("args_digest", "sha256:" + "9" * 64), ("target_digest", "sha256:" + "9" * 64), ("principal_id", "user:b"), ("policy_digest", "policy-sha256:y"), ("logical_operation", "file.write")):
            self.assertEqual(r.redeem(t, dict(self.REQ, **{field: val}), 1001.0), (False, "BINDING_MISMATCH"))
        self.assertEqual(r.redeem(dict(t, expires_at=9e9), self.REQ, 1001.0), (False, "BAD_MAC"))
        self.assertEqual(r.redeem(t, self.REQ, 1061.0), (False, "EXPIRED"))
        self.assertEqual(r.redeem(t, self.REQ, 1001.0, "idem1"), (True, "OK"))
        self.assertEqual(r.redeem(t, self.REQ, 1002.0, "idem1"), (True, "IDEMPOTENT_REPLAY_SAME"))
        self.assertEqual(r.redeem(t, self.REQ, 1002.0), (False, "REPLAYED_NONCE"))
        t2 = tk.mint(k, self.REQ, 1000.0); self.assertEqual(r.redeem(t2, self.REQ, 1001.0, "idem1"), (False, "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_TOKEN"))
        self.assertLessEqual(tk.mint(k, self.REQ, 0.0, ttl=10 ** 6)["expires_at"], 300.0)           # ttl capped

    def test_policy_digest_changes(self):
        self.assertNotEqual(tk.policy_digest(POL), tk.policy_digest({**POL, "rules": POL["rules"][:2]}))
        self.assertEqual(tk.policy_digest(POL), tk.policy_digest(dict(reversed(list(POL.items())))))


class RunState(unittest.TestCase):
    def test_replay_deterministic_and_eviction_flagged(self):
        rules = [{"id": "r1", "premises": ["cap(a)", "cap(b)"], "head": "cap(c)", "code": "HEAD_C"}]
        ev = [{"monotonic_seq": i, "atoms": [f"cap({x})"]} for i, x in enumerate("abdefgh")]
        a, b = rs.replay(rules, ev), rs.replay(rules, ev); self.assertEqual(a, b); self.assertIn("cap(c)", a["atoms"]); self.assertTrue(a["evidence_complete"])
        small = rs.replay(rules, ev, max_atoms=3)
        self.assertFalse(small["evidence_complete"]); self.assertGreater(small["evicted_count"], 0); self.assertNotIn("cap(c)", small["atoms"])
        with self.assertRaises(ValueError): rs.replay(rules, [ev[1], ev[0]])


class Authz(unittest.TestCase):
    G = [{"principal_id": "user:a", "tenant": "t1", "action": "read", "resource_class": "docs", "scope": {"kind": "glob", "value": "t1/docs/*"},
          "constraints": {"purpose": "research"}},
         {"principal_id": "user:a", "tenant": "t1", "action": "send", "resource_class": "net", "scope": {"kind": "any"}, "constraints": {"allowed_destinations": ["https://ok.example/"]}}]

    def test_authz(self):
        f = rs.authorized
        self.assertTrue(f(self.G, "user:a", "t1", "read", "docs", "t1/docs/x", purpose="research"))
        self.assertFalse(f(self.G, "user:a", "t1", "read", "docs", "t1/docs/x", purpose="marketing"))      # purpose-scoped
        self.assertFalse(f(self.G, "user:a", "t2", "read", "docs", "t1/docs/x", purpose="research"))      # tenant-bound
        self.assertFalse(f(self.G, "user:b", "t1", "read", "docs", "t1/docs/x", purpose="research"))      # unknown principal
        self.assertFalse(f(self.G, "user:a", "t1", "read", "docs", "t1/docs/x/y", purpose="research"))    # glob '*' stops at '/'
        self.assertTrue(f(self.G, "user:a", "t1", "send", "net", "x", destination="https://ok.example/"))
        self.assertFalse(f(self.G, "user:a", "t1", "send", "net", "x", destination="https://evil.example/"))   # destination-specific

    def test_epistemic_and_hitting_set(self):
        a = [{"untrusted_ancestor": True, "verified_for": ["report"]}]
        self.assertFalse(rs.epistemic_risk(True, a, "report")); self.assertTrue(rs.epistemic_risk(True, a, "payment")); self.assertFalse(rs.epistemic_risk(False, a, "payment"))
        for _ in range(100):
            ws = [set(R.sample(range(8), R.randint(1, 3))) for _ in range(R.randint(1, 6))]
            hs, exact = rs.min_hitting_set(ws); self.assertTrue(exact and all(hs & w for w in ws))
            self.assertTrue(all(len(hs) <= len(h2) for h2 in [set(c) for k in range(len(hs)) for c in itertools.combinations(range(8), k) if all(set(c) & w for w in ws)]) )
        big = [{i, i + 1} for i in range(0, 60, 2)]; hs, exact = rs.min_hitting_set(big); self.assertFalse(exact); self.assertTrue(all(hs & w for w in big))


from horizon.core import hierarchy as hi


class Hierarchy(unittest.TestCase):
    def test_dag_validation(self):
        ok = {"root": [], "docs": ["root"], "secrets": ["root"], "api_key": ["secrets"]}
        self.assertEqual(hi.validate_hierarchy(ok)[0], "root"); self.assertEqual(hi.ancestors(ok, "api_key"), {"secrets", "root"})
        for bad, frag in (({"a": ["b"], "b": ["a"]}, "cycle"), ({"a": ["a"]}, "self-parent"), ({"a": ["zz"]}, "unknown parent"),
                          ({"r": [], "a": ["r"], "b": ["r"], "c": ["a", "b"]}, "ambiguous"), ({"r": [], "a": ["r", "r"]}, "duplicate")):
            with self.assertRaises(hi.HierarchyError, msg=frag) as cm: hi.validate_hierarchy(bad)
            self.assertIn(frag, str(cm.exception))
        self.assertEqual(len(hi.validate_hierarchy({"r": [], "a": ["r"], "b": ["r"], "c": ["a", "b"]}, frozenset({"c"}))), 4)

    def test_certification_is_sound_overapproximation(self):
        for _ in range(200):
            rules = rand_rules(); tools = {f"t{i}": R.sample(ATOMS, R.randint(0, 3)) for i in range(5)}
            cert = hi.certify(tools, rules, ["cap(a)", "cap(b)"]); full = set(cl.closure(sorted({a for v in tools.values() for a in v}), rules)["atoms"])
            for _ in range(5):                                                   # any runtime subset's closure stays inside the certified closure
                sub = [a for v in R.sample(list(tools.values()), R.randint(0, 5)) for a in v]
                self.assertLessEqual(set(cl.closure(sub, rules)["atoms"]), full)
            self.assertEqual(cert["status"] == "NOT_CERTIFIED", bool({"cap(a)", "cap(b)"} & full))
        self.assertIn("authored horizon complete for scope", cert["assumptions"])


if __name__ == "__main__":
    unittest.main()
