import copy, random, unittest
from horizon.authz import keys as K
from horizon.deleg import authority as A, grants as G, counterexamples as CX

U = "https://api.example.com/v1"
NOW = [1000]


def env(maxd=4):
    rs, ds = K.Signer.generate("r1", "root"), K.Signer.generate("d1", "delegator"); tr = K.TrustStore(clock=lambda: NOW[0])
    tr.add("r1", "root", rs.public_raw(), not_before=0, not_after=2 ** 40); tr.add("d1", "delegator", ds.public_raw(), not_before=0, not_after=2 ** 40)
    v = G.Verifier(tr, audience="gw", clock=lambda: NOW[0], max_depth=maxd); au = G.AuditSchema(); return rs, ds, tr, v, G.Delegator(ds, v, au), au


def root(rs, sub="a", tenant="T", aud="gw", auth=None, **k):
    return G.issue_root(rs, tenant=tenant, sub=sub, aud=aud, auth=auth or A.Authority.make({"read", "send"}, resources=[U], arg_max={"text": 100}, exp=5000), now=0, **k)


def chk(v, envs, leaf, **kw):
    d = dict(principal="b", tenant="T", action="read", tool="t", resource=U + "/notes"); d.update(kw); return v.authorize(envs, leaf["grant"]["id"], **d)


class Algebra(unittest.TestCase):
    def test_subset_basics(self):
        p = A.Authority.make({"read", "send"}, resources=[U], arg_max={"text": 10}); mk = lambda **k: A.Authority.make(**{"actions": {"read"}, "resources": [U + "/x"], "arg_max": {"text": 5}, **k})
        self.assertTrue(A.subset(mk(), p)); self.assertFalse(A.subset(mk(actions={"delete"}), p)); self.assertFalse(A.subset(mk(resources=None), p))
        self.assertFalse(A.subset(mk(resources=[U + "0/x"]), p)); self.assertFalse(A.subset(mk(arg_max={"text": 11}), p)); self.assertFalse(A.subset(mk(arg_max={}), p))
        self.assertFalse(A.subset(mk(exp=2 ** 31 + 1), A.Authority.make({"read"}, exp=2 ** 31))); self.assertFalse(A.subset(mk(tools=None), A.Authority.make({"read"}, tools=["t"], resources=[U], arg_max={"text": 9})))
        self.assertFalse(A.subset(mk(dests=["h"]), A.Authority.make({"read"}, resources=[U], dests=[], arg_max={"text": 9})))
    def test_admin_not_delegable(self):
        with self.assertRaises(A.AuthorityError): A.Authority.make({"admin"})
    def test_intersection_is_lower_bound(self):
        r = random.Random(1)
        def rnd():
            return A.Authority.make(r.sample(sorted(A.EFFECTS), r.randint(1, 4)), r.choice([None, ["t1"], ["t1", "t2"]]), r.choice([None, [U], [U + "/a"], [U + "/b"], [U + "/a", U + "/b"]]), None, {"text": r.randint(1, 50)} if r.random() < .6 else {}, r.randint(0, 10), r.randint(20, 90))
        for _ in range(400):
            a, b = rnd(), rnd(); i = A.intersect(a, b)
            self.assertTrue(A.subset(i, a) and A.subset(i, b))
    def test_permits_reasons(self):
        a = A.Authority.make({"send"}, ["t"], [U], ["h"], {"text": 3}, 0, 10); ok = dict(action="send", tool="t", resource=U + "/n", dest="h", args={"text": "abc"}, now=5)
        self.assertIsNone(A.permits(a, **ok))
        for k, v, code in (("action", "read", "ACTION"), ("tool", "u", "TOOL"), ("resource", "https://x/", "RESOURCE"), ("dest", None, "DEST"), ("args", {"text": "abcd"}, "ARG_RANGE"), ("now", 10, "OUT_OF_WINDOW"), ("args", {"text": ["x"]}, "ARG_RANGE")):
            self.assertEqual(A.permits(a, **dict(ok, **{k: v})), code)
        self.assertEqual(A.permits(A.Authority.make(set()), **ok), "EMPTY_AUTHORITY")


class Chains(unittest.TestCase):
    def setUp(self): NOW[0] = 1000; self.rs, self.ds, self.tr, self.v, self.d, self.au = env(); self.root = root(self.rs)
    def child(self, parent=None, **k):
        parent = parent or self.root; kw = dict(requester=parent["grant"]["sub"], child_sub="b", auth=A.Authority.make({"read"}, resources=[U + "/notes"], arg_max={"text": 10}, exp=4000)); kw.update(k)
        return self.d.delegate([self.root] + ([parent] if parent is not self.root else []), [parent["grant"]["id"]], **kw)
    def test_valid_chain_and_scope(self):
        c = self.child(); self.assertTrue(chk(self.v, [self.root, c], c)["allow"])
        for kw, code in (({"action": "send"}, "ACTION"), ({"resource": U + "/alerts"}, "RESOURCE"), ({"principal": "x"}, "SUBJECT_MISMATCH"), ({"tenant": "T2"}, "TENANT_MISMATCH")):
            r = chk(self.v, [self.root, c], c, **kw); self.assertEqual((r["allow"], r["code"]), (False, code), kw)
    def test_amplification_refused_at_issue_and_at_verify(self):
        for au in (A.Authority.make({"delete"}), A.Authority.make({"read"}, resources=["https://other/"]), A.Authority.make({"read"}, resources=None), A.Authority.make({"read"}, resources=[U], arg_max={"text": 101}, exp=5000), A.Authority.make({"read"}, resources=[U], arg_max={"text": 5}, exp=6000)):
            with self.assertRaises(G.GrantError) as cm: self.child(auth=au)
            self.assertEqual(cm.exception.code, "AMPLIFICATION")
        forged = G.seal(self.ds, dict(self.child()["grant"], auth=A.Authority.make({"read", "delete"}, resources=[U], arg_max={"text": 1}, exp=4000).to_json(), id="g-forged"))     # delegator key compromised / bug
        r = chk(self.v, [self.root, forged], forged); self.assertEqual(r["code"], "AMPLIFICATION")
    def test_tamper_and_wrong_signer(self):
        c = self.child(); t = copy.deepcopy(c); t["grant"]["auth"]["actions"] = ["read", "send"]; self.assertEqual(chk(self.v, [self.root, t], t)["code"], "BAD_SIGNATURE")
        g = dict(c["grant"], iss=G.ROOT_ISSUER); bad = G.seal(self.ds, g); self.assertIn(chk(self.v, [self.root, bad], bad)["code"], ("UNTRUSTED_KEY", "WRONG_ISSUER"))
        rr = G.seal(self.ds, dict(self.root["grant"], iss="delegator", id="g-fakeroot")); self.assertEqual(chk(self.v, [rr], rr, principal="a")["code"], "WRONG_ISSUER")     # delegator cannot mint roots
    def test_untrusted_origin_cannot_grant(self):
        for o in ("tool-output", "model-text", "untrusted", "agent-runtime", ""):
            with self.assertRaises(G.GrantError) as cm: root(self.rs, origin=o)
            self.assertEqual(cm.exception.code, "UNTRUSTED_ORIGIN")
        for o in ("tool-output", "model-text", "untrusted"):
            with self.assertRaises(G.GrantError) as cm: self.child(origin=o)
            self.assertEqual(cm.exception.code, "UNTRUSTED_ORIGIN")
    def test_only_holder_may_delegate(self):
        with self.assertRaises(G.GrantError) as cm: self.child(requester="mallory")
        self.assertEqual(cm.exception.code, "REQUESTER_NOT_HOLDER")
    def test_depth_exhaustion(self):
        rs, ds, tr, v, d, au = env(maxd=2); r0 = root(rs, sub="s0"); envs = [r0]; cur = r0
        for i in range(2):
            cur = d.delegate(envs, [cur["grant"]["id"]], requester=cur["grant"]["sub"], child_sub=f"s{i + 1}", auth=A.Authority.make({"read"}, resources=[U], arg_max={"text": 100}, exp=4000)); envs.append(cur)
        with self.assertRaises(G.GrantError) as cm: d.delegate(envs, [cur["grant"]["id"]], requester="s2", child_sub="s3", auth=A.Authority.make({"read"}, resources=[U], arg_max={"text": 100}, exp=4000))
        self.assertEqual(cm.exception.code, "DEPTH_EXCEEDED")
    def test_cycle_and_missing_parent_and_duplicate(self):
        a = G.seal(self.ds, {**self.child()["grant"], "id": "g-a", "parents": ["g-b"], "depth": 1}); b = G.seal(self.ds, {**self.child()["grant"], "id": "g-b", "parents": ["g-a"], "depth": 1})
        self.assertEqual(chk(self.v, [a, b], a)["code"], "CYCLE"); self.assertEqual(chk(self.v, [a], a)["code"], "MISSING_PARENT")
        c = self.child(); self.assertEqual(chk(self.v, [self.root, c, c], c)["code"], "DUPLICATE_ID")
    def test_expiry_monotone_and_effect_time(self):
        c = self.child(); NOW[0] = 1000; self.assertTrue(chk(self.v, [self.root, c], c)["allow"]); NOW[0] = 4000
        try: self.assertEqual(chk(self.v, [self.root, c], c)["code"], "EXPIRED_OR_NOT_YET")
        finally: NOW[0] = 1000
    def test_revocation_invalidates_descendants_and_cache(self):
        c = self.child(); self.assertTrue(chk(self.v, [self.root, c], c)["allow"]); self.v.rev.revoke(self.root["grant"]["id"])
        self.assertEqual(chk(self.v, [self.root, c], c)["code"], "REVOKED")                  # cache must not serve the pre-revocation answer
    def test_cross_tenant(self):
        other = root(self.rs, sub="a", tenant="T2"); c = self.child(); self.assertEqual(chk(self.v, [other, c], c)["allow"], False)
        x = G.seal(self.ds, dict(c["grant"], tenant="T2", id="g-x")); self.assertEqual(chk(self.v, [self.root, x], x, tenant="T2")["allow"], False)
    def test_confused_deputy_recipient(self):
        c = self.child(); self.assertEqual(chk(self.v, [self.root, c], c, principal="a")["code"], "SUBJECT_MISMATCH")      # the parent cannot use child's grant, nor vice versa
    def test_audience_binding(self):
        other = root(self.rs, aud="other-gw"); self.assertEqual(chk(self.v, [other], other, principal="a")["code"], "AUDIENCE_MISMATCH")
    def test_multi_parent_is_intersection(self):
        r1 = root(self.rs, auth=A.Authority.make({"read"}, resources=[U], exp=5000)); r2 = root(self.rs, auth=A.Authority.make({"send"}, resources=[U], exp=5000)); envs = [r1, r2]
        with self.assertRaises(G.GrantError) as cm: self.d.delegate(envs, [r1["grant"]["id"], r2["grant"]["id"]], requester="a", child_sub="b", auth=A.Authority.make({"read", "send"}, resources=[U], exp=4000))
        self.assertEqual(cm.exception.code, "AMPLIFICATION")
    def test_multi_parent_child_must_fit_every_parent(self):
        r1 = root(self.rs, auth=A.Authority.make({"read"}, resources=[U], exp=5000)); r2 = root(self.rs, auth=A.Authority.make({"send"}, resources=[U], exp=5000))
        f = G.seal(self.ds, {"v": 1, "id": "g-m", "iss": "delegator", "tenant": "T", "sub": "b", "aud": "gw", "parents": sorted([r1["grant"]["id"], r2["grant"]["id"]]), "depth": 1, "auth": A.Authority.make({"read"}, resources=[U], exp=4000).to_json(), "iat": 0, "reason": "x"})
        self.assertEqual(chk(self.v, [r1, r2, f], f)["code"], "AMPLIFICATION")
    def test_verifier_enforces_depth_independently(self):
        rs, ds, tr, v, d, au = env(maxd=1); r0 = root(rs); mk = lambda i, par, dep: G.seal(ds, {"v": 1, "id": i, "iss": "delegator", "tenant": "T", "sub": "b", "aud": "gw", "parents": par, "depth": dep, "auth": A.Authority.make({"read"}, resources=[U], arg_max={"text": 1}, exp=4000).to_json(), "iat": 0, "reason": "x"})
        c1 = mk("g-1", [r0["grant"]["id"]], 1); c2 = mk("g-2", ["g-1"], 2); self.assertTrue(chk(v, [r0, c1], c1)["allow"]); self.assertEqual(chk(v, [r0, c1, c2], c2)["code"], "DEPTH_EXCEEDED")
        lie = mk("g-3", ["g-1"], 1); self.assertEqual(chk(v, [r0, c1, lie], lie)["code"], "BAD_DEPTH")        # claiming a lower depth to dodge the limit
    def test_audit_separates_attribution_from_authorization(self):
        self.child(); self.assertEqual(self.au.rows[0]["authorization"]["parents"], [self.root["grant"]["id"]])
        with self.assertRaises(G.GrantError): self.au.record(kind="effect", authorization=None, attribution=["run-1"])
        with self.assertRaises(G.GrantError): self.au.record(kind="effect", authorization={}, attribution=["run-1"])
    def test_human_reviewed_enlargement(self):
        c = self.child(); big = A.Authority.make({"read", "send"}, resources=[U + "/alerts"], arg_max={"text": 100}, exp=4000)
        with self.assertRaises(G.GrantError): self.d.delegate([self.root, c], [c["grant"]["id"]], requester="b", child_sub="c", auth=big)
        e = root(self.rs, sub="b", auth=big, reason="human-reviewed enlargement ticket-1"); self.assertTrue(chk(self.v, [e], e, resource=U + "/alerts")["allow"])
        self.assertEqual(e["grant"]["reason"], "human-reviewed enlargement ticket-1")


class Counterexamples(unittest.TestCase):
    def test_union_bug_shows_escalation_that_correct_verifier_blocks(self):
        rs, ds, tr, v, d, au = env(); r1 = root(rs, auth=A.Authority.make({"read"}, resources=[U], exp=5000)); r2 = root(rs, auth=A.Authority.make({"send"}, resources=[U], exp=5000))
        big = A.Authority.make({"read", "send"}, resources=[U], exp=4000); forged = G.seal(ds, {"v": 1, "id": "g-u", "iss": "delegator", "tenant": "T", "sub": "b", "aud": "gw", "parents": sorted([r1["grant"]["id"], r2["grant"]["id"]]), "depth": 1, "auth": big.to_json(), "iat": 0, "reason": "x"})
        bad = CX.UnionVerifier(tr, audience="gw", clock=lambda: NOW[0]); a = bad.authorize([r1, r2, forged], "g-u", principal="b", tenant="T", action="send", tool="t", resource=U + "/n")
        self.assertFalse(v.authorize([r1, r2, forged], "g-u", principal="b", tenant="T", action="send", tool="t", resource=U + "/n")["allow"]); self.assertTrue(a["allow"])      # counterexample trace exists
    def test_missing_audience_bug(self):
        rs, ds, tr, v, d, au = env(); other = root(rs, aud="other-gw"); bad = CX.NoAudienceVerifier(tr, audience="gw", clock=lambda: NOW[0])
        self.assertTrue(bad.authorize([other], other["grant"]["id"], principal="a", tenant="T", action="read", tool="t", resource=U + "/n")["allow"])
        self.assertFalse(v.authorize([other], other["grant"]["id"], principal="a", tenant="T", action="read", tool="t", resource=U + "/n")["allow"])


class Property(unittest.TestCase):
    def test_conditional_attenuation_random_chains(self):
        """Theorem (conditional on sound signatures, trusted root issuer and a non-compromised delegator): every verified grant's authority ⊆ its root's; random non-subset children never verify."""
        rs, ds, tr, v, d, au = env(maxd=6); r = random.Random(7); ok = rej = 0
        for trial in range(60):
            rt = root(rs, sub="s0", auth=A.Authority.make(r.sample(sorted(A.EFFECTS), 4), None, [U + "/a", U + "/b"], None, {"text": 50}, 0, 4500)); envs, cur = [rt], rt
            for depth in range(5):
                want = A.Authority.make(r.sample(sorted(A.EFFECTS), r.randint(1, 5)), None, r.choice([[U + "/a"], [U + "/a/x"], [U + "/c"], [U + "/b", U + "/a"]]), None, {"text": r.randint(1, 80)}, 0, r.randint(1000, 5000))
                parent_auth = A.Authority.from_json(cur["grant"]["auth"])
                try: ch = d.delegate(envs, [cur["grant"]["id"]], requester=cur["grant"]["sub"], child_sub=f"s{depth + 1}", auth=want)
                except G.GrantError as e:
                    self.assertEqual(e.code, "AMPLIFICATION"); self.assertFalse(A.subset(want, A.intersect(parent_auth, parent_auth))); rej += 1; continue
                ok += 1; envs.append(ch); eff = v.effective(envs, ch["grant"]["id"], tenant="T"); self.assertTrue(A.subset(eff, A.Authority.from_json(rt["grant"]["auth"]))); cur = ch
        self.assertGreater(ok, 15); self.assertGreater(rej, 15)


if __name__ == "__main__": unittest.main()
