import dataclasses, sys, os, time, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from horizon import normalize as N
from horizon.authz import effect as E
from horizon.authz.keys import Signer, TrustStore
from horizon.authz.gateway import Verifier, NonceStore, ProofError
from horizon.effects.canonical import CanonicalEffect, commit_verify
NOW = 1_800_000_000
class T(unittest.TestCase):
    def setUp(self):
        self.s = Signer.generate("k1", "iss"); self.ts = TrustStore(clock=lambda: NOW); self.ts.add("k1", "iss", self.s.public_raw(), not_before=0, not_after=NOW * 2)
        self.pol = ["p1"]; self.v = Verifier(self.ts, NonceStore(clock=lambda: NOW), issuer="iss", audience="gw", contract_version="c1", policy_version=lambda: self.pol[0], clock=lambda: NOW)
        self.ce = CanonicalEffect("t1", "srv1", "sess1", "agent-a", "send", "url", "https://example.test/x", {"a": 1})
    def tok(self, ce=None, **o):
        ce = ce or self.ce; e = dict(v=1, iss="iss", sub=ce.principal, tenant=ce.tenant, effect=ce.effect, target=N.canonical_target(ce.target_kind, ce.target_raw), args_digest=ce.bound_args_digest(),
                                  contract_version="c1", policy_version="p1", aud="gw", iat=NOW - 1, exp=NOW + 30, nonce=os.urandom(8).hex(), decision_id="d1"); e.update(o); return E.sign(self.s._p, "k1", e)
    def refused(self, token, ce, code):
        with self.assertRaises(ProofError) as c: commit_verify(self.v, token, ce)
        self.assertEqual(c.exception.code, code)
    def test_exact_effect_verifies_once_then_replay_refused(self):
        t = self.tok(); self.assertEqual(commit_verify(self.v, t, self.ce)["sub"], "agent-a"); self.refused(t, self.ce, "REPLAY")
    def test_altered_args(self): self.refused(self.tok(), dataclasses.replace(self.ce, args={"a": 2}), "ARGS_MISMATCH")
    def test_altered_destination(self): self.refused(self.tok(), dataclasses.replace(self.ce, target_raw="https://evil.test/x"), "TARGET_MISMATCH")
    def test_altered_session(self): self.refused(self.tok(), dataclasses.replace(self.ce, session_id="sess2"), "ARGS_MISMATCH")
    def test_altered_server(self): self.refused(self.tok(), dataclasses.replace(self.ce, server_id="srv2"), "ARGS_MISMATCH")
    def test_altered_tenant(self): self.refused(self.tok(), dataclasses.replace(self.ce, tenant="t2"), "TENANT_MISMATCH")
    def test_altered_principal(self): self.refused(self.tok(), dataclasses.replace(self.ce, principal="agent-b"), "PRINCIPAL_MISMATCH")
    def test_altered_effect_type(self): self.refused(self.tok(), dataclasses.replace(self.ce, effect="delete"), "EFFECT_MISMATCH")
    def test_policy_version_change(self): t = self.tok(); self.pol[0] = "p2"; self.refused(t, self.ce, "STALE_POLICY")
    def test_expiry(self): self.refused(self.tok(exp=NOW - 10, iat=NOW - 20), self.ce, "EXPIRED")
    def test_unknown_effect_type_fails_closed(self):
        ce = dataclasses.replace(self.ce, effect="teleport"); self.refused(self.tok(), ce, "UNKNOWN_EFFECT")
    def test_empty_or_nul_field_rejected(self):
        for k in ("session_id", "server_id", "tenant"): self.refused(self.tok(), dataclasses.replace(self.ce, **{k: ""}), "MALFORMED")
        self.refused(self.tok(), dataclasses.replace(self.ce, session_id="a\x00b"), "MALFORMED")
    def test_missing_token(self): self.refused(None, self.ce, "MALFORMED")
    def test_failed_check_does_not_consume_nonce(self):
        t = self.tok(); self.refused(t, dataclasses.replace(self.ce, args={"a": 9}), "ARGS_MISMATCH"); self.assertEqual(commit_verify(self.v, t, self.ce)["nonce"], E.parse(t)[1]["nonce"])
    def test_field_boundary_ambiguity(self):
        a = CanonicalEffect("t", "ab", "c", "p", "send", "resource", "r", {}); b = CanonicalEffect("t", "a", "bc", "p", "send", "resource", "r", {})
        self.assertNotEqual(a.bound_args_digest(), b.bound_args_digest())
    def test_digest_is_domain_separated(self):
        import hashlib
        body = E.canonical({"tenant": "t1", "server": "srv1", "session": "sess1", "args": {"a": 1}}); self.assertNotEqual(self.ce.bound_args_digest(), "sha256:" + hashlib.sha256(body).hexdigest())
if __name__ == "__main__": unittest.main()
