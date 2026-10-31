"""P13 tests: AuthorizedEffect schema, trust store, call authority, gateway verifier, single-use nonces, per-dispatch Code Mode proofs, receiver-side effect oracle, receipts."""
import hashlib, json, os, shutil, sys, tempfile, threading, time, unittest
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAVE_CRYPTO = True
except ImportError: HAVE_CRYPTO = False
if HAVE_CRYPTO:
    from horizon.authz import effect as E, keys as K, authority as AU, gateway as G, receipts as R
    from horizon.service.core import Service
    from horizon.service.audit import verify_audit
    from bench.secbench.world import POLICY
from horizon.codemode.exec import Executor, HERE
HAVE_NODE = bool(shutil.which("node")) and (HERE / "node_modules" / "isolated-vm").exists()
URL = "https://api.example.com/v1/notes"


class Clock:
    def __init__(self, t=1_800_000_000.0): self.t = t
    def __call__(self): return self.t


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.c = Clock(); self.signer = K.Signer.generate("k1", "authority-1"); self.trust = K.TrustStore(self.c); self.trust.add("k1", "authority-1", self.signer.public_raw(), not_before=self.c() - 10, not_after=self.c() + 86400)
        self.svc = Service({"ta": {"tenant": "T1", "principal": "agent1", "role": "adapter"}, "adm": {"tenant": "T1", "principal": "adm", "role": "admin"}}, os.path.join(self.d, "svc.jsonl"), b"k" * 32, clock=self.c); self.addCleanup(self.svc.close)
        self.svc.handle("POST", "/v2/policies", "adm", {"policy": POLICY}); self.n = 0
        self.rc = R.Receipts(os.path.join(self.d, "rc.jsonl"), self.c); self.addCleanup(self.rc.close)
        self.auth = AU.CallAuthority(self.signer, lambda b: self.svc.handle("POST", "/v2/decisions", "ta", b)[1], audiences={"gw-1"}, contract_version="c1", clock=self.c, receipts=self.rc)
        self.nonces = G.NonceStore(clock=self.c); self.pol = [self.svc.tenant("T1").policy_digest]
        self.ver = G.Verifier(self.trust, self.nonces, issuer="authority-1", audience="gw-1", contract_version="c1", policy_version=lambda: self.pol[0], clock=self.c, receipts=self.rc)
        self.who = {"principal": "agent1", "tenant": "T1"}

    def req(self, args=None, url=URL, **kw):
        self.n += 1; args = args if args is not None else {"text": "hello"}; ad = E.args_digest(args)
        body = {"protocol": "utcp", "native_operation": "http:POST", "tool_id": "m/post", "effect": "send", "args_digest": ad, "target": {"kind": "url", "raw": url}, "sink_zone": "partner", "purpose": "p", "input_artifacts": [], "idempotency_key": f"k{self.n}".ljust(20, "x"), "event_id": f"e{self.n}"}
        r = {"effect": "send", "target": {"kind": "url", "raw": url}, "args_digest": ad, "aud": "gw-1", "decision_body": body}; r.update(kw); return r, args
    def issue(self, **kw):
        r, args = self.req(**kw); out = self.auth.issue(self.who, r); return out, args
    def vkw(self, args=None, **kw):
        d = dict(principal="agent1", tenant="T1", effect="send", target={"kind": "url", "raw": URL}, args_digest=E.args_digest(args if args is not None else {"text": "hello"})); d.update(kw); return d
    def code(self, token, **kw):
        with self.assertRaises(G.ProofError) as e: self.ver.verify(token, **self.vkw(**kw))
        return e.exception.code


class EffectSchema(Base):
    def eff(self, **kw):
        e = {"v": 1, "iss": "a", "sub": "p", "tenant": "T", "effect": "send", "target": {"kind": "url", "canonical_id": "https://x.example.com/"}, "args_digest": "sha256:" + "0" * 64, "contract_version": "c", "policy_version": "pv", "aud": "g", "iat": 100, "exp": 160, "nonce": "n", "decision_id": "d"}; e.update(kw); return e
    def test_valid_roundtrip_and_digest_properties(self):
        e = self.eff(); self.assertEqual(E.validate(e), e); d1 = E.digest(e); self.assertEqual(d1, E.digest(dict(reversed(list(e.items()))))); self.assertNotEqual(d1, E.digest(self.eff(nonce="m")))
        self.assertNotEqual(d1, "sha256:" + hashlib.sha256(E.canonical(e)).hexdigest())                       # domain-separated
        tok = E.sign(self.signer, "k1", e); h, e2, _, _ = E.parse(tok); self.assertEqual((h["alg"], h["typ"], e2), ("EdDSA", E.TYP, e))
    def test_validation_rejects_everything_unexpected(self):
        bad = [{"extra": 1}, {"v": 2}, {"effect": "teleport"}, {"target": {"kind": "url"}}, {"target": {"kind": "url", "canonical_id": "x", "extra": 1}}, {"args_digest": "abc"}, {"args_digest": "sha256:" + "G" * 64}, {"iat": True}, {"iat": -1}, {"exp": 100}, {"exp": 50}, {"sub": ""}, {"nonce": 5}, {"aud": "x" * 300}]
        for kw in bad:
            e = self.eff(**{k: v for k, v in kw.items() if k != "extra"}); 
            if "extra" in kw: e["extra"] = 1
            with self.assertRaises(E.EffectError, msg=str(kw)): E.validate(e)
        e = self.eff(); del e["nonce"]
        with self.assertRaises(E.EffectError): E.validate(e)
        with self.assertRaises(E.EffectError): E.validate([])
    def test_oversize_token_rejected_before_parsing(self):
        with self.assertRaises(E.EffectError) as e: E.parse("a" * 3000 + "." + "b" * 2000 + ".c")
        self.assertIn("too large", str(e.exception))
    def test_parse_bounds(self):
        for t in ("", "a.b", "a.b.c.d", None, 5, "x" * 5000, "!!.@@.##"):
            with self.assertRaises(E.EffectError): E.parse(t)
    def test_args_digest_is_canonical_and_distinguishes(self): self.assertEqual(E.args_digest({"a": 1, "b": 2}), E.args_digest({"b": 2, "a": 1})); self.assertNotEqual(E.args_digest({"a": 1}), E.args_digest({"a": "1"})); self.assertNotEqual(E.args_digest({"a": 1}), E.args_digest([("a", 1)]))


class TrustStoreTests(Base):
    def test_windows_revocation_rotation_and_issuer(self):
        at = self.c()
        with self.assertRaises(K.TrustError) as e: self.trust.resolve("k1", "other-issuer"); 
        self.assertEqual(e.exception.code, "ISSUER_MISMATCH")
        with self.assertRaises(K.TrustError) as e: self.trust.resolve("k1", "authority-1", at + 10 ** 7)
        self.assertEqual(e.exception.code, "KEY_OUT_OF_WINDOW")
        with self.assertRaises(K.TrustError) as e: self.trust.resolve("k1", "authority-1", at - 1000)
        self.assertEqual(e.exception.code, "KEY_OUT_OF_WINDOW")
        s2 = K.Signer.generate("k2", "authority-1")
        with self.assertRaises(K.TrustError) as e: self.trust.add("k1", "authority-1", s2.public_raw(), not_before=0, not_after=10)
        self.assertEqual(e.exception.code, "DUPLICATE_KID")
        with self.assertRaises(K.TrustError): self.trust.add("k3", "x", s2.public_raw(), not_before=10, not_after=10)
        self.trust.add("k2", "authority-1", s2.public_raw(), not_before=at - 1, not_after=at + 100); self.trust.revoke("k1")
        with self.assertRaises(K.TrustError) as e: self.trust.resolve("k1", "authority-1")
        self.assertEqual(e.exception.code, "KEY_REVOKED"); self.trust.resolve("k2", "authority-1")
        with self.assertRaises(K.TrustError): self.trust.revoke("nope")
    def test_export_is_public_only_and_import_rejects_private(self):
        doc = self.trust.export_public(); txt = json.dumps(doc); self.assertNotIn("PRIVATE", txt); t2 = K.TrustStore.from_public(doc, self.c); t2.resolve("k1", "authority-1")
        with self.assertRaises(K.TrustError) as e: K.TrustStore.from_public({"k9": dict(doc["k1"], private="00")}); 
        self.assertEqual(e.exception.code, "PRIVATE_MATERIAL")
        self.assertEqual(K.TrustStore.from_public({"k1": dict(doc["k1"], revoked=True)}, self.c).k["k1"]["revoked"], True)
    def test_signer_custody(self):
        import pickle
        self.assertNotIn("Ed25519", repr(self.signer)); 
        with self.assertRaises(TypeError): pickle.dumps(self.signer)
        p = os.path.join(self.d, "key.pem"); self.signer.save(p); self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError): self.signer.save(p)
        s = K.Signer.load("k1", "authority-1", p); self.assertEqual(s.public_raw(), self.signer.public_raw())
        os.chmod(p, 0o644)
        with self.assertRaises(K.TrustError): K.Signer.load("k1", "authority-1", p)
        os.chmod(p, 0o600); os.symlink(p, p + ".ln")
        with self.assertRaises(K.TrustError): K.Signer.load("k1", "authority-1", p + ".ln")


class AuthorityTests(Base):
    def test_allowed_effect_is_issued_with_bound_fields(self):
        out, args = self.issue(); self.assertTrue(out["ok"], out); _, e, _, _ = E.parse(out["token"])
        self.assertEqual((e["sub"], e["tenant"], e["effect"], e["aud"], e["contract_version"], e["policy_version"], e["exp"] - e["iat"]), ("agent1", "T1", "send", "gw-1", "c1", self.pol[0], 60)); self.assertEqual(e["target"]["canonical_id"], URL); self.assertEqual(out["effect_digest"], E.digest(e))
    def test_denied_review_unknown_produce_no_proof(self):
        out, _ = self.issue(url="https://api.example.com/other-zone"); 
        r, args = self.req(); r["decision_body"]["sink_zone"] = "unmapped-zone"; out = self.auth.issue(self.who, r); self.assertFalse(out["ok"]); self.assertNotIn("token", out)
        r, args = self.req(); r["decision_body"]["input_artifacts"] = ["no-such-artifact"]; out = self.auth.issue(self.who, r); self.assertFalse(out["ok"])
    def test_request_validation_and_binding(self):
        r, _ = self.req(); cases = {"aud": ("gw-other", "AUDIENCE_NOT_SERVED"), "effect": ("teleport", "UNKNOWN_EFFECT"), "args_digest": ("nope", "MALFORMED_ARGS_DIGEST"), "target": ({"kind": "url", "raw": "ftp://example.com/x"}, "TARGET_REJECTED")}
        for k, (v, code) in cases.items():
            r2 = json.loads(json.dumps(r)); r2[k] = v; out = self.auth.issue(self.who, r2); self.assertEqual((out["ok"], out["reason_codes"][0]), (False, code), k)
        r2 = json.loads(json.dumps(r)); r2["target"] = {"kind": "url", "raw": "https://api.example.com/v1/OTHER"}; self.assertEqual(self.auth.issue(self.who, r2)["reason_codes"], ["DECISION_BODY_MISMATCH"])     # decision is about a different target
        r2 = json.loads(json.dumps(r)); r2["args_digest"] = E.args_digest({"text": "evil"}); self.assertEqual(self.auth.issue(self.who, r2)["reason_codes"], ["DECISION_BODY_MISMATCH"])
        r2 = json.loads(json.dumps(r)); r2["effect"] = "read"; self.assertEqual(self.auth.issue(self.who, r2)["reason_codes"], ["DECISION_BODY_MISMATCH"])
        r2 = json.loads(json.dumps(r)); del r2["decision_body"]; self.assertEqual(self.auth.issue(self.who, r2)["reason_codes"], ["NO_DECISION_BODY"])
        for who in (None, {}, {"principal": "a"}, {"tenant": "t"}): self.assertEqual(self.auth.issue(who, r)["reason_codes"], ["UNAUTHENTICATED"])
        self.assertEqual(self.auth.issue(self.who, "junk")["reason_codes"], ["MALFORMED"])
    def test_policy_service_failures_fail_closed(self):
        r, _ = self.req()
        for bad in (lambda b: (_ for _ in ()).throw(RuntimeError("down")), lambda b: None, lambda b: "ALLOW", lambda b: {"verdict": "ALLOW"}, lambda b: {"verdict": "ALLOW", "decision_id": "d"}):
            a = AU.CallAuthority(self.signer, bad, audiences={"gw-1"}, contract_version="c1", clock=self.c); out = a.issue(self.who, r); self.assertFalse(out["ok"]); self.assertNotIn("token", out)
    def test_rate_limit_and_ttl_bounds(self):
        a = AU.CallAuthority(self.signer, lambda b: self.svc.handle("POST", "/v2/decisions", "ta", b)[1], audiences={"gw-1"}, contract_version="c1", clock=self.c, rate=0.0001, burst=1); r, _ = self.req(); self.assertTrue(a.issue(self.who, r)["ok"])
        r, _ = self.req(); self.assertEqual(a.issue(self.who, r)["reason_codes"], ["RATE_LIMITED"])
        for ttl in (0, 301, -1):
            with self.assertRaises(ValueError): AU.CallAuthority(self.signer, lambda b: {}, audiences={"x"}, contract_version="c", max_ttl_s=ttl)


class VerifierTests(Base):
    def test_valid_proof_verifies_once(self):
        out, args = self.issue(); p = self.ver.verify(out["token"], **self.vkw(args)); self.assertEqual(p["sub"], "agent1"); self.assertEqual(self.code(out["token"]), "REPLAY")
    def test_binding_mismatches_each_refused(self):
        for kw, code in ((dict(principal="agent2"), "PRINCIPAL_MISMATCH"), (dict(tenant="T2"), "TENANT_MISMATCH"), (dict(effect="delete"), "EFFECT_MISMATCH"), (dict(target={"kind": "url", "raw": "https://api.example.com/v1/other"}), "TARGET_MISMATCH"),
                         (dict(target={"kind": "url", "raw": "https://evil.example.org/v1/notes"}), "TARGET_MISMATCH"), (dict(target={"kind": "url", "raw": "https://127.0.0.1/"}), "TARGET_MISMATCH"), (dict(target={"kind": "bogus", "raw": "x"}), "TARGET_REJECTED"), (dict(target={}), "TARGET_REJECTED"),
                         (dict(args_digest=E.args_digest({"text": "EVIL"})), "ARGS_MISMATCH")):
            out, args = self.issue(); self.assertEqual(self.code(out["token"], **kw), code, kw)
        out, args = self.issue(); self.ver.verify(out["token"], **self.vkw(args))                       # mismatched attempts above did not burn a different valid token
    def test_mismatch_does_not_consume_the_nonce(self):
        out, args = self.issue(); self.assertEqual(self.code(out["token"], principal="agent2"), "PRINCIPAL_MISMATCH"); self.ver.verify(out["token"], **self.vkw(args))
    def test_equivalent_target_spellings_accepted(self):
        out, args = self.issue(); self.ver.verify(out["token"], **self.vkw(args, target={"kind": "url", "raw": "https://API.example.com:443/v1/./notes"}))
    def test_audience_contract_and_time(self):
        out, args = self.issue(); v2 = G.Verifier(self.trust, G.NonceStore(clock=self.c), issuer="authority-1", audience="gw-2", contract_version="c1", clock=self.c)
        with self.assertRaises(G.ProofError) as e: v2.verify(out["token"], **self.vkw(args))
        self.assertEqual(e.exception.code, "BAD_AUDIENCE"); v3 = G.Verifier(self.trust, G.NonceStore(clock=self.c), issuer="authority-1", audience="gw-1", contract_version="c2", clock=self.c)
        with self.assertRaises(G.ProofError) as e: v3.verify(out["token"], **self.vkw(args))
        self.assertEqual(e.exception.code, "CONTRACT_MISMATCH"); v4 = G.Verifier(self.trust, G.NonceStore(clock=self.c), issuer="other", audience="gw-1", contract_version="c1", clock=self.c)
        with self.assertRaises(G.ProofError) as e: v4.verify(out["token"], **self.vkw(args))
        self.assertEqual(e.exception.code, "BAD_ISSUER")
        self.c.t += 200; self.assertEqual(self.code(out["token"]), "EXPIRED")
        self.c.t -= 200; out, args = self.issue(); self.c.t -= 8; self.assertEqual(self.code(out["token"]), "NOT_YET_VALID")
    def test_ttl_longer_than_gateway_policy_refused(self):
        eff = dict(E.parse(self.issue()[0]["token"])[1]); eff["exp"] = eff["iat"] + 400; self.assertEqual(self.code(E.sign(self.signer, "k1", eff)), "TTL_TOO_LONG")
    def test_policy_revision_race_voids_old_proofs(self):
        out, args = self.issue(); pol2 = json.loads(json.dumps(POLICY)); pol2["metadata"]["version"] = 2; self.svc.handle("POST", "/v2/policies", "adm", {"policy": pol2}); self.pol[0] = self.svc.tenant("T1").policy_digest
        self.assertEqual(self.code(out["token"]), "STALE_POLICY"); out2, _ = self.issue(); self.ver.verify(out2["token"], **self.vkw(args))
    def test_signature_forgery_tamper_alg_and_key_state(self):
        out, args = self.issue(); h, p, s = out["token"].split(".")
        self.assertEqual(self.code(".".join([h, p, E.b64e(b"\0" * 64)])), "BAD_SIGNATURE")
        e = json.loads(E.b64d(p)); e["sub"] = "agent2"; forged = ".".join([h, E.b64e(E.canonical(e)), s]); self.assertEqual(self.code(forged, principal="agent2"), "BAD_SIGNATURE")
        other = K.Signer.generate("k1", "authority-1"); eff = E.parse(out["token"])[1]; self.assertEqual(self.code(E.sign(other, "k1", eff)), "BAD_SIGNATURE")                 # attacker-signed with same kid
        for hdr in ({"alg": "none", "typ": E.TYP, "kid": "k1"}, {"alg": "HS256", "typ": E.TYP, "kid": "k1"}, {"alg": "EdDSA", "typ": "JWT", "kid": "k1"}, {"alg": "EdDSA", "typ": E.TYP}):
            self.assertEqual(self.code(".".join([E.b64e(E.canonical(hdr)), p, s])), "BAD_HEADER")
        self.assertEqual(self.code(".".join([E.b64e(E.canonical({"alg": "EdDSA", "typ": E.TYP, "kid": "zz"})), p, s])), "UNKNOWN_KID")
        self.assertEqual(self.code(".".join([h, p])), "MALFORMED"); self.assertEqual(self.code(None), "MALFORMED")
        self.trust.revoke("k1"); self.assertEqual(self.code(out["token"]), "KEY_REVOKED")
    def test_extra_signed_fields_rejected(self):
        eff = dict(E.parse(self.issue()[0]["token"])[1], admin=True); s = E.b64e(E.canonical({"alg": "EdDSA", "typ": E.TYP, "kid": "k1"})) + "." + E.b64e(E.canonical(eff)); tok = s + "." + E.b64e(self.signer.sign(s.encode()))
        self.assertEqual(self.code(tok), "MALFORMED")
    def test_nonce_persistence_across_restart_and_bounds(self):
        p = os.path.join(self.d, "n.db"); n1 = G.NonceStore(p, clock=self.c); self.assertTrue(n1.consume("a", 10 ** 10)); n1.close(); n2 = G.NonceStore(p, clock=self.c); self.assertFalse(n2.consume("a", 10 ** 10)); self.assertTrue(n2.consume("b", 10 ** 10))
        small = G.NonceStore(max_rows=2, clock=self.c); small.consume("x", 10 ** 10); small.consume("y", 10 ** 10)
        with self.assertRaises(G.ProofError) as e: small.consume("z", 10 ** 10)
        self.assertEqual(e.exception.code, "NONCE_STORE_FULL"); old = G.NonceStore(max_rows=1, clock=self.c); old.consume("q", int(self.c()) - 7200); self.assertTrue(old.consume("r", 10 ** 10))      # expired rows are purged
    def test_concurrent_replay_exactly_one_wins(self):
        out, args = self.issue(); res = []; bar = threading.Barrier(16)
        def go():
            bar.wait()
            try: self.ver.verify(out["token"], **self.vkw(args)); res.append("ok")
            except G.ProofError as e: res.append(e.code)
        ts = [threading.Thread(target=go) for _ in range(16)]; [t.start() for t in ts]; [t.join() for t in ts]; self.assertEqual((res.count("ok"), res.count("REPLAY")), (1, 15))


class Receiver:
    """Synthetic effect oracle (P13-12): records the bytes that actually 'arrive'."""
    def __init__(self): self.got = []


class GuardedSinks(Base):
    def setUp(self):
        super().setUp(); self.rx = Receiver()
    def test_utcp_style_sink_delivers_only_with_valid_unreplayed_proof(self):
        def describe(r, proof=None): return {"token": proof, "principal": "agent1", "tenant": "T1", "effect": "send", "target": {"kind": "url", "raw": r["url"]}, "args": r["body"]}
        @G.guard(self.ver, describe)
        def send(r, proof=None): self.rx.got.append((r["url"], r["body"]))
        body = {"text": "hello"}; call = {"url": URL, "body": body}
        for proof in (None, "garbage"):
            with self.assertRaises(G.ProofError): send(call, proof)
        out, _ = self.issue(args=body); send(call, out["token"]); self.assertEqual(self.rx.got, [(URL, body)])
        with self.assertRaises(G.ProofError) as e: send(call, out["token"])
        self.assertEqual(e.exception.code, "REPLAY")
        out, _ = self.issue(args=body)
        for mutated in ({"url": "https://api.example.com/v1/other", "body": body}, {"url": URL, "body": {"text": "SECRET"}}, {"url": "https://evil.example.org/", "body": body}):
            with self.assertRaises(G.ProofError): send(mutated, out["token"])
        self.assertEqual(len(self.rx.got), 1); send(call, out["token"]); self.assertEqual(len(self.rx.got), 2)                      # the valid proof still works for the exact effect
    def test_mcp_style_forward_requires_proof_in_extra(self):
        def describe(server, req, extra): return {"token": extra.get("proof"), "principal": req["principal"], "tenant": "T1", "effect": "send", "target": {"kind": "url", "raw": URL}, "args": req["arguments"]}
        @G.guard(self.ver, describe)
        def forward(server, req, extra): self.rx.got.append(req["arguments"]); return {"result": "ok"}
        out, _ = self.issue(args={"text": "hello"})
        with self.assertRaises(G.ProofError): forward("s", {"principal": "agent1", "arguments": {"text": "hello"}}, {})
        with self.assertRaises(G.ProofError) as e: forward("s", {"principal": "agent2", "arguments": {"text": "hello"}}, {"proof": out["token"]})
        self.assertEqual(e.exception.code, "PRINCIPAL_MISMATCH"); self.assertEqual(forward("s", {"principal": "agent1", "arguments": {"text": "hello"}}, {"proof": out["token"]}), {"result": "ok"}); self.assertEqual(len(self.rx.got), 1)
    def test_broker_secret_injected_only_after_verification_and_never_in_proof_or_receipts(self):
        from horizon.adapters.utcp.creds import CredentialBroker
        b = CredentialBroker(); b.put("T1", "reg", "REGISTRY-SECRET-123", audience_origin="https://api.example.com"); seen = []
        def describe(r, proof=None): return {"token": proof, "principal": "agent1", "tenant": "T1", "effect": "send", "target": {"kind": "url", "raw": r["url"]}, "args": r["body"]}
        @G.guard(self.ver, describe)
        def send(r, proof=None): h = b.inject("T1", "reg", {"scheme": "https", "host": "api.example.com", "port": 443}, {}); seen.append(h)
        call = {"url": URL, "body": {"text": "x"}}
        with self.assertRaises(G.ProofError): send(call, None)
        self.assertEqual(seen, []); out, _ = self.issue(args=call["body"]); send(call, out["token"]); self.assertEqual(len(seen), 1)
        self.assertNotIn("REGISTRY-SECRET-123", out["token"] + json.dumps(E.parse(out["token"])[1])); self.rc.close(); self.assertNotIn(b"REGISTRY-SECRET-123", Path(self.d, "rc.jsonl").read_bytes())


@unittest.skipUnless(HAVE_CRYPTO and HAVE_NODE, "needs cryptography and Code Mode runtime")
class CodeModePerDispatch(Base):
    def test_each_dispatch_needs_its_own_proof_not_one_outer_program_proof(self):
        executed = []; pre = {}
        for doc in ("A", "B"): pre[doc] = self.issue(args={"id": doc})
        grant = {"A": pre["A"][0]["token"]}                                         # the host holds a proof for A only; model code cannot mint one
        def mediator(call):
            args = call["args"] if "args" in call else call.get("arguments", {}); doc = args.get("id") if isinstance(args, dict) else None
            try: self.ver.verify(grant.get(doc), principal="agent1", tenant="T1", effect="send", target={"kind": "url", "raw": URL}, args_digest=E.args_digest({"id": doc}))
            except G.ProofError as e: return {"ok": False, "error": e.code}
            executed.append(doc); return {"ok": True, "result": "sent " + doc}
        ex = Executor(mediator)
        r = ex.run("const out = []; for (const id of ['A','B','A']) { try { out.push(await tools.mcp.get_doc({id})); } catch (e) { out.push('ERR:' + (e.code || e.message)); } } return out;", ["mcp.get_doc"], principal="agent1", timeout_s=30)
        self.assertEqual(executed, ["A"]); self.assertEqual(json.dumps(r).count("sent A"), 1); self.assertIn("ERR", json.dumps(r))


class ReceiptTests(Base):
    def test_receipts_are_chained_policy_bound_and_secret_free(self):
        out, args = self.issue(args={"text": "TOPSECRET-PAYLOAD"}); self.ver.verify(out["token"], **self.vkw({"text": "TOPSECRET-PAYLOAD"})); self.code(out["token"], args_digest=E.args_digest({"text": "TOPSECRET-PAYLOAD"})); self.rc.close()
        p = os.path.join(self.d, "rc.jsonl"); ok, why = verify_audit(p); self.assertTrue(ok, why); recs = [json.loads(x) for x in open(p)]; self.assertEqual([r["outcome"] for r in recs], ["issued", "verified", "refused"])
        self.assertEqual(recs[0]["policy_version"], self.pol[0]); self.assertEqual(recs[0]["effect_digest"], recs[1]["effect_digest"]); self.assertEqual(recs[2]["reasons"], ["REPLAY"])
        raw = Path(p).read_text()
        for banned in ("TOPSECRET", out["token"], "agent1", "api.example.com", "hello"): self.assertNotIn(banned, raw)
        lines = raw.splitlines(); Path(p).write_text("\n".join([lines[0], lines[2]]) + "\n"); self.assertFalse(verify_audit(p)[0])


class OverheadAndDocs(unittest.TestCase):
    def test_overhead_result_is_complete_and_honest(self):
        d = REPO / "results/v2/p13-overhead"; r = json.loads((d / "result.json").read_text()); m = json.loads((d / "manifest.json").read_text())
        self.assertEqual(set(r["components"]), {"policy_decision_only", "authority_issue_incl_decision_and_sign", "sign_only", "verify_incl_nonce", "nonce_consume_only", "guarded_gateway_call"}); self.assertEqual((m["experiment_id"], r["iterations"]), ("p13-overhead", 2000))
        for c in r["components"].values(): self.assertTrue(0 < c["p50_us"] <= c["p95_us"] <= c["p99_us"] <= c["max_us"], c)
        self.assertIn("not a production benchmark", r["environment"]["note"]); self.assertIn("no pass/fail threshold", m["status"])
    def test_overhead_script_refuses_to_overwrite(self):
        import subprocess
        r = subprocess.run([sys.executable, str(REPO / "bench/p13/overhead.py")], capture_output=True, text=True); self.assertNotEqual(r.returncode, 0); self.assertIn("write-once", r.stderr + r.stdout)
    def test_proof_sketch_states_limits(self):
        t = (REPO / "docs/security/P13_PROOF_SKETCH.md").read_text()
        for w in ("no independent cryptography", "P13-01", "not** wired", "Authority compromise", "Consumption before effect"): self.assertIn(w.lower(), t.lower(), w)


if __name__ == "__main__": unittest.main()
