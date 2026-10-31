"""P7 tests: sidecar/labels/forgery, tenant isolation + grants, declassification, delegation, value tracking, outgoing-boundary detector vs byte oracle,
verification relations, paired study across MCP/UTCP/Code Mode using the REAL P3 service and gates."""
import base64, binascii, json, os, shutil, sys, unittest
from pathlib import Path
from urllib.parse import quote
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from horizon.core import labels as L
from horizon import schemas
from horizon.lineage import tracked as TV, detect as D
from horizon.lineage.sidecar import Sidecar, Hub, Delegations, LineageError
from horizon.lineage.oracle import Oracle, strip_truth, TRUTH_KEYS
from horizon.lineage.epistemic import Ledger
from bench.p7 import study as ST
from horizon.codemode.exec import Executor, HERE
import inspect

SRC = {"vault": ("SECRET", "TRUSTED"), "pub": ("PUBLIC", "TRUSTED"), "web": ("PUBLIC", "UNTRUSTED"), "wiki": ("INTERNAL", "UNVERIFIED"), "kb": ("PUBLIC", "TRUSTED"), "audit": ("PUBLIC", "TRUSTED")}
SECRET = "CANARY-api-0123456789abcdef01234567"


class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t


def sc_(tenant="T1", clock=None, **kw): return Sidecar(tenant, sources=SRC, declassifier_keys={"dc": b"k" * 16}, clock=clock or Clock(), **kw)


class SidecarTests(unittest.TestCase):
    def test_labels_come_from_operator_config_not_caller_and_artifacts_validate(self):
        s = sc_(); a = s.ingest("vault", SECRET, principal="p", event_id="e1"); b = s.ingest("unknown-src", "x", principal="p", event_id="e2")
        self.assertEqual((s.art[a]["confidentiality"], s.art[a]["trust"]), ("SECRET", "TRUSTED")); self.assertEqual((s.art[b]["confidentiality"], s.art[b]["trust"]), ("INTERNAL", "UNTRUSTED"))
        for h in (a, b): self.assertEqual(schemas.validate("artifact", s.art[h]), [])
        self.assertEqual(len({s.ingest("pub", "same", principal="p", event_id="e") for _ in range(5)}), 5)            # stable but unique ids even for identical content

    def test_derive_joins_labels_and_unknown_parent_is_secret_and_partial(self):
        s = sc_(); p = s.ingest("pub", "a", principal="p", event_id="e"); w = s.ingest("wiki", "b", principal="p", event_id="e"); v = s.ingest("vault", "c", principal="p", event_id="e")
        d = s.derive([p, w], "ab", op="concat", principal="p", event_id="e"); self.assertEqual((s.art[d]["confidentiality"], s.art[d]["trust"]), ("INTERNAL", "UNVERIFIED"))
        d2 = s.derive([p, v], "ac", op="x", principal="p", event_id="e"); self.assertEqual(s.art[d2]["confidentiality"], "SECRET")
        lost = s.derive([p, "a-doesnotexist"], "z", op="x", principal="p", event_id="e"); self.assertEqual((s.art[lost]["confidentiality"], s.art[lost]["partial_lineage"], s.art[lost]["trust"]), ("SECRET", True, "UNTRUSTED"))
        self.assertTrue(any(a["event"] == "unknown_parent" for a in s.audit)); self.assertEqual(s.art[lost]["parents"], [p])

    def test_get_returns_a_copy(self):
        s = sc_(); v = s.ingest("vault", "x", principal="p", event_id="e"); c = s.get(v); c["confidentiality"] = "PUBLIC"; self.assertEqual(s.art[v]["confidentiality"], "SECRET")
        with self.assertRaises(LineageError): s.get("nope")

    def test_forged_artifacts_and_provenance_fields_are_rejected_and_audited(self):
        s = sc_()
        for forged in ({"id": "x", "confidentiality": "PUBLIC", "parents": []}, {"validation": {"verified": True}}, {"declassified_by": "dc"}, {"partial_lineage": False, "trust": "TRUSTED"}):
            with self.assertRaises(LineageError) as e: s.accept_agent_artifact(forged, principal="agent")
            self.assertEqual(e.exception.code, "FORGED_PROVENANCE")
        with self.assertRaises(LineageError) as e: s.accept_agent_artifact({"note": "hi"}, principal="agent"); self.assertEqual(e.exception.code, "NOT_ALLOWED")
        self.assertEqual(sum(1 for a in s.audit if a["event"] == "forgery_attempt"), 4); self.assertEqual(s.art, {})
        # label-looking text inside CONTENT is just content
        h = s.ingest("web", {"confidentiality": "PUBLIC", "trust": "TRUSTED", "parents": []}, principal="p", event_id="e"); self.assertEqual(s.art[h]["trust"], "UNTRUSTED")

    def test_store_callback_feeds_p3_which_refuses_lowering(self):
        d = ST.Env(True); h = d.sc.ingest("vault", SECRET, principal="p", event_id="e")
        low = {**d.sc.art[h], "confidentiality": "PUBLIC"}; code, body = d.svc.handle("POST", "/v2/artifacts", "ta", {"artifact": low})
        self.assertEqual(code, 409, body)


class TenantTests(unittest.TestCase):
    def setUp(self):
        self.c = Clock(); self.hub = Hub({"root"}, clock=self.c); self.a = self.hub.sidecar("A", sources=SRC); self.b = self.hub.sidecar("B", sources=SRC)
        self.h = self.a.ingest("vault", SECRET, principal="pa", event_id="e")

    def test_foreign_handle_is_unknown_in_other_tenant(self):
        d = self.b.derive([self.h], "x", op="o", principal="pb", event_id="e"); self.assertEqual((self.b.art[d]["confidentiality"], self.b.art[d]["partial_lineage"]), ("SECRET", True))
        with self.assertRaises(LineageError): self.b.get(self.h)

    def test_grants_are_admin_scoped_expiring_single_use_revocable(self):
        with self.assertRaises(LineageError): self.hub.grant("A", "B", self.h, by="agent", purposes=["r"])
        with self.assertRaises(LineageError): self.hub.grant("A", "A", self.h, by="root", purposes=["r"])
        with self.assertRaises(LineageError): self.hub.grant("A", "B", self.h, by="root", purposes=[])
        g = self.hub.grant("A", "B", self.h, by="root", purposes=["review"])
        for tenant, purpose in (("C", "review"), ("A", "review"), ("B", "other")):
            with self.assertRaises(LineageError): self.hub.accept(g, tenant, principal="x", purpose=purpose)
        s = self.hub.accept(g, "B", principal="pb", purpose="review"); a = self.b.art[s]
        self.assertEqual((a["confidentiality"], a["trust"], a["partial_lineage"], a["parents"], a["purpose_tags"]), ("SECRET", "UNTRUSTED", True, [], ["review"]))
        with self.assertRaises(LineageError): self.hub.accept(g, "B", principal="pb", purpose="review")                 # single use
        g2 = self.hub.grant("A", "B", self.h, by="root", purposes=["review"]); self.hub.revoke(g2, "root")
        with self.assertRaises(LineageError): self.hub.accept(g2, "B", principal="pb", purpose="review")
        with self.assertRaises(LineageError): self.hub.revoke(g2, "agent")
        g3 = self.hub.grant("A", "B", self.h, by="root", purposes=["review"], ttl_s=10); self.c.t += 11
        with self.assertRaises(LineageError): self.hub.accept(g3, "B", principal="pb", purpose="review")

    def test_shared_secret_remains_detectable_in_receiving_tenant(self):
        g = self.hub.grant("A", "B", self.h, by="root", purposes=["review"]); self.hub.accept(g, "B", principal="pb", purpose="review")
        r = D.Boundary(self.b)({"body": f"leak {SECRET}".encode(), "url": "", "input_artifacts": []}); self.assertIn(D.VERIFIED_LEAK, r["reason_codes"])


class DeclassTests(unittest.TestCase):
    def setUp(self):
        self.c = Clock(); self.s = sc_(clock=self.c); self.v = self.s.ingest("vault", SECRET, principal="p", event_id="e")

    def req(self, **kw):
        r = {"artifact_id": self.v, "from": "SECRET", "to": "PUBLIC", "nonce": "n1", "declassifier": "dc", "reason": "release approved"}; r.update(kw); return r

    def go(self, **kw):
        r = self.req(**{k: v for k, v in kw.items() if k in ("nonce", "to", "reason", "artifact_id", "declassifier")})
        a = dict(purpose="release", sink_zones=["partner"], declassifier="dc", nonce=r["nonce"], reason=r["reason"], sig=L.sign_declassification(b"k" * 16, r)); a.update({k: v for k, v in kw.items() if k in ("purpose", "sink_zones", "sig", "ttl_s")})
        return self.s.declassify(kw.get("h", self.v), r["to"], **a)

    def test_valid_purpose_bound_and_audited(self):
        d = self.go(); self.assertEqual((self.s.art[d]["confidentiality"], self.s.art[d]["parents"]), ("PUBLIC", [])); self.assertEqual(self.s.art[self.v]["confidentiality"], "SECRET")
        self.assertTrue(self.s.use_allowed(d, "release", "partner")); self.assertFalse(self.s.use_allowed(d, "marketing", "partner")); self.assertFalse(self.s.use_allowed(d, "release", "public-web"))
        self.c.t += 4000; self.assertFalse(self.s.use_allowed(d, "release", "partner")); self.assertIn("declassified", [a["event"] for a in self.s.audit])

    def test_refusals(self):
        with self.assertRaises(LineageError): self.go(sig="0" * 64)
        with self.assertRaises(LineageError): self.go(purpose="")
        with self.assertRaises(LineageError): self.go(sink_zones=[])
        with self.assertRaises(LineageError): self.go(to="SECRET")
        self.go()
        with self.assertRaises(LineageError): self.go()                                                                  # nonce replay
        lost = self.s.derive([self.v, "ghost"], "z", op="x", principal="p", event_id="e")
        with self.assertRaises(LineageError) as e: self.s.declassify(lost, "PUBLIC", purpose="r", sink_zones=["z"], declassifier="dc", nonce="n9", reason="r", sig="0")
        self.assertEqual(e.exception.code, "PARTIAL_LINEAGE")

    def test_p3_sees_declassified_as_public_and_original_secret(self):
        e = ST.Env(True); v = e.sc.ingest("vault", SECRET, principal="p", event_id="e")
        r = {"artifact_id": v, "from": "SECRET", "to": "PUBLIC", "nonce": "n2", "declassifier": "dc1", "reason": "ok"}
        d = e.sc.declassify(v, "PUBLIC", purpose="release", sink_zones=["partner"], declassifier="dc1", nonce="n2", reason="ok", sig=L.sign_declassification(ST.DECL_KEY, r))
        t = e.svc.tenant("T1"); self.assertEqual((schemas.effective_confidentiality(d, t.artifacts), schemas.effective_confidentiality(v, t.artifacts)), ("PUBLIC", "SECRET"))


class DelegationTests(unittest.TestCase):
    def test_attenuation_only(self):
        c = Clock(); dl = Delegations(c); root = dl.root("A", {"h1", "h2"}, {"read", "send"}, ttl_s=100)
        with self.assertRaises(LineageError): dl.delegate(root, "B", {"h1", "h3"}, {"read"})
        with self.assertRaises(LineageError): dl.delegate(root, "B", {"h1"}, {"admin"})
        b = dl.delegate(root, "B", {"h1"}, {"read"}, ttl_s=1000); self.assertTrue(dl.allows(b, "B", "h1", "read")); self.assertFalse(dl.allows(b, "B", "h2", "read")); self.assertFalse(dl.allows(b, "B", "h1", "send")); self.assertFalse(dl.allows(b, "C", "h1", "read"))
        with self.assertRaises(LineageError): dl.delegate(b, "C", {"h1"}, {"read"})                                    # B cannot re-delegate
        c.t += 101; self.assertFalse(dl.allows(b, "B", "h1", "read"))                                                    # bounded by the root expiry despite its own 1000s ttl


class TrackingTests(unittest.TestCase):
    def test_operations_propagate_sources(self):
        a, b = TV.of("secret-a", "h1"), TV.of("b", "h2")
        self.assertEqual(TV.concat([a, TV.lit("-"), b]).src, {"h1", "h2"}); self.assertEqual(TV.fmt("{x}!", x=a).src, {"h1"}); self.assertEqual(TV.dumps(TV.dictof({"k": a, "z": b})).src, {"h1", "h2"})
        self.assertEqual(TV.loads(TV.dumps(TV.dictof({"k": a}))).src, {"h1"}); self.assertEqual(TV.get(TV.of({"k": 1}, "h3"), "k").src, {"h3"}); self.assertEqual(TV.encode(a, "b64").src, {"h1"}); self.assertEqual(TV.encode(a, "hex").src, {"h1"})
        self.assertEqual(TV.listof([a, b]).src, {"h1", "h2"}); self.assertEqual(TV.slice_(TV.of([1, 2, 3], "h4"), 1).src, {"h4"}); self.assertEqual(TV.lit(5).src, frozenset())

    def test_loops_callbacks_reduce_and_nested_structures(self):
        arr = TV.of(["x", "y", "z"], "hA"); extra = TV.of("e", "hB")
        m = TV.map_(arr, lambda e: TV.concat([e, extra])); self.assertEqual(m.src, {"hA", "hB"}); self.assertEqual(m.v, ["xe", "ye", "ze"])
        m2 = TV.map_(arr, lambda e: e.v.upper()); self.assertEqual((m2.src, m2.v), ({"hA"}, ["X", "Y", "Z"]))                     # plain return inherits the element's sources
        r = TV.reduce_(arr, lambda acc, e: TV.concat([acc, e]), TV.lit("")); self.assertEqual((r.src, r.v), ({"hA"}, "xyz"))
        out = TV.lit("")
        for e in TV.items(arr): out = TV.concat([out, e])
        self.assertEqual(out.src, {"hA"})
        self.assertEqual(TV.dictof({"a": TV.listof([TV.dictof({"deep": extra})])}).src, {"hB"})

    def test_opaque_paraphrase_keeps_sources_and_flag_and_nothing_prints(self):
        a = TV.of("secret", "h1"); p = TV.paraphrase(a, lambda s: "totally different words"); self.assertEqual((p.src, p.opaque, p.v), ({"h1"}, True, "totally different words")); self.assertTrue(TV.concat([p, TV.lit("x")]).opaque)
        self.assertNotIn("secret", repr(a))

    def test_cross_protocol_chain_http_to_codemode_to_utcp_and_mcp_to_message_to_agent(self):
        s = sc_(); http = s.ingest("web", {"body": "response from HTTP"}, principal="p", event_id="e", protocol="utcp"); mcp = s.ingest("vault", "mcp tool result " + SECRET, principal="p", event_id="e", protocol="mcp")
        v = TV.concat([TV.of("r:", http), TV.of("m:", mcp)]); h = TV.materialize(s, v, op="build-body", principal="p", event_id="e2")
        self.assertEqual(set(s.art[h]["parents"]), {http, mcp}); self.assertEqual(s.art[h]["confidentiality"], "SECRET"); self.assertEqual(s.meta[h]["protocol"], "codemode")
        msg = TV.fmt("please act on: {m}", m=TV.of("x", h)); h2 = TV.materialize(s, msg, op="agent-message", principal="p", event_id="e3", protocol="agent"); self.assertEqual(s.art[h2]["parents"], [h]); self.assertEqual(schemas.effective_confidentiality(h2, s.art), "SECRET")
        self.assertEqual({s.meta[i]["protocol"] for i in (http, mcp)}, {"utcp", "mcp"})

    def test_untracked_values_lose_lineage_by_design(self):
        a = TV.of("secret", "h1"); plain = a.v + "!"; self.assertFalse(hasattr(plain, "src"))        # documented limit: the byte-level boundary is what catches this


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.s = sc_(); self.v = self.s.ingest("vault", SECRET, principal="p", event_id="e"); self.pub = self.s.ingest("pub", "hello public world", principal="p", event_id="e"); self.b = D.Boundary(self.s)

    def chk(self, body, ids=(), url=""): return self.b({"body": body.encode() if isinstance(body, str) else body, "url": url, "input_artifacts": list(ids), "sink_zone": "partner", "purpose": "release"})

    def test_verified_leak_in_every_encoding(self):
        enc = {"raw": SECRET, "b64": base64.b64encode(SECRET.encode()).decode(), "b64url": base64.urlsafe_b64encode(SECRET.encode()).decode().rstrip("="), "hex": binascii.hexlify(SECRET.encode()).decode(),
               "pct": quote(f"k={SECRET}", safe=""), "json": json.dumps({"a": {"b": [SECRET]}}), "pct2": quote(quote(SECRET, safe=""), safe=""), "nested": base64.b64encode(binascii.hexlify(SECRET.encode())).decode(),
               "inurl": None}
        for k, v in enc.items():
            r = self.chk(v if v else "", url=f"https://x.example/?q={SECRET}" if k == "inurl" else "")
            self.assertFalse(r["allow"], k); self.assertIn(D.VERIFIED_LEAK, r["reason_codes"], k)

    def test_encodings_that_change_bytes_for_secrets_with_special_characters(self):
        sec = "p@ss/w0rd+key=abc>>??~~value"; s = sc_(); s.ingest("vault", sec, principal="p", event_id="e"); b = D.Boundary(s)
        for k, body in {"b64url": base64.urlsafe_b64encode(sec.encode()).decode().rstrip("="), "b64": base64.b64encode(sec.encode()).decode(), "pct": quote(sec, safe=""), "pct-in-url": None}.items():
            r = b({"body": (body or "").encode(), "url": f"https://x.example/?q={quote(sec, safe='')}" if body is None else "", "input_artifacts": []})
            self.assertIn(D.VERIFIED_LEAK, r["reason_codes"], k)
        self.assertNotEqual(base64.urlsafe_b64encode(sec.encode()), base64.b64encode(sec.encode())); self.assertNotEqual(quote(sec, safe=""), sec)

    def test_purpose_violation_alone_denies(self):
        r = {"artifact_id": self.v, "from": "SECRET", "to": "PUBLIC", "nonce": "q1", "declassifier": "dc", "reason": "ok"}
        d = self.s.declassify(self.v, "PUBLIC", purpose="release", sink_zones=["partner"], declassifier="dc", nonce="q1", reason="ok", sig=L.sign_declassification(b"k" * 16, r))
        out = self.b({"body": b"entirely harmless text", "url": "", "input_artifacts": [d], "sink_zone": "partner", "purpose": "marketing"}); self.assertEqual((out["allow"], out["reason_codes"]), (False, [D.PURPOSE_VIOLATION]))

    def test_benign_and_lookalikes_are_not_flagged(self):
        for body in ("hello public world", "token sk-EXAMPLEPUBLIC1234567890", "CANARY-api-different0000000000000000", "AKIAIOSFODNN7EXAMPLE", ""):
            r = self.chk(body, [self.pub]); self.assertTrue(r["allow"], body); self.assertEqual(r["reason_codes"], [])

    def test_possible_flow_vs_verified_leak_codes_are_distinct(self):
        r = self.chk("summary without the secret", [self.v]); self.assertEqual((r["allow"], r["reason_codes"], r["verified"]), (True, [D.POSSIBLE_FLOW], []))                    # label says it MAY flow; boundary does not block by itself (P3 policy does)
        r = self.chk(SECRET, [self.v]); self.assertEqual((r["allow"], D.POSSIBLE_FLOW in r["reason_codes"], D.VERIFIED_LEAK in r["reason_codes"]), (False, True, True))
        r = self.chk(SECRET, []); self.assertEqual((r["allow"], r["reason_codes"]), (False, [D.VERIFIED_LEAK]))                                                                       # lineage lost, bytes still caught

    def test_partial_and_unknown_inputs_are_reported(self):
        lost = self.s.derive([self.pub, "ghost"], "x", op="o", principal="p", event_id="e"); r = self.chk("hi", [lost]); self.assertIn(D.PARTIAL_LINEAGE, r["reason_codes"]); self.assertIn(D.POSSIBLE_FLOW, r["reason_codes"])
        self.assertIn(D.UNKNOWN_INPUT, self.chk("hi", ["a-not-there"])["reason_codes"])

    def test_token_as_authentication_vs_token_as_payload(self):
        b = D.Boundary(self.s, credential_secrets=lambda: ["BROKER-TOKEN-123456"])
        self.assertTrue(b({"body": b"ordinary", "url": "", "input_artifacts": []})["allow"])
        r = b({"body": b"echo BROKER-TOKEN-123456", "url": "", "input_artifacts": []}); self.assertEqual((r["allow"], r["reason_codes"]), (False, [D.CREDENTIAL_IN_PAYLOAD]))

    def test_paraphrase_without_lineage_is_a_documented_miss(self):
        r = self.chk("the vault token starts with canary and has twenty-four hex characters", []); self.assertTrue(r["allow"])              # no bytes, no labels: undetectable by design
        o = Oracle(); o.plant("v"); o.canaries["v"] = SECRET; self.assertEqual(o.observe("x", b"the vault token starts with canary"), [])

    def test_purpose_bound_declassified_copy_is_exempt_only_in_scope(self):
        r = {"artifact_id": self.v, "from": "SECRET", "to": "PUBLIC", "nonce": "z1", "declassifier": "dc", "reason": "ok"}
        d = self.s.declassify(self.v, "PUBLIC", purpose="release", sink_zones=["partner"], declassifier="dc", nonce="z1", reason="ok", sig=L.sign_declassification(b"k" * 16, r))
        self.assertTrue(self.chk(SECRET, [d])["allow"])
        out = self.b({"body": SECRET.encode(), "url": "", "input_artifacts": [d], "sink_zone": "partner", "purpose": "marketing"}); self.assertEqual((out["allow"], D.PURPOSE_VIOLATION in out["reason_codes"]), (False, True))
        out = self.b({"body": SECRET.encode(), "url": "", "input_artifacts": [d], "sink_zone": "public-web", "purpose": "release"}); self.assertFalse(out["allow"])
        self.assertFalse(self.chk(SECRET, [])["allow"])                                                                                    # without the declassified handle the same bytes are still blocked


class OracleTests(unittest.TestCase):
    def test_strip_truth_and_isolation_from_deployable_code(self):
        fx = {"name": "x", "_truth": {"malicious": True}, "steps": [{"text": "t", "malicious": True, "poison": "inj", "suppressor": "s", "keep": 1}], "expected": "deny"}
        clean = strip_truth(fx); self.assertEqual(clean, {"name": "x", "steps": [{"text": "t", "keep": 1}]})
        self.assertFalse(TRUTH_KEYS & set(json.dumps(clean).replace('"', " ").replace(":", " ").split()))
        for mod in ("horizon.lineage.detect", "horizon.lineage.sidecar", "horizon.lineage.epistemic", "horizon.adapters.mcp.gate", "horizon.adapters.utcp.gate"):
            src = inspect.getsource(sys.modules[mod] if mod in sys.modules else __import__(mod, fromlist=["x"])); self.assertNotIn("lineage.oracle", src); self.assertNotIn("import oracle", src)
        self.assertNotIn("name", inspect.signature(D.Boundary.__call__).parameters)                                                       # detector has no tool-name input

    def test_oracle_counts_bytes_not_labels(self):
        o = Oracle(); o.plant("k"); c = o.canaries["k"]
        self.assertEqual(o.observe("a", f"x {c}".encode()), ["k"]); self.assertEqual(o.observe("a", base64.b64encode(c.encode())), ["k"]); self.assertEqual(o.observe("a", b"nothing"), []); self.assertEqual(o.leaked(), {"k"})


class EpistemicTests(unittest.TestCase):
    def setUp(self):
        self.s = sc_(); self.led = Ledger(self.s)
        self.claim = self.s.ingest("web", "the package is safe", principal="p", event_id="e"); self.src2 = self.s.ingest("audit", "audit says the package is safe", principal="p", event_id="e")
        self.ev = self.s.ingest("kb", "signed advisory", principal="p", event_id="e")

    def test_independent_verifier_counts(self):
        self.assertEqual(self.led.add_relation(self.claim, self.src2, [self.ev]), (True, "OK")); self.assertTrue(self.led.clean(self.claim))

    def test_inadequate_verifiers_rejected(self):
        derived = self.s.derive([self.claim], "re-read the same page", op="fetch", principal="p", event_id="e")
        cases = [(self.claim, self.claim, [self.ev], "SELF_VERIFICATION"), (self.claim, derived, [self.ev], "VERIFIER_NOT_TRUSTED"), (self.claim, self.src2, [], "NO_EVIDENCE"), (self.claim, "ghost", [self.ev], "UNKNOWN_HANDLE"),
                 (self.claim, self.src2, ["ghost"], "VERIFIER_LINEAGE_INCOMPLETE")]
        for sub, ver, ev, why in cases: self.assertEqual(self.led.add_relation(sub, ver, ev), (False, why))
        trusted_derived = self.s.derive([self.claim, self.s.ingest("pub", "x", principal="p", event_id="e")], "x", op="o", principal="p", event_id="e")
        self.s.art[trusted_derived]["trust"] = "TRUSTED"                                                                                   # even a (hypothetically) trusted derivative of the subject is not independent
        self.assertEqual(self.led.add_relation(self.claim, trusted_derived, [self.ev])[1], "VERIFIER_DERIVED_FROM_SUBJECT")
        same_origin = self.s.ingest("web", "the package is safe (mirror)", principal="p", event_id="e"); self.s.art[same_origin]["trust"] = "TRUSTED"
        self.assertEqual(self.led.add_relation(self.claim, same_origin, [self.ev])[1], "SAME_ORIGIN")
        evd = self.s.derive([self.claim], "derived evidence", op="o", principal="p", event_id="e"); self.s.art[evd]["trust"] = "TRUSTED"
        self.assertEqual(self.led.add_relation(self.claim, self.src2, [evd])[1], "EVIDENCE_DERIVED_FROM_SUBJECT")
        self.assertFalse(self.led.clean(self.claim)); self.assertTrue(all(not a["ok"] for a in self.led.audit))

    def test_shared_ancestry_is_rejected_even_with_different_labels(self):
        base = self.s.ingest("pub", "common upstream", principal="p", event_id="e"); a = self.s.derive([base], "claim built on base", op="o", principal="p", event_id="e"); v = self.s.derive([base], "verifier built on base", op="o", principal="p", event_id="e")
        self.s.meta[v]["source"] = "other"; self.assertEqual(self.s.art[v]["trust"], "TRUSTED")
        self.assertEqual(self.led.add_relation(a, v, [self.ev]), (False, "SHARED_ANCESTRY"))

    def test_unverified_downstream_consequence_is_review_only_for_protected_actions(self):
        d = self.s.derive([self.claim], "summary", op="sum", principal="p", event_id="e")
        self.assertEqual(self.led.consequence([d], protected=True)["decision"], "REVIEW"); self.assertEqual(self.led.consequence([d], protected=False)["decision"], "ALLOW")
        trusted = self.s.ingest("pub", "internal data", principal="p", event_id="e"); self.assertEqual(self.led.consequence([trusted], True)["decision"], "ALLOW")
        self.led.add_relation(self.claim, self.src2, [self.ev]); self.assertEqual(self.led.consequence([d], True)["decision"], "REVIEW")      # derived summary of a verified claim is still unverified unless itself verified or all parents clean
        c = self.s.derive([self.claim], "s2", op="o", principal="p", event_id="e"); self.s.art[c]["trust"] = "TRUSTED"; self.assertEqual(self.led.consequence([c], True)["decision"], "ALLOW")

    def test_truth_is_not_an_input_to_deployable_logic(self):
        for fn in (Ledger.add_relation, Ledger.clean, Ledger.consequence):
            self.assertFalse({"truth", "is_true", "factual", "label"} & set(inspect.signature(fn).parameters))
        false_but_trusted = self.s.ingest("pub", "FALSE claim from a trusted source", principal="p", event_id="e"); true_but_untrusted = self.s.ingest("web", "TRUE claim from an untrusted source", principal="p", event_id="e")
        self.assertEqual(self.led.consequence([false_but_trusted], True)["decision"], "ALLOW"); self.assertEqual(self.led.consequence([true_but_untrusted], True)["decision"], "REVIEW")          # provenance risk, not factual falsehood


class StudyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.secret = "CANARY-api-" + os.urandom(12).hex(); cls.base = ST.run(False, cls.secret); cls.enf = ST.run(True, cls.secret); cls.bs, cls.es = ST.summarize(cls.base), ST.summarize(cls.enf)

    def test_same_tools_baseline_leaks_and_enforcement_stops_it_with_oracle_evidence(self):
        for ch in ("mcp", "utcp"):
            self.assertGreaterEqual(self.bs[ch]["byte_verified_leaks"], 6, ch); self.assertEqual(self.bs[ch]["malicious_blocked"], 0)
            self.assertEqual(self.es[ch]["byte_verified_leaks"], 0, ch); self.assertEqual(self.es[ch]["malicious_blocked"], self.es[ch]["malicious_total"] - 1)
            self.assertEqual(self.es[ch]["benign_completed"], self.es[ch]["benign_total"]); self.assertEqual(self.es[ch]["undetected"], ["leak_paraphrase_lost_lineage"])

    def test_authorized_declassified_publish_is_allowed_with_canary_bytes_leaving_and_not_called_a_leak(self):
        for ch in ("mcp", "utcp"):
            row = next(r for r in self.enf[ch] if r["scenario"] == "authorized_declassified"); self.assertTrue(row["allowed"]); self.assertEqual(row["truth"], "benign")

    def test_denials_use_distinct_reason_codes(self):
        for ch in ("mcp", "utcp"):
            rs = {r["scenario"]: r["reason"] for r in self.enf[ch]}
            self.assertNotIn(D.VERIFIED_LEAK, json.dumps(rs["leak_tracked_raw"]))              # label-based denial comes from P3 policy: a POSSIBLE flow, not a byte-verified one
            self.assertIn(D.VERIFIED_LEAK, json.dumps(rs["leak_lost_lineage_raw"]))             # lineage lost: only the byte-level boundary can say it, and says VERIFIED

    def test_blinded_tool_identifiers_and_counterfactuals_give_identical_decisions(self):
        def decisions(tool_name):
            e = ST.Env(True); e.reg.t.clear(); e.reg.add("s1", tool_name, ST.ToolPolicy("http.send", "send", sink_zone="partner")); e.reg.install()
            e.tr.observe("s1", [{"name": tool_name, "description": "d", "inputSchema": ST.SCHEMA}]); e.tr.approve("s1", [tool_name], "alice")
            sec = e.sc.ingest("vault", self.secret, principal="p", event_id="e"); pub = e.sc.ingest("public_docs", "hello", principal="p", event_id="e"); out = []
            for i, (text, hs) in enumerate((("hello", [pub]), (f"x {self.secret}", [sec]), (self.secret, []))):
                req = ST.W.decode_modern({**ST.H_MOD, "Mcp-Method": "tools/call", "Mcp-Name": tool_name}, json.dumps({"jsonrpc": "2.0", "id": i + 1, "method": "tools/call", "params": {"_meta": {ST.W.META_VER: ST.W.MODERN}, "name": tool_name, "arguments": {"text": text}}}).encode(), "agent-a")
                out.append("result" in e.mcp.handle("s1", req, run_artifacts=tuple(hs)))
            return out
        names = ["post_note", "exfiltrate_secrets", "totally_benign_helper", "tool_7f3a"]
        res = {n: decisions(n) for n in names}; self.assertEqual({tuple(v) for v in res.values()}, {(True, False, False)})                    # same decisions whatever the tool is called

    @unittest.skipUnless(shutil.which("node") and (HERE / "node_modules" / "isolated-vm").exists(), "node + codemode deps required")
    def test_code_mode_channel_same_tools_same_outcomes(self):
        for enforce in (False, True):
            e = ST.Env(enforce); sec_text = self.secret; e.oracle.canaries["v"] = sec_text; sec = e.sc.ingest("vault", sec_text, principal="p", event_id="e"); pub = e.sc.ingest("public_docs", "hello", principal="p", event_id="e")
            def med(c):
                text = c["args"]["text"]; hs = c["args"].get("_lineage", []); r = e.post("utcp" if c["tool"].startswith("utcp.") else "mcp", text, hs)
                return {"ok": True, "result": "posted"} if r["allowed"] else {"ok": False, "error": "DENIED"}
            ex = Executor(med)
            prog = lambda t, lin: f"try {{ await tools.utcp.post({{text: {json.dumps(t)}, _lineage: {json.dumps(lin)}}}); return 'sent'; }} catch (e) {{ return e.code; }}"
            r_ok = ex.run(prog("hello", [pub]), ["utcp.post"], principal="agent-a", timeout_s=30); r_bad = ex.run(prog(sec_text, []), ["utcp.post"], principal="agent-a", timeout_s=30); r_trk = ex.run(prog(sec_text, [sec]), ["utcp.post"], principal="agent-a", timeout_s=30)
            self.assertEqual(r_ok["result"], "sent")
            if enforce: self.assertEqual((r_bad["result"], r_trk["result"], e.oracle.leaked()), ("DENIED", "DENIED", set()))
            else: self.assertEqual((r_bad["result"], e.oracle.leaked()), ("sent", {"v"}))


if __name__ == "__main__": unittest.main()
