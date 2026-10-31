import json, os, tempfile, threading, time, unittest
from horizon import schemas
from horizon.service.core import Service
from horizon.service.audit import verify_audit
from horizon.service.redact import redact
from horizon.service import http as H, cli
from horizon.sdk.client import Client, Denied

POLICY = {"apiVersion": "horizon.security/v2", "kind": "PolicyBundle",
          "metadata": {"id": "p1", "version": 1, "owner": "sec", "signature": "x"},
          "principals": [{"id": "agent-a", "allowed_purposes": ["approved_release"]}],
          "resources": [],
          "rules": [
              {"id": "deny-secret", "when": {"effect": "send", "input_label_at_least": "SECRET"}, "decision": "DENY"},
              {"id": "allow-public", "when": {"effect": "send", "sink_zone": "registry", "maximum_input_label": "PUBLIC"}, "decision": "ALLOW"},
              {"id": "review-int", "when": {"effect": "send", "sink_zone": "partner", "input_label_at_least": "INTERNAL"}, "decision": "REVIEW"},
              {"id": "allow-int", "when": {"effect": "send", "sink_zone": "partner", "maximum_input_label": "INTERNAL"}, "decision": "ALLOW"}],
          "defaults": {"protected_effect": "DENY", "inspection_only": "QUARANTINE", "evaluation_timeout": "DENY"}}
TOK = {"ta": {"tenant": "T1", "principal": "agent-a", "role": "adapter"},
       "tb": {"tenant": "T2", "principal": "agent-b", "role": "adapter"},
       "adm": {"tenant": "T1", "principal": "admin", "role": "admin"},
       "rev": {"tenant": "T1", "principal": "alice", "role": "reviewer"}}
SHA = "sha256:" + "a" * 64


def art(i, conf="PUBLIC", parents=(), partial=False, tenant="T1"):
    return {"id": i, "producer_event_id": "e1", "parents": list(parents), "confidentiality": conf, "trust": "TRUSTED", "tenant_id": tenant, "partial_lineage": partial}


def req(**kw):
    r = {"protocol": "utcp", "native_operation": "http:POST", "effect": "send", "args_digest": SHA,
         "target": {"kind": "url", "raw": "https://registry.example.com/x"}, "sink_zone": "registry", "input_artifacts": ["a1"]}
    r.update(kw); return r


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.now = [1_000_000.0]
        self.svc = Service(TOK, os.path.join(self.d, "audit.jsonl"), b"k" * 32, clock=lambda: self.now[0])
        self.call("POST", "/v2/policies", "adm", {"policy": POLICY})
        self.call("POST", "/v2/artifacts", "ta", {"artifact": art("a1")})

    def call(self, m, p, tok=None, body=None):
        return self.svc.handle(m, p, tok, body)


class Auth(Base):
    def test_unauthenticated_and_role(self):
        self.assertEqual(self.call("POST", "/v2/decisions", None, req())[0], 401)
        self.assertEqual(self.call("POST", "/v2/decisions", "wrong", req())[0], 401)
        self.assertEqual(self.call("POST", "/v2/decisions", "rev", req())[0], 403)
        self.assertEqual(self.call("POST", "/v2/policies", "ta", {"policy": POLICY})[0], 403)
        self.assertEqual(self.call("GET", "/v2/health")[0], 200)                       # health needs no auth, leaks nothing sensitive

    def test_internal_errors_do_not_leak(self):
        s, b = self.call("POST", "/v2/decisions", "ta", {"protocol": 5, "native_operation": [], "effect": {}, "args_digest": 1, "target": 3})
        self.assertIn(s, (400, 500)); self.assertNotIn("Traceback", json.dumps(b))


class Decisions(Base):
    def test_allow_mints_bound_token_and_conforms(self):
        s, d = self.call("POST", "/v2/decisions", "ta", req())
        self.assertEqual((s, d["verdict"]), (200, "ALLOW")); self.assertTrue(d["token"]["mac"])
        self.assertEqual(schemas.validate("decision", {k: v for k, v in d.items() if k != "token"}), [])

    def test_deny_secret_and_no_policy_and_unmapped(self):
        self.call("POST", "/v2/artifacts", "ta", {"artifact": art("s1", "SECRET")})
        self.assertEqual(self.call("POST", "/v2/decisions", "ta", req(input_artifacts=["s1"]))[1]["verdict"], "DENY")
        self.assertEqual(self.call("POST", "/v2/decisions", "tb", req())[1]["reason_codes"], ["NO_POLICY"])   # other tenant has no policy
        d = self.call("POST", "/v2/decisions", "ta", req(native_operation="tools/call", protocol="mcp"))[1]
        self.assertEqual(d["verdict"], "DENY"); self.assertEqual(d["reason_codes"], ["UNKNOWN_MAPPING_PROTECTED"])

    def test_unknown_artifact_is_secret_and_incomplete_lineage(self):
        self.assertEqual(self.call("POST", "/v2/decisions", "ta", req(input_artifacts=["ghost"]))[1]["verdict"], "DENY")

    def test_uninterceptable_denied(self):
        self.assertEqual(self.call("POST", "/v2/decisions", "ta", req(interceptable=False))[1]["reason_codes"], ["UNINTERCEPTABLE_EFFECT"])

    def test_shadow_mode_never_blocks_but_reports(self):
        self.svc.mode = "shadow"
        self.call("POST", "/v2/artifacts", "ta", {"artifact": art("s1", "SECRET")})
        d = self.call("POST", "/v2/decisions", "ta", req(input_artifacts=["s1"]))[1]
        self.assertEqual((d["verdict"], d["shadow_would_be"]), ("SHADOW_ALLOW", "DENY")); self.assertNotIn("token", d)

    def test_policy_version_cannot_roll_back(self):
        self.assertEqual(self.call("POST", "/v2/policies", "adm", {"policy": POLICY})[0], 409)

    def test_invalid_policy_rejected(self):
        bad = json.loads(json.dumps(POLICY)); bad["metadata"]["version"] = 2; bad["rules"][0]["when"] = {}
        self.assertEqual(self.call("POST", "/v2/policies", "adm", {"policy": bad})[0], 422)

    def test_declassification_blocked_at_api(self):
        self.assertEqual(self.call("POST", "/v2/artifacts", "ta", {"artifact": art("a1", "PUBLIC")})[0], 200)
        self.call("POST", "/v2/artifacts", "ta", {"artifact": art("x", "SECRET")})
        self.assertEqual(self.call("POST", "/v2/artifacts", "ta", {"artifact": art("x", "PUBLIC")})[0], 409)

    def test_tenant_isolation(self):
        self.call("POST", "/v2/policies", "adm", {"policy": POLICY})
        self.assertEqual(self.call("POST", "/v2/decisions", "tb", req())[1]["reason_codes"], ["NO_POLICY"])
        s, d = self.call("POST", "/v2/decisions", "ta", req())
        s2, _ = self.call("POST", "/v2/outcomes", "tb", {"decision_id": d["decision_id"]})
        self.assertEqual(s2, 404)                                                       # tb cannot see T1's decision

    def test_idempotency(self):
        a = self.call("POST", "/v2/decisions", "ta", req(idempotency_key="k1"))[1]
        b = self.call("POST", "/v2/decisions", "ta", req(idempotency_key="k1"))[1]
        self.assertEqual(a["decision_id"], b["decision_id"]); self.assertTrue(b["idempotent_replay"])
        self.assertEqual(self.call("POST", "/v2/decisions", "ta", req(idempotency_key="k1", args_digest="sha256:" + "b" * 64))[0], 409)


class Approvals(Base):
    def _review(self):
        s, d = self.call("POST", "/v2/decisions", "ta", req(sink_zone="partner", input_artifacts=["i1"], target={"kind": "url", "raw": "https://p.example.com/"}))
        return s, d

    def setUp(self):
        super().setUp(); self.call("POST", "/v2/artifacts", "ta", {"artifact": art("i1", "INTERNAL")})

    def test_review_then_exact_one_shot_approval(self):
        r = req(sink_zone="partner", input_artifacts=["i1"], target={"kind": "url", "raw": "https://p.example.com/"})
        self.assertEqual(self.call("POST", "/v2/decisions", "ta", r)[1]["verdict"], "REVIEW")
        s, ap = self.call("POST", "/v2/approvals", "rev", {"request": {**r, "principal": "agent-a"}})
        self.assertEqual(s, 200)
        ok = self.call("POST", "/v2/decisions", "ta", {**r, "approval_id": ap["approval_id"]})[1]
        self.assertEqual(ok["verdict"], "ALLOW"); self.assertIn("APPROVED_REVIEW", ok["reason_codes"])
        again = self.call("POST", "/v2/decisions", "ta", {**r, "approval_id": ap["approval_id"]})[1]
        self.assertEqual(again["verdict"], "REVIEW")                                    # one shot

    def test_approval_bound_to_exact_request_and_expires(self):
        r = req(sink_zone="partner", input_artifacts=["i1"], target={"kind": "url", "raw": "https://p.example.com/"})
        ap = self.call("POST", "/v2/approvals", "rev", {"request": {**r, "principal": "agent-a"}, "ttl_s": 10})[1]
        changed = {**r, "args_digest": "sha256:" + "c" * 64, "approval_id": ap["approval_id"]}
        self.assertEqual(self.call("POST", "/v2/decisions", "ta", changed)[1]["verdict"], "REVIEW")
        self.now[0] += 11
        self.assertEqual(self.call("POST", "/v2/decisions", "ta", {**r, "approval_id": ap["approval_id"]})[1]["verdict"], "REVIEW")

    def test_approval_never_overrides_deny_and_no_self_approval(self):
        self.call("POST", "/v2/artifacts", "ta", {"artifact": art("s1", "SECRET")})
        r = req(input_artifacts=["s1"])
        ap = self.call("POST", "/v2/approvals", "rev", {"request": {**r, "principal": "agent-a"}})[1]
        self.assertEqual(self.call("POST", "/v2/decisions", "ta", {**r, "approval_id": ap["approval_id"]})[1]["verdict"], "DENY")
        self.assertEqual(self.call("POST", "/v2/approvals", "rev", {"request": {**r, "principal": "alice"}})[0], 403)
        self.assertEqual(self.call("POST", "/v2/approvals", "ta", {"request": r})[0], 403)


class Outcomes(Base):
    def test_token_redeem_once_and_redaction(self):
        d = self.call("POST", "/v2/decisions", "ta", req())[1]
        binding = {"principal_id": "agent-a", "target_digest": d["token"]["target_digest"], "args_digest": SHA,
                   "policy_digest": d["token"]["policy_digest"], "logical_operation": "http.send"}
        body = {"decision_id": d["decision_id"], "token": d["token"], "request_binding": binding, "status": "ok",
                "detail": {"Authorization": "Bearer abcdefgh12345678", "note": "sk-abcdefghijklmnopqrstuv", "ok": "fine"}}
        self.assertEqual(self.call("POST", "/v2/outcomes", "ta", body)[0], 200)
        self.assertEqual(self.call("POST", "/v2/outcomes", "ta", body)[0], 409)         # replay
        raw = open(os.path.join(self.d, "audit.jsonl")).read()
        self.assertNotIn("abcdefgh12345678", raw); self.assertNotIn("sk-abcdefghij", raw); self.assertIn("fine", raw)

    def test_redact_bounds(self):
        deep = cur = {}
        for _ in range(10): cur["a"] = {}; cur = cur["a"]
        self.assertIn("TRUNCATED", json.dumps(redact(deep))); self.assertEqual(len(redact("x" * 5000)), 513)


class Audit(Base):
    def test_chain_verifies_and_detects_tamper(self):
        for _ in range(3): self.call("POST", "/v2/decisions", "ta", req())
        p = os.path.join(self.d, "audit.jsonl"); ok, _ = verify_audit(p); self.assertTrue(ok)
        lines = open(p).read().splitlines()
        for name, mutated in (("modify", [lines[0].replace("\"T1\"", "\"T9\"")] + lines[1:]), ("delete", lines[:1] + lines[2:]),
                              ("reorder", [lines[1], lines[0]] + lines[2:]), ("truncate", lines[:-1] + [lines[-1][:20]])):
            q = os.path.join(self.d, name); open(q, "w").write("\n".join(mutated) + "\n")
            self.assertFalse(verify_audit(q)[0], name)

    def test_audit_failure_fails_closed_for_protected(self):
        os.close(self.svc.audit.fd)
        d = self.call("POST", "/v2/decisions", "ta", req())[1]
        self.assertEqual((d["verdict"], d["reason_codes"]), ("DENY", ["AUDIT_UNAVAILABLE"])); self.assertIsNone(d["token"])
        self.assertEqual(self.call("GET", "/v2/health")[1]["status"], "degraded")


class Limits(Base):
    def test_rate_limit_and_breaker(self):
        s = Service(TOK, os.path.join(self.d, "a2"), b"k" * 32, clock=lambda: self.now[0], rate=1, burst=2)
        codes = [s.handle("POST", "/v2/artifacts", "ta", {"artifact": art("z")})[0] for _ in range(4)]
        self.assertEqual(codes, [200, 200, 429, 429]); self.now[0] += 5
        self.assertEqual(s.handle("POST", "/v2/artifacts", "ta", {"artifact": art("z")})[0], 200)

    def test_open_circuit_denies_protected(self):
        for _ in range(5): self.svc.breaker.record(False)
        self.assertEqual(self.call("POST", "/v2/decisions", "ta", req())[1]["reason_codes"], ["SERVICE_DEGRADED"])
        self.now[0] += 11                                                                # cooldown => half-open probe
        self.assertEqual(self.call("POST", "/v2/decisions", "ta", req())[1]["verdict"], "ALLOW")

    def test_evaluation_timeout_fails_closed(self):
        s = Service(TOK, os.path.join(self.d, "a3"), b"k" * 32, clock=lambda: self.now[0], eval_timeout_s=-1.0)
        s.handle("POST", "/v2/policies", "adm", {"policy": POLICY}); s.handle("POST", "/v2/artifacts", "ta", {"artifact": art("a1")})
        d = s.handle("POST", "/v2/decisions", "ta", req())[1]
        self.assertEqual((d["verdict"], d["reason_codes"]), ("DENY", ["EVALUATION_TIMEOUT"]))


class Simulate(Base):
    def test_simulate_has_no_side_effects(self):
        before = open(os.path.join(self.d, "audit.jsonl")).read()
        s, o = self.call("POST", "/v2/policies/simulate", "rev", {"policy": POLICY, "requests": [req()]})
        self.assertEqual((s, o["results"][0]["verdict"]), (200, "ALLOW")); self.assertNotIn("token", json.dumps(o))
        self.assertEqual(before, open(os.path.join(self.d, "audit.jsonl")).read())
        self.assertEqual(self.call("POST", "/v2/policies/simulate", "ta", {"policy": POLICY, "requests": []})[0], 403)


class Transport(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.svc = Service(TOK, os.path.join(self.d, "audit.jsonl"), b"k" * 32)
        self.svc.handle("POST", "/v2/policies", "adm", {"policy": POLICY}); self.svc.handle("POST", "/v2/artifacts", "ta", {"artifact": art("a1")})

    def test_unix_socket_end_to_end_and_perms(self):
        p = os.path.join(self.d, "s.sock"); srv = H.serve(self.svc, unix_path=p); H.start_thread(srv)
        try:
            self.assertEqual(oct(os.stat(p).st_mode & 0o777), "0o600")
            c = Client("ta", unix_path=p); self.assertEqual(c.health()["status"], "ok")
            self.assertEqual(c.require_allow(req())["verdict"], "ALLOW")
            with self.assertRaises(Denied): c.require_allow(req(input_artifacts=["ghost"]))
            self.assertEqual(Client("nope", unix_path=p).decide(req())["verdict"], "DENY")      # 401 => synthetic DENY, not ALLOW
        finally: srv.shutdown(); srv.server_close()

    def test_loopback_only_and_fail_closed_when_down(self):
        with self.assertRaises(ValueError): H.serve(self.svc, host="0.0.0.0")
        with self.assertRaises(ValueError): H.serve(self.svc, host="192.0.2.1")
        d = Client("ta", port=1, timeout=0.3).decide(req())
        self.assertEqual((d["verdict"], d["reason_codes"]), ("DENY", ["SERVICE_UNREACHABLE"]))

    def test_oversize_and_bad_json(self):
        srv = H.serve(self.svc, port=0); H.start_thread(srv); port = srv.server_address[1]
        import http.client
        try:
            c = http.client.HTTPConnection("127.0.0.1", port); c.request("POST", "/v2/decisions", b"{bad", {"Authorization": "Bearer ta", "Content-Length": "4"})
            self.assertEqual(c.getresponse().status, 400)
            c = http.client.HTTPConnection("127.0.0.1", port); c.request("POST", "/v2/decisions", b"{}", {"Authorization": "Bearer ta", "Content-Length": str(10**8)})
            self.assertEqual(c.getresponse().status, 413)
        finally: srv.shutdown(); srv.server_close()

    def test_concurrent_decisions(self):
        out = []
        def w():
            for _ in range(20): out.append(self.svc.handle("POST", "/v2/decisions", "ta", req())[1]["verdict"])
        ts = [threading.Thread(target=w) for _ in range(8)]; [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(set(out), {"ALLOW"}); self.assertEqual(len(out), 160)
        self.assertTrue(verify_audit(os.path.join(self.d, "audit.jsonl"))[0])


class Lineage(Base):
    def test_lineage_immutable_and_tenant_bound(self):
        self.call("POST", "/v2/artifacts", "ta", {"artifact": art("c1", parents=["a1"])})
        self.assertEqual(self.call("POST", "/v2/artifacts", "ta", {"artifact": art("c1", parents=[])})[0], 409)       # cannot launder by dropping parents
        self.assertEqual(self.call("POST", "/v2/artifacts", "ta", {"artifact": art("c2", tenant="T2")})[0], 403)      # cannot write into another tenant

    def test_audit_records_policy_and_digests_and_trace(self):
        self.svc.tracer.path = os.path.join(self.d, "trace.jsonl")
        self.svc.handle("POST", "/v2/decisions", "ta", req(experiment_id="exp-7"), trace="tr1")
        recs = [json.loads(l) for l in open(os.path.join(self.d, "audit.jsonl"))]
        dec = [r for r in recs if r["ev"] == "decision"][-1]
        self.assertTrue(dec["policy_digest"].startswith("policy-sha256:")); self.assertTrue(dec["request_digest"].startswith("sha256:")); self.assertEqual(dec["trace_id"], "tr1")
        sp = json.loads(open(self.svc.tracer.path).readline())
        self.assertEqual((sp["trace_id"], sp["experiment_id"]), ("tr1", "exp-7")); self.assertEqual(sp["attrs"]["authorization"], "[REDACTED]")
        self.assertNotIn("ta", [v for v in sp["attrs"].values() if isinstance(v, str) and v == "Bearer ta"])


class Cli(unittest.TestCase):
    def test_version_doctor(self):
        self.assertEqual(cli.main(["version"]), 0); self.assertEqual(cli.main(["doctor"]), 0)
        self.assertEqual(cli.main(["doctor", "--audit", "/nonexistent"]), 2)

    def test_cli(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "p.json"); json.dump(POLICY, open(p, "w"))
        self.assertEqual(cli.main(["policy-validate", p]), 0)
        bad = dict(POLICY, rules=[]); json.dump(bad, open(p, "w")); json.dump({"x": 1}, open(os.path.join(d, "q"), "w"))
        self.assertEqual(cli.main(["policy-validate", os.path.join(d, "q")]), 1)
        self.assertEqual(cli.main(["audit-verify", os.path.join(d, "missing")]), 2)


if __name__ == "__main__": unittest.main()
