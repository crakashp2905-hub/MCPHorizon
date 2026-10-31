"""Transport-independent decision service (P3-02..P3-20). The HTTP layer only parses/frames; all logic is here so it is testable.

Trust model: the caller authenticates with a bearer token mapped to (tenant, principal, role). Only role "adapter" may assert
interception facts; request bodies never carry trusted context such as identity_valid or approval validity.
Fail-closed: any internal error, timeout, open circuit or audit-write failure on a protected effect => DENY (never ALLOW).
Stores are in-memory; persistence/HA is out of scope for this candidate (see BLOCKERS)."""
from __future__ import annotations
import hashlib, hmac, json, threading, time, uuid
from .. import schemas, normalize
from ..core import decide as D, tokens as T
from ..core.labels import C
from .audit import AuditLog
from .limits import RateLimiter, Breaker
from .redact import redact
from .trace import Tracer

PROTECTED = frozenset({"write", "modify", "delete", "execute", "send", "admin"})   # subset of the policy schema effect vocabulary; read/list/receive are inspection-only
API = "v2"
MAX_BODY = 1 << 20


class ApiError(Exception):
    def __init__(self, status: int, code: str, msg: str, retryable: bool = False):
        super().__init__(msg); self.status, self.code, self.msg, self.retryable = status, code, msg, retryable

    def body(self) -> dict:
        return {"error": {"code": self.code, "message": self.msg, "retryable": self.retryable}}


def _sha(o) -> str: return "sha256:" + hashlib.sha256(json.dumps(o, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
def _iso(t: float) -> str: return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


class Tenant:
    def __init__(self, key: bytes):
        self.policy: dict | None = None; self.policy_digest: str | None = None
        self.artifacts: dict[str, dict] = {}; self.redeemer = T.Redeemer(key)
        self.approvals: dict[str, dict] = {}; self.decisions: dict[str, dict] = {}; self.idem: dict[str, dict] = {}
        self.lock = threading.Lock()


class Service:
    def __init__(self, tokens: dict[str, dict], audit_path: str, token_key: bytes, clock=time.time,
                 rate: float = 100.0, burst: int = 200, eval_timeout_s: float = 2.0, mode: str = "enforce", trace_path: str | None = None):
        """tokens: {bearer_secret: {"tenant":..., "principal":..., "role": "adapter"|"admin"|"reviewer"}}"""
        self.tokens, self.clock, self.key, self.timeout, self.mode = tokens, clock, token_key, eval_timeout_s, mode
        self.tenants: dict[str, Tenant] = {}; self.audit = AuditLog(audit_path)
        self.rl = RateLimiter(rate, burst, clock); self.breaker = Breaker(5, 10.0, clock)
        self.tracer = Tracer(trace_path); self.metrics = {"requests": 0, "decisions": {}, "errors": 0}; self.ml = threading.Lock()

    # ---- auth / plumbing
    def auth(self, bearer: str | None) -> dict:
        if bearer:
            for secret, who in self.tokens.items():
                if hmac.compare_digest(secret, bearer): return who          # constant-time per candidate
        raise ApiError(401, "UNAUTHENTICATED", "missing or invalid credentials")

    def tenant(self, name: str) -> Tenant:
        return self.tenants.setdefault(name, Tenant(self.key + name.encode()))

    def handle(self, method: str, path: str, bearer: str | None, body: dict | None, trace: str | None = None) -> tuple[int, dict]:
        trace = trace or uuid.uuid4().hex
        with self.ml: self.metrics["requests"] += 1
        try:
            if (method, path) == ("GET", "/v2/health"): return 200, self.health()
            who = self.auth(bearer)
            if not self.rl.allow(who["tenant"] + "/" + who["principal"]):
                raise ApiError(429, "RATE_LIMITED", "rate limit exceeded", True)
            routes = {("POST", "/v2/decisions"): lambda w, b: self.decisions(w, b, trace), ("POST", "/v2/outcomes"): self.outcomes,
                      ("POST", "/v2/artifacts"): self.artifacts, ("POST", "/v2/policies"): self.policies_put,
                      ("POST", "/v2/policies/validate"): self.policies_validate, ("POST", "/v2/policies/simulate"): self.policies_simulate,
                      ("POST", "/v2/approvals"): self.approvals, ("GET", "/v2/metrics"): lambda w, b: self.metrics}
            fn = routes.get((method, path))
            if fn is None: raise ApiError(404, "NOT_FOUND", "no such route")
            if method == "POST" and not isinstance(body, dict): raise ApiError(400, "BAD_REQUEST", "body must be a JSON object")
            t0 = self.clock(); out = fn(who, body or {})
            self.tracer.span(path, trace, t0, self.clock(), {"tenant": who["tenant"], "principal": who["principal"], "verdict": out.get("verdict") if isinstance(out, dict) else None,
                                                             "authorization": "Bearer " + (bearer or "")}, (body or {}).get("experiment_id"))
            return 200, out
        except ApiError as e:
            with self.ml: self.metrics["errors"] += 1
            return e.status, {**e.body(), "trace_id": trace}
        except Exception:                                              # never leak internals; fail closed
            with self.ml: self.metrics["errors"] += 1
            return 500, {"error": {"code": "INTERNAL", "message": "internal error", "retryable": False}, "trace_id": trace}

    def health(self) -> dict:
        ok = self.audit.writable()
        return {"status": "ok" if ok else "degraded", "api": API, "audit_writable": ok, "breaker_open": self.breaker.is_open()}

    @staticmethod
    def _need(who, *roles):
        if who["role"] not in roles: raise ApiError(403, "FORBIDDEN", f"role {who['role']!r} may not call this endpoint")

    def close(self) -> None: self.audit.close()

    def _audit(self, rec: dict) -> None:
        rec = {**rec, "t": self.clock()}
        try: self.audit.write(rec)
        except OSError as e: raise ApiError(503, "AUDIT_UNAVAILABLE", "audit log not writable", True) from e

    # ---- policies
    def policies_validate(self, who, b):
        self._need(who, "admin", "reviewer")
        errs = schemas.validate("policy", b.get("policy"))
        return {"valid": not errs, "errors": errs[:50]}

    def policies_put(self, who, b):
        self._need(who, "admin")
        pol = b.get("policy"); errs = schemas.validate("policy", pol)
        if errs: raise ApiError(422, "POLICY_INVALID", "; ".join(errs[:5]))
        t = self.tenant(who["tenant"])
        if t.policy and pol["metadata"]["version"] <= t.policy["metadata"]["version"]:
            raise ApiError(409, "POLICY_VERSION_NOT_NEWER", "policy version must increase (no silent rollback)")
        with t.lock: t.policy, t.policy_digest = pol, T.policy_digest(pol)
        self._audit({"ev": "policy_put", "tenant": who["tenant"], "by": who["principal"], "digest": t.policy_digest})
        return {"policy_digest": t.policy_digest}

    def policies_simulate(self, who, b):
        """Evaluate hypothetical requests against a candidate policy. Never mints tokens, never writes state."""
        self._need(who, "admin", "reviewer")
        pol = b.get("policy"); errs = schemas.validate("policy", pol)
        if errs: raise ApiError(422, "POLICY_INVALID", "; ".join(errs[:5]))
        reqs = b.get("requests")
        if not isinstance(reqs, list) or len(reqs) > 100: raise ApiError(400, "BAD_REQUEST", "requests must be a list of <=100")
        t = self.tenant(who["tenant"]); out = []
        for r in reqs:
            ctx, _ = self._context(who, r, t, simulated=True)
            out.append(D.decide(pol, ctx))
        return {"results": out, "simulated": True}

    # ---- artifacts
    def artifacts(self, who, b):
        self._need(who, "adapter", "admin")
        errs = schemas.validate("artifact", b.get("artifact"))
        if errs: raise ApiError(422, "ARTIFACT_INVALID", "; ".join(errs[:5]))
        a = b["artifact"]; t = self.tenant(who["tenant"])
        with t.lock:
            old = t.artifacts.get(a["id"])
            if old and (old["parents"] != a["parents"] or old["tenant_id"] != a["tenant_id"] or old["producer_event_id"] != a["producer_event_id"]):
                raise ApiError(409, "LINEAGE_IMMUTABLE", "artifact identity, producer and parents cannot change after creation")
            if a["tenant_id"] != who["tenant"]: raise ApiError(403, "FORBIDDEN", "artifact tenant does not match caller tenant")
            if old and C[a["confidentiality"]] < C[old["confidentiality"]]:
                raise ApiError(409, "DECLASSIFICATION_FORBIDDEN", "lowering confidentiality requires a signed declassification path")
            t.artifacts[a["id"]] = a
        return {"id": a["id"], "stored": True}

    # ---- decisions
    def _context(self, who, r: dict, t: Tenant, simulated=False) -> tuple[dict, dict]:
        for k in ("protocol", "native_operation", "effect", "args_digest", "target"):
            if k not in r: raise ApiError(400, "BAD_REQUEST", f"missing field {k}")
        mapping_complete = True; lop = None
        try: lop = normalize.logical_operation(r["protocol"], r["native_operation"], r.get("tool_id"))
        except normalize.Unmapped: mapping_complete = False
        try:
            tgt = normalize.canonical_target(r["target"].get("kind", ""), r["target"].get("raw", ""))
            tdig = normalize.target_digest(tgt)
        except Exception:
            tgt, tdig, mapping_complete = None, "sha256:" + "0" * 64, False        # un-normalizable target: incomplete mapping
        ids = list(r.get("input_artifacts", []))[:200]
        arts = t.artifacts
        labels = [schemas.effective_confidentiality(i, arts) for i in ids]
        eff_label = max(labels, key=lambda x: C[x], default="PUBLIC")
        lineage = all(schemas.lineage_complete(i, arts) for i in ids)
        pol = t.policy
        authorized = False
        if pol and r.get("purpose"):
            pr = next((p for p in pol.get("principals", []) if p["id"] == who["principal"]), None)
            authorized = bool(pr and r["purpose"] in pr.get("allowed_purposes", []))
        is_adapter = who["role"] == "adapter"
        ctx = {"identity_valid": True, "mapping_complete": mapping_complete,
               "interceptable": bool(r.get("interceptable", True)) if (is_adapter or simulated) else False,
               "protected_effect": r["effect"] in PROTECTED, "effect": r["effect"], "sink_zone": r.get("sink_zone"),
               "purpose": r.get("purpose"), "input_label": eff_label, "lineage_complete": lineage,
               "authorized_flow": authorized, "approval": None}
        return ctx, {"logical_operation": lop, "target_digest": tdig, "target": tgt}

    def decisions(self, who, b, trace=None):
        self._need(who, "adapter")
        t = self.tenant(who["tenant"])
        did = uuid.uuid4().hex; started = self.clock()
        ik = b.get("idempotency_key")
        if ik:
            with t.lock:
                if ik in t.idem:
                    prev = t.idem[ik]
                    if prev["fingerprint"] != _sha({k: v for k, v in b.items() if k != "idempotency_key"}):
                        raise ApiError(409, "IDEMPOTENCY_KEY_REUSED", "idempotency key reused with a different request")
                    return {**prev["response"], "idempotent_replay": True}
        ctx, meta = self._context(who, b, t)
        if t.policy is None:
            ctx_protected = ctx["protected_effect"]
            res = {"verdict": "DENY" if ctx_protected else "UNKNOWN", "reason_codes": ["NO_POLICY"], "rule": None}
        elif self.breaker.is_open():
            res = {"verdict": "DENY" if ctx["protected_effect"] else "UNKNOWN", "reason_codes": ["SERVICE_DEGRADED"], "rule": None}
        else:
            ap = t.approvals.get(b.get("approval_id", ""))
            if ap and ap["used"] is False and ap["bound"] == self._bind(who, b, meta, t) and ap["expires_at"] > self.clock():
                ctx["approval"] = {"valid": True}
            try:
                res = D.decide(t.policy, ctx); self.breaker.record(True)
            except Exception:
                self.breaker.record(False)
                res = {"verdict": "DENY", "reason_codes": ["EVALUATION_ERROR"], "rule": None}
            if self.clock() - started > self.timeout:                                   # evaluation exceeded its budget
                res = {"verdict": "DENY", "reason_codes": ["EVALUATION_TIMEOUT"], "rule": None}
        verdict = res["verdict"]
        out = {"schema_version": "2.0.0", "decision_id": did, "policy_version": t.policy_digest or "none",
               "event_id": str(b.get("event_id") or did), "verdict": verdict, "reason_codes": res["reason_codes"],
               "mode": self.mode, "required_approval": ({"kind": "human"} if verdict == "REVIEW" else None)}
        if verdict == "ALLOW" and ctx["approval"]:
            ap = t.approvals[b["approval_id"]]; ap["used"] = True                        # one-shot
        if self.mode == "shadow" and verdict != "ALLOW":
            out["verdict"] = "SHADOW_ALLOW"; out["shadow_would_be"] = verdict
        if verdict == "ALLOW":
            req = {"principal_id": who["principal"], "target_digest": meta["target_digest"], "args_digest": b["args_digest"],
                   "policy_digest": t.policy_digest, "logical_operation": meta["logical_operation"]}
            tok = T.mint(t.redeemer.key, req, self.clock())
            out["token"] = tok; out["expires_at"] = _iso(tok["expires_at"])
            out.update({"bound_target_digest": meta["target_digest"], "bound_args_digest": b["args_digest"], "approved_principal": who["principal"]})
            if ik: out["idempotency_key"] = ik
        errs = schemas.validate("decision", {k: v for k, v in out.items() if k not in ("token", "shadow_would_be")})
        if errs: raise ApiError(500, "INTERNAL", "decision failed schema validation")
        try:
            self._audit({"ev": "decision", "tenant": who["tenant"], "principal": who["principal"], "decision_id": did,
                         "verdict": verdict, "codes": res["reason_codes"], "policy_digest": t.policy_digest, "request_digest": _sha({k: v for k, v in b.items() if k != "idempotency_key"}), "trace_id": trace, "target_digest": meta["target_digest"],
                         "args_digest": b["args_digest"], "effect": b["effect"]})
        except ApiError:
            if ctx["protected_effect"]:                                                  # cannot record => cannot allow
                deny = {k: v for k, v in out.items() if k not in ("token", "expires_at", "bound_target_digest", "bound_args_digest", "approved_principal", "idempotency_key")}
                return {**deny, "verdict": "DENY", "reason_codes": ["AUDIT_UNAVAILABLE"], "token": None}
            raise
        with self.ml: self.metrics["decisions"][verdict] = self.metrics["decisions"].get(verdict, 0) + 1
        t.decisions[did] = {"verdict": verdict, "principal": who["principal"]}
        if ik:
            with t.lock: t.idem[ik] = {"fingerprint": _sha({k: v for k, v in b.items() if k != "idempotency_key"}), "response": out}
        return out

    def _bind(self, who, b, meta, t) -> dict:
        return {"principal": who["principal"], "target_digest": meta["target_digest"], "args_digest": b["args_digest"],
                "logical_operation": meta["logical_operation"], "policy_digest": t.policy_digest}

    # ---- approvals (human reviewer only; bound to the exact request, one shot, expiring)
    def approvals(self, who, b):
        self._need(who, "reviewer")
        t = self.tenant(who["tenant"]); r = b.get("request")
        if not isinstance(r, dict): raise ApiError(400, "BAD_REQUEST", "request required")
        subject = r.get("principal") or ""
        if subject == who["principal"]: raise ApiError(403, "SELF_APPROVAL", "a principal cannot approve its own request")
        _, meta = self._context({"principal": subject, "role": "adapter", "tenant": who["tenant"]}, r, t)
        aid = uuid.uuid4().hex; ttl = min(float(b.get("ttl_s", 300)), 900.0)
        t.approvals[aid] = {"bound": {"principal": subject, "target_digest": meta["target_digest"], "args_digest": r["args_digest"],
                                      "logical_operation": meta["logical_operation"], "policy_digest": t.policy_digest},
                            "expires_at": self.clock() + ttl, "used": False, "by": who["principal"]}
        self._audit({"ev": "approval", "tenant": who["tenant"], "by": who["principal"], "approval_id": aid, "subject": subject})
        return {"approval_id": aid, "expires_at": _iso(self.clock() + ttl)}

    # ---- outcomes (post-effect report; redacted)
    def outcomes(self, who, b):
        self._need(who, "adapter")
        did = b.get("decision_id"); t = self.tenant(who["tenant"])
        if did not in t.decisions: raise ApiError(404, "UNKNOWN_DECISION", "no such decision for this tenant")
        if t.decisions[did]["principal"] != who["principal"]: raise ApiError(403, "FORBIDDEN", "decision belongs to another principal")
        tok = b.get("token"); ok = None
        if tok and isinstance(b.get("request_binding"), dict):
            ok, why = t.redeemer.redeem(tok, b["request_binding"], self.clock(), b.get("idempotency_key"))
            if not ok: raise ApiError(409, "TOKEN_REJECTED", why)
        self._audit({"ev": "outcome", "tenant": who["tenant"], "decision_id": did, "status": str(b.get("status", ""))[:32],
                     "detail": redact(b.get("detail"))})
        return {"recorded": True, "token_redeemed": ok}
