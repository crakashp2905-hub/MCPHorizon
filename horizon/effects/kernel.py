"""PR-04 (masterplan M3): ONE commit pipeline for every sink kind (file, network, process), replacing per-sink copies of the same sequence.
Order, identical for all sinks: bind payload to the permit's args -> ledger.request (duplicates never re-verify/re-run) -> verify the single-use permit -> commit-time gate (deny-only) -> authorize (spends the nonce)
-> begin -> perform through the sink adapter (which calls the broker, which re-checks its own policy) -> finish. Outcomes map to the contracts error table; UNKNOWN is never coerced and never retried here.
Adapters own only translation between a typed payload and the broker call, plus (optionally) a `witness`: an observation of the receiving side used by reconcile. Without a witness an UNKNOWN effect STAYS UNKNOWN.
CANDIDATE / honest limit: in-process library over local brokers; the receiver witness for net is whatever the caller supplies (no real internet receiver, no independent observer here); brokers still rely on the sandbox for mandatory use (masterplan section 12)."""
from __future__ import annotations
import hashlib, json, time
from dataclasses import dataclass, fields
from horizon import normalize as N
from horizon.authz.gateway import ProofError, Verifier
from horizon.authz.keys import TrustStore
from horizon.contracts.v1 import CanonicalEffectV1, ContractError, EFFECT_CLASSES, EMPTY_CHAIN, EffectReceiptV1, EffectState, SCHEMA_VERSION
from horizon.contracts.v1.messages import WITNESS_KINDS
from horizon.contracts.v1 import errors as ER
from horizon.effects.canonical import CanonicalEffect, commit_verify
from horizon.effects.filesink import FileSink, SinkError
from horizon.effects.ledger import EffectLedger, LedgerError
from horizon.effects.netbroker import NetBroker, NetBrokerError
from horizon.effects.procbroker import ProcBroker, ProcBrokerError


def _h(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
def _j(o) -> str: return _h(json.dumps(o, sort_keys=True, separators=(",", ":")).encode())


class Outcome:
    """Result shape: status in ALLOW_COMMITTED|BLOCKED|UNKNOWN|DUPLICATE; `effect` is HAPPENED|DID_NOT_HAPPEN|UNDETERMINED from the contract table (never guessed)."""
    @staticmethod
    def make(status, code="", **kw):
        effect = {"ALLOW_COMMITTED": "HAPPENED", "UNKNOWN": "UNDETERMINED"}.get(status)
        if effect is None: effect = "DID_NOT_HAPPEN" if status in ("BLOCKED", "DUPLICATE") else "UNDETERMINED"
        if status == "BLOCKED" and code and ER.lookup(code).effect == "UNDETERMINED": effect = "UNDETERMINED"       # table is authoritative when it says the effect may have happened
        return {"status": status, "code": code, "effect": effect, **kw}


# ---- adapters ---------------------------------------------------------------------------------------------------------------------------------------------
class FileAdapter:
    effect, target_kind = "write", "file"
    witness_id, witness_kind = "filesink:journal", "sink-journal"          # the protected sink's own hash-chained journal, a separate component from the agent and the gateway code path
    def __init__(self, sink: FileSink): self.sink = sink
    def target(self, p): return p["path"]
    def args(self, p): return {"sha256": _h(p["data"])}
    def perform(self, p, effect_id):
        try: rec = self.sink.write(p["path"], p["data"], effect_id)
        except SinkError as e: raise _Refused(e.code, started=_started(e.code))
        return {"sha256": rec["sha256"], "sink_receipt": rec}
    reconcile_kind = "sink-journal"
    def witness(self, effect_id):
        obs = self.sink.fence_and_observe(effect_id); return bool(obs and obs["present_now"])



def _started(code: str) -> bool: return ER.lookup(code).effect != "DID_NOT_HAPPEN"      # contract table decides; an unknown code is treated as possibly-happened (fail closed)


class NetAdapter:
    effect, target_kind = "send", "url"
    witness_id, witness_kind = "netbroker:report", "broker-report"           # the broker's own report of what it did; NOT an independent receiver observation
    def __init__(self, broker: NetBroker, witness=None, *, witness_kind: str = "caller-supplied"): self.broker, self._w, self.reconcile_kind = broker, witness, witness_kind
    def target(self, p): return p["url"]
    def args(self, p): return {"method": p["method"], "body_sha256": _h(p.get("body", b"")), "headers_sha256": _j(sorted((p.get("headers") or {}).items()))}
    def perform(self, p, effect_id):
        try: status, data = self.broker.request(p["method"], p["url"], p.get("headers"), p.get("body", b""))
        except NetBrokerError as e: raise _Refused(e.code, started=_started(e.code))
        return {"http_status": status, "response_sha256": _h(data), "response_len": len(data)}
    def witness(self, effect_id): return None if self._w is None else self._w(effect_id)


class ProcAdapter:
    effect, target_kind = "execute", "process"
    witness_id, witness_kind = "procbroker:report", "broker-report"
    def __init__(self, broker: ProcBroker, witness=None, *, witness_kind: str = "caller-supplied"): self.broker, self._w, self.reconcile_kind = broker, witness, witness_kind
    def target(self, p): return "proc:" + p["argv"][0]
    def args(self, p): return {"argv": list(p["argv"]), "cwd": p.get("cwd"), "stdin_sha256": _h(p.get("stdin", b""))}
    def perform(self, p, effect_id):
        try: rc, out, err = self.broker.run(p["argv"], p.get("cwd"), p.get("stdin", b""))
        except ProcBrokerError as e: raise _Refused(e.code, started=_started(e.code))
        return {"exit": rc, "stdout_sha256": _h(out), "stderr_sha256": _h(err)}
    def witness(self, effect_id): return None if self._w is None else self._w(effect_id)


class _Refused(Exception):
    def __init__(self, code, started): super().__init__(code); self.code, self.started = code, started


# ---- kernel -----------------------------------------------------------------------------------------------------------------------------------------------
class EffectKernel:
    def __init__(self, verifier: Verifier, ledger: EffectLedger, adapters: dict, gate=None, *, receipt_signer=None, clock=time.time):
        self.v, self.ledger, self.adapters, self.gate, self.rsigner, self.clock = verifier, ledger, dict(adapters), gate, receipt_signer, clock

    def effect_for(self, kind: str, payload: dict, *, tenant, server_id, session_id, principal) -> CanonicalEffect:
        """Build the canonical effect the permit must be minted for (callers cannot supply a digest of their own)."""
        a = self.adapters[kind]; return CanonicalEffect(tenant, server_id, session_id, principal, a.effect, a.target_kind, a.target(payload), a.args(payload)).validate()

    def execute(self, token, kind: str, ce: CanonicalEffect, payload: dict, effect_id: str, *, fault=None) -> dict:
        a = self.adapters.get(kind)
        if a is None or (ce.effect, ce.target_kind) != (a.effect, a.target_kind): return Outcome.make("BLOCKED", "UNSUPPORTED_EFFECT")
        try:
            base = {k: v for k, v in ce.args.items() if k != "v1"} if isinstance(ce.args, dict) and "v1" in ce.args else ce.args      # a V1 digest rides in the permit-bound args; execute_v1 verifies it
            bound = (ce.target_raw == a.target(payload) and base == a.args(payload))
        except Exception: bound = False
        if not bound: return Outcome.make("BLOCKED", "DATA_NOT_BOUND_TO_PERMIT")                      # what is performed must be exactly what the permit committed to
        if not self.ledger.request(effect_id, {"target": ce.target_raw, "kind": kind}): return Outcome.make("DUPLICATE", "DUPLICATE")
        try: claim = commit_verify(self.v, token, ce)
        except ProofError as e:
            if self.ledger.state(effect_id) == "REQUESTED": self.ledger.block(effect_id, {"code": e.code})
            return Outcome.make("BLOCKED", e.code)
        if self.gate is not None:
            try: g = self.gate(); ok = g[0] is True; why = str(g[1]) if len(g) > 1 else ""
            except Exception: ok, why = False, "GATE_ERROR"
            if not ok:
                if self.ledger.state(effect_id) == "REQUESTED": self.ledger.block(effect_id, {"code": "ASSURANCE_DENIED", "why": why})
                return Outcome.make("BLOCKED", "ASSURANCE_DENIED", why=why)
        if not self.ledger.authorize(effect_id, claim["nonce"]): self.ledger.block(effect_id, {"code": "NONCE_REUSE"}); return Outcome.make("BLOCKED", "NONCE_REUSE")
        if not self.ledger.begin(effect_id): return Outcome.make("DUPLICATE", "DUPLICATE")
        try:
            if fault: fault()
            rec = a.perform(payload, effect_id)
        except _Refused as e:
            to = "UNKNOWN" if e.started else "BLOCKED"
            try: self.ledger.finish(effect_id, to, {"code": e.code}); return Outcome.make(to, e.code)
            except LedgerError: return Outcome.make("UNKNOWN", e.code)                                 # ledger already moved on: do not overwrite it
        except BaseException as e:
            try: self.ledger.finish(effect_id, "UNKNOWN", {"error": type(e).__name__})
            except LedgerError: pass
            return Outcome.make("UNKNOWN", "UPSTREAM_FAILED")
        try: self.ledger.finish(effect_id, "COMMITTED", {k: v for k, v in rec.items() if k != "sink_receipt"})
        except LedgerError: return Outcome.make("UNKNOWN", "LEDGER_MOVED_ON", receipt=rec)
        return Outcome.make("ALLOW_COMMITTED", "", receipt=rec)

    def reconcile(self, kind: str, effect_id: str) -> str:
        """Resolve UNKNOWN only from the sink-side witness. No witness, or a witness that cannot tell (None), leaves the effect UNKNOWN."""
        if self.ledger.state(effect_id) != "UNKNOWN": return self.ledger.state(effect_id)
        try: seen = self.adapters[kind].witness(effect_id)
        except Exception: seen = None
        if seen is None: return "UNKNOWN"
        self.ledger.reconcile(effect_id, bool(seen), {"witness": kind}); return self.ledger.state(effect_id)


# ---- CanonicalEffectV1 adoption, receipts and identity separation (K1) --------------------------------------------------------------------------------------
def make_enforcer_signer(kid: str = "ek1"):
    """A fresh in-memory enforcement identity (role 'enforcer'). In production this key must live with the enforcement component and be distinct from every permit-issuer key; custody is an owner decision."""
    from horizon.authz.keys import Signer
    return Signer.generate(kid, "enforcer")


class IdentityError(Exception):
    def __init__(self, code="IDENTITY_NOT_SEPARATED", msg=""): super().__init__(msg or code); self.code = code


@dataclass(frozen=True)
class Context:
    """The CanonicalEffectV1 fields an adapter cannot derive from the payload. Trust-bearing fields have NO defaults."""
    effect_id: str; tenant_id: str; agent_id: str; session_id: str; principal_id: str; tool_server_id: str; tool_id: str; transport: str; purpose: str
    policy_digest: str; policy_epoch: int; deadline: int; nonce: str; trace_id: str
    assurance_claim_id: str | None = None; assurance_epoch: int | None = None; idempotency_key: str | None = None
    delegation_chain_digest: str = EMPTY_CHAIN; artifact_lineage_digests: tuple | None = None; approval_id: str | None = None; budget_reservation_id: str | None = None


@dataclass(frozen=True)
class Prepared:
    ce: CanonicalEffect; v1: CanonicalEffectV1


def v1_binding(ce_fields: dict, v1: CanonicalEffectV1) -> bool:
    """The legacy permit fields and the V1 effect must describe the same effect (checked by the issuer before signing and by the kernel before executing)."""
    return (v1.tenant_id, v1.tool_server_id, v1.session_id, v1.principal_id, v1.effect_class, v1.target_kind) == tuple(ce_fields[k] for k in ("tenant", "server_id", "session_id", "principal", "effect", "target_kind"))


def _prepare(self, kind: str, payload: dict, ctx: Context) -> Prepared:
    """Build the V1 effect (deriving effect class, target, argument digest from the ADAPTER, never from the caller) and the legacy CanonicalEffect whose bound args include the V1 digest, so one permit covers all 26 V1 fields."""
    a = self.adapters[kind]; target = a.target(payload); args = a.args(payload)
    try: canon = N.canonical_target(a.target_kind, target)["canonical_id"]
    except ValueError: raise ContractError("MALFORMED", "target not canonicalisable")
    v1 = CanonicalEffectV1(SCHEMA_VERSION, ctx.effect_id, ctx.tenant_id, ctx.agent_id, ctx.session_id, ctx.principal_id, ctx.delegation_chain_digest, ctx.tool_server_id, ctx.tool_id, ctx.transport, a.effect, a.target_kind,
                           canon, "sha256:" + _j(args), ctx.artifact_lineage_digests, ctx.purpose, ctx.policy_digest, ctx.policy_epoch, ctx.assurance_claim_id, ctx.assurance_epoch, ctx.approval_id, ctx.budget_reservation_id,
                           ctx.deadline, ctx.idempotency_key if ctx.idempotency_key is not None else ctx.effect_id, ctx.nonce, ctx.trace_id).validate()
    ce = CanonicalEffect(v1.tenant_id, v1.tool_server_id, v1.session_id, v1.principal_id, a.effect, a.target_kind, target, {**args, "v1": v1.digest()}).validate()
    return Prepared(ce, v1)


def _check_identities(self):
    if self.rsigner is None: raise IdentityError("IDENTITY_NOT_SEPARATED", "a receipt signer (role 'enforcer') is required")
    if getattr(self.rsigner, "iss", None) != "enforcer": raise IdentityError("IDENTITY_NOT_SEPARATED", "receipt signer must hold the 'enforcer' role")
    mine = self.rsigner.public_raw()
    for r in self.v.t.k.values():
        from cryptography.hazmat.primitives import serialization as _s
        if r["pub"].public_bytes(_s.Encoding.Raw, _s.PublicFormat.Raw) == mine: raise IdentityError("IDENTITY_NOT_SEPARATED", "the enforcement key must differ from every permit-issuer key")


def _receipt(self, kind: str, v1: CanonicalEffectV1, out: dict) -> dict:
    a = self.adapters[kind]; st = self.ledger.state(v1.effect_id)
    state = {"COMMITTED": EffectState.COMMITTED, "BLOCKED": EffectState.BLOCKED, "UNKNOWN": EffectState.UNKNOWN, "RECONCILED_COMMITTED": EffectState.RECONCILED_COMMITTED, "RECONCILED_BLOCKED": EffectState.RECONCILED_BLOCKED}.get(st)
    if state is None: raise ContractError("MALFORMED", "no receipt for state " + str(st))
    if state in (EffectState.COMMITTED,): wid, wk = a.witness_id, a.witness_kind
    elif state in (EffectState.RECONCILED_COMMITTED, EffectState.RECONCILED_BLOCKED): wid, wk = a.witness_id.split(":")[0] + ":witness", a.reconcile_kind
    else: wid, wk = None, None
    obs = hashlib.sha256(json.dumps(out.get("receipt") or {}, sort_keys=True, default=str).encode()).hexdigest() if state == EffectState.COMMITTED else None
    r = EffectReceiptV1(v1.effect_id, v1.digest(), state, wid, ("sha256:" + obs) if obs else None, wk).validate()
    body = {"effect_id": r.effect_id, "effect_digest": r.effect_digest, "state": r.state.name, "witness": r.witness, "witness_kind": r.witness_kind, "observation": r.observation, "code": out.get("code", ""), "trace_id": v1.trace_id, "idempotency_key": v1.idempotency_key,
            "tool_server_id": v1.tool_server_id, "tenant_id": v1.tenant_id, "assurance_claim_id": v1.assurance_claim_id, "assurance_epoch": v1.assurance_epoch, "policy_epoch": v1.policy_epoch}
    return {"body": body, "kid": self.rsigner.kid, "sig": self.rsigner.sign(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hex()}


def _execute_v1(self, token, kind: str, prep: Prepared, payload: dict, *, fault=None) -> dict:
    _check_identities(self); v1, a = prep.v1, self.adapters.get(kind)
    if a is None: return Outcome.make("BLOCKED", "UNSUPPORTED_EFFECT")
    try:
        ok = (prep.ce.args.get("v1") == v1.digest() and v1_binding({"tenant": prep.ce.tenant, "server_id": prep.ce.server_id, "session_id": prep.ce.session_id, "principal": prep.ce.principal, "effect": prep.ce.effect, "target_kind": prep.ce.target_kind}, v1)
              and v1.effect_class == a.effect and v1.arguments_digest == "sha256:" + _j(a.args(payload)) and v1.target_canonical == N.canonical_target(a.target_kind, a.target(payload))["canonical_id"])
    except Exception: ok = False
    if not ok: return Outcome.make("BLOCKED", "V1_BINDING_MISMATCH")
    if not (self.clock() < v1.deadline): return Outcome.make("BLOCKED", "DEADLINE_EXCEEDED")
    out = self.execute(token, kind, prep.ce, payload, v1.effect_id, fault=fault)
    if out["status"] == "DUPLICATE": return out                                        # a duplicate call reports a duplicate; it never mints a second receipt for the first effect
    try: out["receipt_v1"] = _receipt(self, kind, v1, out)
    except ContractError: pass
    return out


def _reconcile_v1(self, kind: str, prep: Prepared) -> dict:
    _check_identities(self); st = self.reconcile(kind, prep.v1.effect_id); out = {"status": st, "code": ""}
    if st in ("RECONCILED_COMMITTED", "RECONCILED_BLOCKED"): out["receipt_v1"] = _receipt(self, kind, prep.v1, out)
    return out


def verify_receipt(rec: dict, enforcer_trust: TrustStore, *, now: float | None = None) -> dict:
    """Check an enforcer-signed receipt. Raises ContractError('MALFORMED') on any failure (bad shape, unknown/wrong-role key, bad signature)."""
    try:
        b = rec["body"]; enforcer_trust.resolve(rec["kid"], "enforcer", at=now).verify(bytes.fromhex(rec["sig"]), json.dumps(b, sort_keys=True, separators=(",", ":")).encode())
        EffectReceiptV1(b["effect_id"], b["effect_digest"], EffectState[b["state"]], b["witness"], b["observation"], b["witness_kind"]).validate(); return b
    except ContractError: raise
    except Exception: raise ContractError("MALFORMED", "receipt verification failed")


EffectKernel.prepare = _prepare; EffectKernel.execute_v1 = _execute_v1; EffectKernel.reconcile_v1 = _reconcile_v1
