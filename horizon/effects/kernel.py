"""PR-04 (masterplan M3): ONE commit pipeline for every sink kind (file, network, process), replacing per-sink copies of the same sequence.
Order, identical for all sinks: bind payload to the permit's args -> ledger.request (duplicates never re-verify/re-run) -> verify the single-use permit -> commit-time gate (deny-only) -> authorize (spends the nonce)
-> begin -> perform through the sink adapter (which calls the broker, which re-checks its own policy) -> finish. Outcomes map to the contracts error table; UNKNOWN is never coerced and never retried here.
Adapters own only translation between a typed payload and the broker call, plus (optionally) a `witness`: an observation of the receiving side used by reconcile. Without a witness an UNKNOWN effect STAYS UNKNOWN.
CANDIDATE / honest limit: in-process library over local brokers; the receiver witness for net is whatever the caller supplies (no real internet receiver, no independent observer here); brokers still rely on the sandbox for mandatory use (masterplan section 12)."""
from __future__ import annotations
import hashlib, json
from horizon.authz.gateway import ProofError, Verifier
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
    def __init__(self, sink: FileSink): self.sink = sink
    def target(self, p): return p["path"]
    def args(self, p): return {"sha256": _h(p["data"])}
    def perform(self, p, effect_id):
        try: rec = self.sink.write(p["path"], p["data"], effect_id)
        except SinkError as e: raise _Refused(e.code, started=_started(e.code))
        return {"sha256": rec["sha256"], "sink_receipt": rec}
    def witness(self, effect_id):
        obs = self.sink.fence_and_observe(effect_id); return bool(obs and obs["present_now"])



def _started(code: str) -> bool: return ER.lookup(code).effect != "DID_NOT_HAPPEN"      # contract table decides; an unknown code is treated as possibly-happened (fail closed)


class NetAdapter:
    effect, target_kind = "send", "url"
    def __init__(self, broker: NetBroker, witness=None): self.broker, self._w = broker, witness
    def target(self, p): return p["url"]
    def args(self, p): return {"method": p["method"], "body_sha256": _h(p.get("body", b"")), "headers_sha256": _j(sorted((p.get("headers") or {}).items()))}
    def perform(self, p, effect_id):
        try: status, data = self.broker.request(p["method"], p["url"], p.get("headers"), p.get("body", b""))
        except NetBrokerError as e: raise _Refused(e.code, started=_started(e.code))
        return {"http_status": status, "response_sha256": _h(data), "response_len": len(data)}
    def witness(self, effect_id): return None if self._w is None else self._w(effect_id)


class ProcAdapter:
    effect, target_kind = "execute", "process"
    def __init__(self, broker: ProcBroker, witness=None): self.broker, self._w = broker, witness
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
    def __init__(self, verifier: Verifier, ledger: EffectLedger, adapters: dict, gate=None):
        self.v, self.ledger, self.adapters, self.gate = verifier, ledger, dict(adapters), gate

    def effect_for(self, kind: str, payload: dict, *, tenant, server_id, session_id, principal) -> CanonicalEffect:
        """Build the canonical effect the permit must be minted for (callers cannot supply a digest of their own)."""
        a = self.adapters[kind]; return CanonicalEffect(tenant, server_id, session_id, principal, a.effect, a.target_kind, a.target(payload), a.args(payload)).validate()

    def execute(self, token, kind: str, ce: CanonicalEffect, payload: dict, effect_id: str, *, fault=None) -> dict:
        a = self.adapters.get(kind)
        if a is None or (ce.effect, ce.target_kind) != (a.effect, a.target_kind): return Outcome.make("BLOCKED", "UNSUPPORTED_EFFECT")
        try: bound = (ce.target_raw == a.target(payload) and ce.args == a.args(payload))
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
