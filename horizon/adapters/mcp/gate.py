"""Pre-call enforcement gate for MCP (P4-06..P4-11, P4-16, P4-18). Nothing is forwarded to a server unless the decision service returned
ALLOW/SHADOW_ALLOW for THIS request. Any error, timeout or unknown method => not forwarded. Principal, tenant, approvals and run artifacts come
from the trusted host (call arguments), never from the request body."""
from __future__ import annotations
import hashlib, json, time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable
from ... import normalize
from .wire import Request, MODERN, LEGACY
from .manifest import ManifestTracker, ManifestError
from .schema import validate_args
from .post import label_output

ALLOW_VERDICTS = ("ALLOW", "SHADOW_ALLOW")
E_DENIED, E_PARAMS, E_METHOD, E_INVALID, E_UNCERTAIN, E_TOOL = -32001, -32602, -32601, -32600, -32002, -32003
# method -> (effect, target kind). Everything else is UNSUPPORTED and never forwarded (see compat.py).
READ_METHODS = {"tools/list": ("list", "resource"), "resources/list": ("list", "resource"), "prompts/list": ("list", "resource"),
                "resources/read": ("read", "resource"), "prompts/get": ("read", "resource"), "server/discover": ("read", "resource")}
SUPPORTED = {MODERN: {"tools/call", *READ_METHODS}, LEGACY: {"tools/call", "initialize", "ping", *READ_METHODS}}
NOTIFY_OK = {"notifications/cancelled", "notifications/initialized"}


@dataclass(frozen=True)
class ToolPolicy:
    logical_op: str
    effect: str                      # policy-schema effect vocabulary: read|list|write|modify|delete|execute|send|receive|admin
    target_arg: str | None = None
    target_kind: str = "resource"
    sink_zone: str | None = None
    default_conf: str = "INTERNAL"
    trusted_output: bool = False
    purpose: str | None = None


class ToolRegistry:
    """Operator-supplied (trusted) mapping from tools to logical operations/effects. Tool metadata from servers never contributes to it."""
    def __init__(self): self.t: dict[str, ToolPolicy] = {}
    def add(self, server_id: str, name: str, p: ToolPolicy) -> None: self.t[f"{server_id}/{name}"] = p
    def get(self, server_id: str, name: str): return self.t.get(f"{server_id}/{name}")
    def install(self) -> None:
        """Publish logical ops into horizon.normalize so the decision service can map mcp:tools/call. Global state: call once at setup."""
        for tid, p in self.t.items(): normalize.TOOL_REGISTRY[tid] = p.logical_op


def _canon(o) -> str: return json.dumps(o, sort_keys=True, separators=(",", ":"))
def _sha(o) -> str: return "sha256:" + hashlib.sha256(_canon(o).encode()).hexdigest()


def handles(args, limit=200) -> list[str]:
    """Artifact handles in tool arguments: any object {"$artifact": "<id>"} (bounded walk)."""
    out, stack = [], [args]
    while stack and len(out) < limit:
        v = stack.pop()
        if isinstance(v, dict):
            if set(v) == {"$artifact"} and isinstance(v["$artifact"], str): out.append(v["$artifact"])
            else: stack.extend(v.values())
        elif isinstance(v, list): stack.extend(v)
    return sorted(set(out))


class McpGate:
    def __init__(self, *, decide: Callable[[dict], dict], forward: Callable[[str, Request, dict], dict], registry: ToolRegistry, tracker: ManifestTracker,
                 tenant: str, store_artifact: Callable[[dict], None] | None = None, clock=time.time, cache_size: int = 10_000):
        self.decide, self.forward, self.reg, self.tracker, self.tenant, self.store, self.clock = decide, forward, registry, tracker, tenant, store_artifact, clock
        self.artifacts: dict[str, dict] = {}; self.done: OrderedDict = OrderedDict(); self.cancelled: set = set(); self.cache_size = cache_size
        self.log: list[dict] = []

    def add_artifact(self, a: dict) -> None:
        self.artifacts[a["id"]] = a
        if self.store: self.store(a)

    # -- helpers
    def _err(self, rid, code, msg, data=None): return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": msg, **({"data": data} if data else {})}}
    def _deny(self, rid, dec): return self._err(rid, E_DENIED, "denied by policy", {"verdict": dec.get("verdict"), "reason_codes": dec.get("reason_codes", [])})

    def cancel(self, principal: str, rid) -> None: self.cancelled.add((principal, rid))

    def handle(self, server_id: str, req: Request, *, approval_id: str | None = None, run_artifacts: tuple = ()) -> dict | None:
        """approval_id and run_artifacts are supplied by the trusted host. Anything of that kind inside req.params is ignored."""
        if req.kind == "notification":
            if req.method == "notifications/cancelled" and isinstance(req.params.get("requestId"), (str, int)): self.cancel(req.principal, req.params["requestId"])
            if req.method == "notifications/tools/list_changed": self.tracker.mark_stale(server_id)
            return None                                              # notifications are never forwarded by this gate
        if req.kind != "request": return None
        if req.method not in SUPPORTED[req.version]: return self._err(req.id, E_METHOD, f"method {req.method} is not supported by this adapter")
        key = (req.principal, str(req.id), req.method); fp = _sha(req.params)
        prior = self.done.get(key)
        if prior:
            if prior["fp"] != fp: return self._err(req.id, E_INVALID, "request id reused with different parameters")
            if prior["state"] == "uncertain": return self._err(req.id, E_UNCERTAIN, "a previous attempt may have executed; reconcile before retrying")
            return prior["resp"]                                      # duplicate delivery => cached response, no second execution
        try:
            resp, ran = self._dispatch(server_id, req, fp, approval_id, tuple(run_artifacts))
        except Exception:                                            # fail closed
            return self._err(req.id, E_DENIED, "denied: internal error in enforcement path", {"reason_codes": ["GATE_ERROR"]})
        if ran == "uncertain": self._remember(key, {"fp": fp, "state": "uncertain", "resp": None})
        elif ran == "done": self._remember(key, {"fp": fp, "state": "done", "resp": resp})
        if (req.principal, req.id) in self.cancelled and ran: self.log.append({"event": "result_discarded_after_cancel", "id": req.id}); return None
        return resp

    def _remember(self, key, v):
        self.done[key] = v
        while len(self.done) > self.cache_size: self.done.popitem(last=False)

    def _dispatch(self, server_id, req: Request, fp: str, approval_id, run_artifacts):
        m, p = req.method, req.params
        if (req.principal, req.id) in self.cancelled: return self._err(req.id, E_DENIED, "cancelled before execution"), None
        if m in ("initialize", "ping"): return self.forward(server_id, req, {}), "done"        # legacy lifecycle: no effect, nothing to decide
        if m == "tools/call":
            name = req.name
            try: rec = self.tracker.resolve(server_id, name)
            except ManifestError as e: return self._err(req.id, E_TOOL, str(e), {"reason_codes": [e.code]}), None
            pol = self.reg.get(server_id, name)
            if pol is None: return self._err(req.id, E_DENIED, "tool has no operator-declared policy (unmapped)", {"reason_codes": ["UNKNOWN_MAPPING"]}), None
            args = p.get("arguments", {})
            status, errs = validate_args(rec["input_schema"], args)
            protected = pol.effect in ("write", "modify", "delete", "execute", "send", "admin")
            if status == "INVALID": return self._err(req.id, E_PARAMS, "arguments do not match the tool schema", {"errors": errs[:5]}), None
            if status == "UNVALIDATED" and protected: return self._err(req.id, E_DENIED, "arguments cannot be validated for a protected effect", {"reason_codes": ["UNVALIDATED_ARGS"]}), None
            raw_target = f"{server_id}/{name}"
            if pol.target_arg:
                tv = args.get(pol.target_arg) if isinstance(args, dict) else None
                if not isinstance(tv, str): return self._err(req.id, E_PARAMS, f"target argument {pol.target_arg!r} missing or not a string"), None
                raw_target = tv
            tool_id, effect, tkind, zone, purpose = f"{server_id}/{name}", pol.effect, pol.target_kind, pol.sink_zone, pol.purpose
            inputs = sorted(set(handles(args)) | set(run_artifacts))
            body = {"protocol": "mcp", "native_operation": "tools/call", "tool_id": tool_id, "effect": effect, "args_digest": _sha(args),
                    "target": {"kind": tkind, "raw": raw_target}, "sink_zone": zone, "purpose": purpose, "input_artifacts": inputs,
                    "idempotency_key": hashlib.sha256(f"{req.principal}|{req.id}|{fp}".encode()).hexdigest()[:48], "event_id": f"{req.principal}-{req.id}"}
        else:                                                              # read-style methods
            effect, tkind = READ_METHODS[m]; tool_id, pol, zone = m, None, None
            body = {"protocol": "mcp", "native_operation": m, "effect": effect, "args_digest": _sha(p), "target": {"kind": tkind, "raw": self._target_id(m, req.name)},
                    "input_artifacts": sorted(run_artifacts), "idempotency_key": hashlib.sha256(f"{req.principal}|{req.id}|{fp}".encode()).hexdigest()[:48], "event_id": f"{req.principal}-{req.id}"}
        if approval_id: body["approval_id"] = approval_id
        dec = self.decide(body)
        if dec.get("verdict") not in ALLOW_VERDICTS: return self._deny(req.id, dec), None
        if (req.principal, req.id) in self.cancelled: return self._err(req.id, E_DENIED, "cancelled before execution"), None
        try: raw_resp = self.forward(server_id, req, {"decision_id": dec.get("decision_id")})
        except Exception:
            return self._err(req.id, E_UNCERTAIN, "upstream failed; outcome unknown", {"reason_codes": ["UNCERTAIN_EXECUTION"]}), ("uncertain" if effect not in ("read", "list") else None)
        return self._post(server_id, req, pol, effect, inputs if m == "tools/call" else list(run_artifacts), raw_resp), "done"

    @staticmethod
    def _target_id(method: str, name: str | None) -> str:
        """Collision-resistant, charset-safe target identity for name-bearing reads: digest of (method, name) — distinct URIs never share an id."""
        return f"{method.replace('/', '.')}:" + hashlib.sha256((name or "").encode()).hexdigest()[:40] if name else method.replace("/", ".")

    def _post(self, server_id, req, pol, effect, inputs, resp):
        if not isinstance(resp, dict) or "result" not in resp:
            return resp if isinstance(resp, dict) and "error" in resp else self._err(req.id, E_INVALID, "malformed upstream response")
        result = resp["result"]
        if req.method == "tools/list" and isinstance(result, dict): self.tracker.observe(server_id, result.get("tools", []))      # observation only: never auto-approves
        art, safe = label_output(tenant=self.tenant, event_id=f"{req.principal}-{req.id}", tool_default_conf=(pol.default_conf if pol else "INTERNAL"),
                                 trusted=bool(pol and pol.trusted_output), input_artifacts=self.artifacts, input_ids=inputs, result=result)
        self.add_artifact(art)
        out = {"jsonrpc": "2.0", "id": req.id, "result": safe["result"]}
        r = safe["result"] if isinstance(safe["result"], dict) else {}
        meta = {"artifact_id": safe["artifact_id"], "untrusted": art["trust"] == "UNTRUSTED", "instruction_like": safe["instruction_like"]}
        if r.get("resultType") == "input_required" or "inputRequests" in r: meta["input_required_is_not_approval"] = True      # field names per SEP-2322: UNVERIFIED assumption
        out["_horizon"] = meta
        return out
