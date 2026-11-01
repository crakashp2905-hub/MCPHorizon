"""Privacy-ledger identity across carriers and delegated agents (P45-07). The context names a TASK and (optionally) the ledger the caller believes it is charging; the service derives the real ledger from the dataset and refuses a mismatch, so a carrier can neither choose nor drop the ledger. These codecs are carrier-level stand-ins (a JSON-RPC `_meta` field, an HTTP header, a Code Mode binding argument); they are not wired into McpGate or the real UTCP adapter."""
import base64, json
from . import units as U

HEADER = "X-Horizon-Privacy"; META_KEY = "horizon/privacy"; MAX_DEPTH = 4


def make(dataset, task, chain=()): return {"ledger": U.ledger_id(dataset), "task": task, "chain": list(chain)}
def delegate(ctx, child):
    if len(ctx["chain"]) >= MAX_DEPTH: raise ValueError("delegation depth limit")
    return {**ctx, "chain": ctx["chain"] + [child]}
def to_mcp(ctx, params): return {**params, "_meta": {**params.get("_meta", {}), META_KEY: ctx}}
def from_mcp(params): return (params.get("_meta") or {}).get(META_KEY)
def to_utcp(ctx, headers): return {**headers, HEADER: base64.b64encode(json.dumps(ctx, sort_keys=True).encode()).decode()}
def from_utcp(headers):
    h = headers.get(HEADER)
    return json.loads(base64.b64decode(h)) if h else None
def to_codemode(ctx, binding): return {**binding, "__privacy": ctx}
def from_codemode(binding): return binding.get("__privacy")
