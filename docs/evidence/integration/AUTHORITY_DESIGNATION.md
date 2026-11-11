# Authority designation (M0-04) — PROPOSED, not owner-approved
Status: CANDIDATE. Every "designated" choice below is a coding-agent proposal derived from `ROUTE_TRACE.json`; masterplan §12 reserves the real decision (issuer/reviewer custody, protected root) to the owner. Nothing here is independently verified.

| Authority | Proposed single owner | Current duplicate/violation (from ROUTE_TRACE) | Closing milestone |
|---|---|---|---|
| Policy decision | `horizon/core/decide.py` | parallel decision routes in hpolicy / lp / mcp adapter | PR-02 |
| Permit signing | `horizon/authz/keys.py` (separate process) | `Signer.generate` constructed inside `effects/mcp_gateway.Gateway` and several scenario modules | PR-02 |
| Nonce / replay store | `horizon/authz/gateway.NonceStore` (durable) | one in-memory instance per Gateway | PR-02/PR-04 |
| Effect ledger | `horizon/effects/ledger.EffectLedger` | constructed per gateway, not shared with brokers | PR-04 |
| Claim registry | `horizon/assurance/durable.DurableRegistry` | extra registries in scenario files | PR-05 |
| Sinks (file/net/proc) | `effects/kernel.EffectKernel` over `filesink` / `netbroker` / `procbroker` adapters | kernel exists (PR-04) but the reference gateway and legacy `ProtectedFileWriter` still use their own copy of the pipeline | PR-04 follow-up |

Rule: all other instances are migration-only (deleted or made test-only when the owner module is adopted). Research modules (`research/*`, `horizon/forge`) may not mint permits or read keys (graph rules R2/R4).
Not decided here: who holds issuer keys, who reviews, which Linux scope is supported.
