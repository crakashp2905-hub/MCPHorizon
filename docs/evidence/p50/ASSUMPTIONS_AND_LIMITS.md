# P50 HorizonBudget — assumptions and limits (CANDIDATE)

Status: CANDIDATE. Nothing here is VERIFIED. Evidence is local mocks only; no real service, payment, model or network was used.

## Supported guarantee (P50-16)
Within the model below, the sum of units a task's *receiver-side effects* apply never exceeds the signed cap, in every ledger scope and across MCP, UTCP, Code Mode and the OS broker, concurrent agents, retries, spawned children, lost responses and silent telemetry. The ledger, not the agent, decides; the receiver's own counters are the ground truth.

Mechanisms: signed budget assignment (ATTESTATION from the `owner` role, bound to task, policy revision, increasing version); one SQLite ledger (`BEGIN IMMEDIATE`, hash-chained entries); reservation before the effect, checked against the scope and every ancestor; idempotency by request id plus digest; costs derived from a tool registry (non-negative integers only); a per-request hard cap enforced at the sink; conservative handling of unknown outcomes (charged until the receiver says otherwise); reconciliation against receiver observations.

## Assumptions
- The receiver (the charged service) is a trusted enforcement point: it applies the sink cap and reports its own observations honestly. A compromised or lying receiver is out of scope.
- Costs are expressible as integers in five classes (`export_rows`, `compute_units`, `spend_cents`, `priv_writes`, `requests`) from a registry. A tool missing from the registry is refused.
- Every effect goes through the broker. An effect issued directly to the service bypasses accounting; the sink cap only bounds each request.
- The policy owner key and the ledger file are protected from agents (not tested against the real kernel here).
- Clock is monotone enough for TTLs; the experiments use a fake clock.

## External-service accounting (what the model cannot give)
Real LLM, payment and API services report usage after the fact, round, batch, retry and sometimes undercount. HorizonBudget charges the reservation up front and the observed amount on commit; where a service cannot enforce a per-request cap, an effect larger than reserved is detected only after it happened. The ledger records the overrun and charges it (the remaining budget can go negative) but cannot undo it. A hard guarantee therefore holds only for services that accept a cap (`max_units` here). Irreversible classes (spend, privileged writes, export) are the ones where this matters.

## Limits
- Carrier codecs for the four carriers normalise messages; they are **not** wired into the real MCP/UTCP/Code Mode adapters or the OS broker.
- `attenuation` is redundant with the ancestor check in this suite (a child cap larger than its parent's is still limited by every ancestor); it remains as defence in depth and for clearer caps.
- `budget-no-reconcile` also disables the sink cap, so it is not an isolated ablation.
- Unknown outcomes stay charged: honest retries after a lost response can exhaust a budget early (availability cost). One UNKNOWN reservation remains in the F01 scenario by design.
- A single SQLite writer bounds throughput (see `scripts/p50_bench.py`; machine-specific, not recorded). No multi-node deployment, no replication, no clock-skew handling.
- Suite: 11 attacks, 8 benign, 1 failure scenario, scripted agents, written by the same author as the system. Wilson intervals are descriptive.
- No intent or weight attribution; traces are treated as inert data.
