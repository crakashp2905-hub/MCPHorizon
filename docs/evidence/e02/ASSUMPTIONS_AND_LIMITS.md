# ENG-PR02 — MCP gate request scoping (E02-01..04, E02-11) — CANDIDATE

Source: main d7036e7 + this PR. Scope: `horizon/adapters/mcp/gate.py`.

Changes: reply cache, cancellation set, idempotency key and event id are keyed by
(tenant, server_id, session_id, principal, typed JSON-RPC id[, method]). `1` and `"1"` are distinct.
`cancel()` now requires `server_id` (breaking signature change; one existing test updated).
Cache eviction never removes an `uncertain` record, so a retry of a possibly-started effect still returns E_UNCERTAIN.

Risk: cache can now exceed `cache_size` when many uncertain records exist (bounded by the number of uncertain effects; deliberate fail-closed trade-off).
Negative findings: none observed; 12 new tests, 8/8 mutants killed (`scripts/e02_mutants.py`), 37 existing p4 tests pass.
Limits: in-memory only; no durable ledger (ENG-PR04); no real MCP server. Not independently verified.
Reproduce: `python3 -B -m unittest tests.e02.test_mcp_scoping && python3 -B scripts/e02_mutants.py`
