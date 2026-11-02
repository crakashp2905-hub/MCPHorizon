# P90 framework adapter contract (CANDIDATE, library only)
`horizon/frameworks/adapter.py`: lineage-required call context (principal, run, task, tool_call, artifact), six support levels, downgrade rules (version drift or failed conformance → UNKNOWN for NATIVE/BRIDGED; subprocess/raw-network paths are UNSUPPORTED unless OS-protected), generated coverage matrix, bounded queue with cancellation and idempotency-keyed retry.
Evidence: 18 tests (`tests/p90`), 19 mutants killed. No result file: nothing was measured, no real framework SDK exists in this repo's tests, so no latency/false-block/completion numbers (P90-13) and no customer survey (P90-01), pinning (P90-02), adapters for real frameworks (P90-04/05), external reviewer (P90-17) or CG-14.
Mapped tasks are the contract/rules only.
