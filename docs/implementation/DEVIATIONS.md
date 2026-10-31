# DEVIATIONS (P0-16)

Format: `ID | date | spec ref | deviation | rationale | status (open/approved) | approver`

| ID | Date | Spec ref | Deviation | Rationale | Status | Approver |
|---|---|---|---|---|---|---|
| D-001 | 2026-10-31 | §119 deliverable paths | `spec/dependencies.yaml` holds JSON syntax (valid YAML) | Stdlib-only tooling; no PyYAML dependency | open | — |
| D-002 | 2026-10-31 | P0-10 | Integration approach "B" (no private core) assumed provisionally | Private core absent from public tree; maintainer must confirm | open | — |
| D-003 | 2026-10-31 | START_HERE/README | `tests/test_task_inventory.py` referenced by the bootstrap README was not in the supplied files; not fabricated | Compiler tests added under `tests/spec/`; inventory tests still to be supplied/written | open | — |
| D-004 | 2026-10-31 | P83-05 | Only phase-level gate edges extracted; no task-level edges inferred | Spec prose does not give task-level prerequisites; inference requires signed review (P83-06) | open | — |
