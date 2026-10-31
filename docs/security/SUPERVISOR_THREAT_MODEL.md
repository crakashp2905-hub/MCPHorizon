# Supervisor threat model (candidate; P86 subset)

Scope: `orchestrator/` (ledger, packets, verifier). Local-trust prototype — principals and HMAC keys are passed in by the caller, all in one process/host. **It is not a hardened boundary** (no key storage, no process/OS isolation, no network sandbox, no multi-host leases).

| Threat | Control | Test |
|---|---|---|
| Worker marks own work VERIFIED | VERIFIED reachable only via `accept_receipt` with a registered verifier's HMAC | `test_worker_cannot_self_verify_or_set_verified` |
| Forged / altered / replayed receipt | HMAC check; receipt must match task, git sha, lease epoch, plan digest | `test_forged_and_mismatched_receipts` |
| Stale or foreign lease | epoch + worker identity + expiry checked on submit | `test_stale_epoch_*`, `test_expired_lease` |
| Scheduling on unreviewed plan / skipping gates | `refresh_ready` no-op unless plan reviewed; lease re-checks gates | `test_unreviewed_*`, `test_cannot_skip_gates` |
| Agent fabricates RC-R | needs HMAC signature from registered `external` principal over the plan digest | `test_rcr_requires_external_signature_not_agent` |
| N/A used to bypass gate | requires signed approver reason; never satisfies a gate | `test_not_applicable_*` |
| Journal rewrite | hash chain; `verify_journal` | `test_journal_tamper_detected` |
| Prompt injection in task text | text carried as data in its own packet field; packet fixed fields unaffected | `test_packet_scope_and_injection` |
| Path escape / protected files / secrets | allowlist + protected-prefix + secret-name checks | `test_changed_path_checks` |
| Dirty or wrong checkout, arbitrary command | verifier requires HEAD==sha, clean tree, program allowlist, no shell | `test_verifier_*` |

Known gaps: the `vid == worker` guard is unreachable by construction (roles are exclusive), so mutation testing does not exercise it; the verifier runs the *repository's own* tests, so a worker can weaken tests inside its allowlist (needs P85 independent oracles and test-path protection); HMAC keys are symmetric and shared with the ledger process; no concurrency stress test beyond SQLite `BEGIN IMMEDIATE`.
