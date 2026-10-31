# STATUS — MCPHorizon 2.0 implementation (P0-15)

Snapshot: 2026-10-31 · base commit `0ebad0c` · branch `claude/p0-audit-p83-compiler`.
Vocabulary per AGENTS.md/CLAUDE.md: CANDIDATE | FAILED | BLOCKED | NEEDS_APPROVAL | WAITING_EXTERNAL. **Nothing below is VERIFIED** — an independent verifier owns that state. 0 of 1,686 tasks are verified.

## Overall
| Area | State | Evidence |
|---|---|---|
| Master spec installed (`docs/MCPHORIZON_2_0_MASTER_SPEC.md`) | CANDIDATE | sha256 `077ba6c9…9825776`; 1,686 tasks, P0–P94 parse cleanly |
| P0 repository audit (mechanical items) | CANDIDATE | `docs/implementation/p0/` ; `python3 scripts/p0_audit.py` |
| P0 judgement items (provenance, licence, private core, branch protection, legacy re-runs) | BLOCKED / NEEDS_APPROVAL | see BLOCKERS.md B-02…B-04 |
| P83 compiler/validator, schema, plan.lock | CANDIDATE | 15/15 tests pass (`python3 -m unittest discover -s tests/spec -v`); `python3 scripts/validate_plan.py` exit 0 |
| P83 reviewed dependency DAG | CANDIDATE (approved) | 158 gate edges SIGNED by maintainer via chat instruction 2026-10-31 (non-cryptographic, not line-by-line); `scheduling_enabled=true` |
| P75–P77 ledger/state machine, P84 work packets, P85 verifier, P86 adversarial subset | CANDIDATE (prototype) | `orchestrator/`, 17 tests pass (`python3 -m unittest discover -s tests/supervisor -v`); local-trust only, see `docs/security/SUPERVISOR_THREAT_MODEL.md`; hardening needs B-05 |
| P84 work packets (partial) | CANDIDATE (partial) | `orchestrator/packet2.py` (signed contract + trust-labelled context, fail-on-truncation, stale/revoked/expired rejection, provider ceiling + scrub, handoff schema), `tests/supervisor/test_packets2.py` (18 tests; a mutation check confirmed the relabel test fails when labels are removed from the digest), `results/v2/p84_packet_sizes.json` (mandatory context ≈3.0–3.4k est. tokens over all 1,686 tasks). Building that measurement exposed that 21 phases use a `### Phase Pn` heading — now handled, and ambiguity fails closed. **Not done:** P84-03 API contracts; P84-06 tool/model/CLI version capture; P84-14 Codex/Claude equivalence (needs live providers); P84-16 cost/validity/missing-instruction rates (needs live runs); P84-18 CG-05/CG-06 independent replay. The packet is validated by the supervisor-side gatekeeper because HMAC keys are symmetric: a worker holding the key could forge packets, so keys must never reach workers. Injection scanning is regex-based and trivially evadable; the safety property is the signed contract, not detection. Secret scrubbing is pattern-based and will miss unlabelled secrets. |
| P1 schemas/validator/normalization/HMAC (P1-07..12, 15..19) | CANDIDATE | `horizon/`, `schemas/`, 53-file fixture corpus, 14 tests: `python3 -m unittest discover -s tests/p1 -v` |
| P1-01..06 version pins & wire docs | CANDIDATE | `docs/protocols/PINNED_VERSIONS.md`; lockfiles in `third_party_pins/`. Finding: TS SDK 1.32.2 does not implement 2026-07-28 (Python `mcp` 2.3.0 does); 5 high npm-audit findings (zod). UTCP spec-version string / other plugins still unpinned |
| P1-13/14/20 generated TS/Python/Rust types + cross-language conformance | CANDIDATE | `scripts/run_conformance.sh`: Python, Ajv and Rust `jsonschema` agree on 55 fixtures; semantic rules (bound ALLOW, policy ambiguity, major-version) exist only in Python |
| CI verifier | CANDIDATE | `.github/workflows/verify.yml` + `spec/acceptance.json` (17 task mappings); Sigstore-attested receipts after merge to main; First run on `main` (da472f1): workflow run 41199943817 succeeded, all steps incl. attestation. **Receipt contents and the Sigstore signature were NOT independently checked** (this sandbox cannot reach the artifact store or Sigstore TUF). To confirm, run: `gh run download 41199943817 -n receipts && gh attestation verify receipts.json --repo crakashp2905-hub/MCPHorizon --signer-workflow crakashp2905-hub/MCPHorizon/.github/workflows/verify.yml`. Until then, tasks stay CANDIDATE |
| P2 core (P2-01..P2-23) | CANDIDATE | Python oracle `horizon/core/`, Rust `core/` (locked), `tests/p2` (20 tests), differential `scripts/run_diff.py` (Python vs Rust, 0 mismatches over 5 seeds ≈ 12k cases each). Started on P1 *candidate* status at the maintainer's instruction ("Proceed"); P2 results are void if P1 is later rejected. Rust covers scope/closure/labels/decide only — tokens, authz, run state, declassification, hierarchy, certification, remediation are Python-only |
| P2-24 proofs | CANDIDATE | `docs/formal/P2_CLAIMS_AND_PROOFS.md` — written by the implementer; needs independent mathematical review before it can count as proved |
| P3 local service (P3-01..P3-20) | CANDIDATE (partial) | `horizon/service/` (core, http, audit, limits, redact, trace, cli), `horizon/sdk/client.py`, `sdk-ts/`, `tests/p3` (31 tests), TS smoke test against a live Unix socket. **Done to candidate level:** P3-01..05, 07, 08, 09, 12..17, 19(examples written, not executed in CI), 20. **Not done / partial:** P3-06 (simulate evaluates hypothetical requests but there is no frozen-event corpus or shadow-decision store), P3-10 (Python SDK is a client; no replay/analysis tooling), P3-11 (CLI has `version`, `doctor`, `policy-validate`, `audit-verify`, `schema-validate`; **no `scan` or `replay`**), P3-16 (local JSONL spans only, not OpenTelemetry/OTLP), P3-18 (outage via audit failure, breaker and timeout is tested; latency injection is not). **Known limits:** all service state is in memory (restart forgets artifacts, approvals, nonces, idempotency); tokens are bearer secrets in config with no rotation; evaluation timeout is checked after the fact (post-hoc), not preemptive; the HMAC token key is a single process secret; no TLS (local only by design). Load test (`results/v2/p3_load_test.json`) is in-process on a 2-vCPU sandbox and excludes HTTP overhead, so p50/p95/p99 are not a deployment claim |
| P75–P77 supervisor (partial) | CANDIDATE (partial) | Builds on the P83-era prototype. **Added:** versioned migrations, injectable clock, stale-lease reclaim with epoch fencing, uncertain-external-effect reconciliation, journal bound to plan digest, backup/restore with `audit_verified`, scrubbed checkpoints, manifests, atomic writes, log rotation, shutdown flag (`orchestrator/recovery.py`); plan CLI `scripts/horizon_plan.py` (plan/next/list/why-blocked/status/export-dag/render); 32 new tests incl. false-completion attacks (a mutation check confirmed the signature test fails when verification is disabled). **Not done:** P75-01..12/14/18 beyond what P83 compiled (no overrides workflow, no task classification beyond `work_class`, external-authority extraction); P76-06/07 (worktree-per-task, attempt metadata capture), P76-13 (daemon restart bounds — only log rotation), P76-14 (PostgreSQL plan); P77-01..08, 10..15, 18 (verifier is a CI script, not a separate service with its own credentials; no effect-oracle integration; no automated stale-evidence trigger on file change; no security-review queue). The `vid == w` self-verify check in `accept_receipt` is unreachable defence-in-depth (role checks already block it) and is not independently tested. Local-trust only: keys are in-process; the hash chain is not externally anchored. |
| P3+ | NOT STARTED | |
| P78–P82 | NOT STARTED | require B-01, B-05 |
| P1–P54, P87–P94 research & engineering | NOT STARTED | depend on reviewed DAG and authorized budget (B-07) |
| P91–P93 science/budget/customer validation | WAITING_EXTERNAL | needs real stakeholders |
| RC-R and P55–P74 productization | BLOCKED | independent RC-R sign-off required (B-06) |

## P0 task mapping
| Task | State | Note |
|---|---|---|
| P0-01 env record | CANDIDATE | `p0/environment.json` (captured in cloud sandbox, not the maintainer's machine) |
| P0-02 inventory+hashes | CANDIDATE | 1,814 tracked files |
| P0-03 component tags | CANDIDATE | heuristic; every tag `needs_human_review` |
| P0-04/05 README/USAGE vs entrypoints | CANDIDATE | console script `mcphorizon.cli:main` and `mcphorizon.engine` declared but **absent** from tree |
| P0-06 duplicate reports | CANDIDATE | 47 identical-content groups; 9 same-name files differ (40/44 shared `results/`↔`MCPWEEK5/` files identical); canonical choice left to maintainer |
| P0-07 freeze hashes | CANDIDATE | 530 files under MCPTox/MCPSecBench/TAMAS; manifest `a9c2c8d7…98b714` |
| P0-08 provenance | BLOCKED | needs upstream info (B-03) |
| P0-09 licence audit | NEEDS_APPROVAL | raw signals only (`p0/license_signals.json`); `THIRD_PARTY_NOTICES.md` not drafted |
| P0-10 private core / approach A/B | NEEDS_APPROVAL | provisional B in DEVIATIONS D-002 |
| P0-11 re-run legacy experiments | BLOCKED | engine source absent (B-04); not attempted |
| P0-12 archive legacy metrics (42/26/14) | CANDIDATE | `LEGACY_METRICS.md` (archived, not re-run) |
| P0-13 predictor limitations register | CANDIDATE | `RESEARCH_RISK_REGISTER.md` (severities proposed) |
| P0-14 unavailable references | CANDIDATE | `p0/unavailable_in_public_release.json` |
| P0-15/16 STATUS, DEVIATIONS | CANDIDATE | this file, DEVIATIONS.md |
| P0-17 branch protection/CODEOWNERS | NEEDS_APPROVAL | repo-admin action |
| P0-18 results/v2 namespace | CANDIDATE | `results/v2/README.md` |
| P0-19 ADR-0001 | CANDIDATE | status Proposed |
| P0-20 clean checkout & commit | CANDIDATE | no tracked file modified except `.gitignore` (append-only) |

## Notable audit findings
- `data/` is byte-identical to `MCPTox/def_tool/` (485/485 files): a second copy of the same dataset.
- Legacy numbers in reports are unverified here; no experiment was re-run.
- `scripts/task_inventory.py` ledger bootstrap runs (1,686 PENDING); its unit tests were not supplied (D-003).
