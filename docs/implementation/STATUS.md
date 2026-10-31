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
| P1 schemas/validator/normalization/HMAC (P1-07..12, 15..19) | CANDIDATE | `horizon/`, `schemas/`, 53-file fixture corpus, 14 tests: `python3 -m unittest discover -s tests/p1 -v` |
| P1-01..06 version pins & wire docs | PARTIAL | `docs/protocols/`; P1-04/05/06 open (need sandboxed install + source inspection) |
| P1-13/14/20 Rust/TS types and cross-language conformance | NOT STARTED | no Rust/TS toolchain run here; Python only |
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
