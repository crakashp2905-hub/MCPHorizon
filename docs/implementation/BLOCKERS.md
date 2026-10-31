# BLOCKERS (as of 2026-10-31)

| ID | Class | Blocks | What is needed | Owner |
|---|---|---|---|---|
| B-01 | RESOLVED 2026-10-31 (chat approval; consider a real signature) | P83-06, P83-16, P83-18, all scheduling | Authorized maintainer reviews/signs the 158 gate edges in `spec/dependencies.yaml` and `plan.lock` | Maintainer |
| B-02 | NEEDS_APPROVAL | P0-09, P0-17 | Legal review of proprietary root LICENSE vs imported datasets; GitHub branch-protection/CODEOWNERS (repo-admin action) | Maintainer/counsel |
| B-03 | WAITING_EXTERNAL | P0-08, P0-10 | Upstream provenance for MCPTox / MCPSecBench / TAMAS copies; decision on private-core access | Maintainer |
| B-04 | MISSING_ARTIFACT | P0-11, P0-05 | `mcphorizon` package source (cli.py, engine/) absent: legacy experiments needing it cannot be re-run | Maintainer |
| B-05 | PARTIAL (CI verifier built; see VERIFIER.md) | P75–P82, P84–P86 | Verifier identity/keys, budgets, provider credentials, sandbox host for an unattended supervisor | Maintainer |
| B-06 | WAITING_EXTERNAL | RC-R, P55–P74, P91–P93 | Independent RC-R sign-off, external audits, real customer pilots, legal/compliance approvals — cannot be produced by an agent | External parties |
| B-07 | SCOPE | P1–P54, P87–P94 | ~1,400 research/engineering tasks need an authorized, budgeted multi-session campaign under the supervisor; none executed here | Maintainer |
| B-08 | OPEN_FINDING | P1-01..06, P86-07 | `third_party_pins/python-requirements.lock.txt` pins 31 packages with **no checksums**; `orchestrator/deps.py` would reject it. Hashes must be generated per platform from a trusted index (cannot be done meaningfully from this sandbox) | Maintainer |
