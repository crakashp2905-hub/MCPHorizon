# Honest capability matrix (P38-03)

`README.md` is hash-frozen by `scripts/p23_freeze.py --check` (P23), so the matrix lives here and the README is not edited. Status vocabulary: **IMPLEMENTED-CANDIDATE** = code + tests + synthetic results, no independent review; **PLANNED** = specified, no code; **NOT RUN** = needs resources that do not exist here.

| Capability | Phase | Status | Evidence | Open |
|---|---|---|---|---|
| MCP/UTCP/Code Mode adapters, supervisor, verifier | P1–P22 | IMPLEMENTED-CANDIDATE | `tests/`, `docs/implementation/STATUS.md` | independent review |
| Kernel sandbox, brokers, managed credentials | P23–P28 | IMPLEMENTED-CANDIDATE | `tests/p24..p28` | IPv6 (P30-02), kernel limits |
| HAA benchmark B0–B6, latency, held-out, adaptive | P29 | IMPLEMENTED-CANDIDATE | `results/v2/haa-*` | live model (L3) NOT RUN |
| Reviewer bundle, claims audit | P30 | IMPLEMENTED-CANDIDATE | `scripts/p30_*` | independent reviewer |
| Model intake | P31 | IMPLEMENTED-CANDIDATE | `tests/p31` | dormant triggers cannot be detected |
| Trigger lab | P32 | IMPLEMENTED-CANDIDATE (toy models) | `results/v2/p32-triggerlab` | live models NOT RUN |
| Generated-code gate | P33 | IMPLEMENTED-CANDIDATE (toy models) | `results/v2/p33-hccb` | human adjudication NOT RUN |
| Agent isolation | P34 | IMPLEMENTED-CANDIDATE | `tests/p34` | non-inventoried channels |
| Telemetry / forensic integrity | P35 | IMPLEMENTED-CANDIDATE | `tests/p35` | P35-15 key-management review open |
| InfraGuard | P36 | IMPLEMENTED-CANDIDATE | `results/v2/p36-checkov-compare` | real cloud NOT RUN |
| H4 benchmark suites | P37 | IMPLEMENTED-CANDIDATE | `results/v2/h4-main` | same-author bias |
| Release evidence | P38 | IN PROGRESS | `docs/evidence/p38` | independent reproduction |
| HorizonEmergence … HorizonContinuity | P39–P53 | PLANNED until each phase merges | `docs/MCPHORIZON_2_0_MASTER_SPEC.md` §57–73 | all |
| Cross-module integration | P54 | PLANNED | spec §74–80 | all |
| Gates | — | HR-G7, HR-G9 NOT MET; MG-G12 not met (no independent reproduction) | `docs/evidence/HR_GATES.md`, `docs/evidence/p38/MG_GATES.md` | independent humans, live model, pilot |
