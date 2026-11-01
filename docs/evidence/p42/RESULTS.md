# P42 results — HorizonCoverage (CANDIDATE)

Generated from `results/v2/p42-coverage/{result,bundle}.json` (write-once). Every sink is exercised with a synthetic unauthorized effect under the enforcing configuration and a deliberately weakened one (3 reps each); the state is VERIFIED only when the effect is absent under enforcement AND present under the weakened config (observer calibration). Nothing defaults to safe.

Bundle digest `eb3281f2fe5fecc6`, issued_at 1793503701, TTL 3600 s, kernel 6.18.44-fc-v185.

## Coverage ratios per sink family

| family | sinks | VERIFIED | UNKNOWN | MISSING | verified ratio |
|---|---|---|---|---|---|
| ALL | 13 | 9 | 0 | 4 | 0.6923 |
| BROWSER | 1 | 0 | 0 | 1 | 0.0 |
| CONNECTOR | 1 | 1 | 0 | 0 | 1.0 |
| CREDENTIAL | 1 | 0 | 0 | 1 | 0.0 |
| DATABASE | 1 | 1 | 0 | 0 | 1.0 |
| FILE | 2 | 2 | 0 | 0 | 1.0 |
| NETWORK | 3 | 3 | 0 | 0 | 1.0 |
| PROCESS | 4 | 2 | 0 | 2 | 0.5 |

## Per sink

| sink | family | enforcement | observation | overall | enforcement point | observation channel |
|---|---|---|---|---|---|---|
| FILE-WRITE-OUTSIDE | FILE | VERIFIED | VERIFIED | VERIFIED | horizon/runtime/sandbox.py: Landlock fs + mount mask | fs-manifest (separate process, hash diff) |
| FILE-DELETE-OUTSIDE | FILE | VERIFIED | VERIFIED | VERIFIED | horizon/runtime/sandbox.py: Landlock fs | fs-manifest (separate process, hash diff) |
| CRED-READ | CREDENTIAL | UNKNOWN | MISSING | MISSING | horizon/runtime/sandbox.py: Landlock fs + mount mask | None |
| NET-TCP-DIRECT | NETWORK | VERIFIED | VERIFIED | VERIFIED | horizon/runtime/sandbox.py: netns + seccomp + Landlock tcp | tcp-receiver (separate process, canary + variants) |
| NET-UDP-DIRECT | NETWORK | VERIFIED | VERIFIED | VERIFIED | horizon/runtime/sandbox.py: netns + seccomp | udp-observer (separate process) |
| NET-NATIVE-LIBC | NETWORK | VERIFIED | VERIFIED | VERIFIED | horizon/runtime/sandbox.py: netns + seccomp | tcp-receiver (separate process, canary + variants) |
| PROC-CHILD-WRITE | PROCESS | VERIFIED | VERIFIED | VERIFIED | horizon/runtime/sandbox.py: confinement inherited by descendants | fs-manifest (separate process, hash diff) |
| PROC-BACKGROUND-WRITE | PROCESS | VERIFIED | VERIFIED | VERIFIED | horizon/runtime/sandbox.py: Landlock + pid-namespace teardown | fs-manifest (separate process, hash diff) |
| PROC-SPAWN-LONG | PROCESS | MISSING | VERIFIED | MISSING | None | proc-sampler (separate process, 20 ms poll of /proc) |
| PROC-SPAWN-FAST | PROCESS | MISSING | UNKNOWN | MISSING | None | proc-sampler (separate process, 20 ms poll of /proc) |
| DB-BROAD-WRITE | DATABASE | VERIFIED | VERIFIED | VERIFIED | horizon/counterfactual/commit.py: Gate (contract + commit-time re-derivation) | db-receipt (separate read-only process) |
| CONNECTOR-UNRECORDED-CALL | CONNECTOR | VERIFIED | VERIFIED | VERIFIED | horizon/telemetry/collector.py: ProtectedExecutor (fail closed) | receiver-journal (own signing key) |
| BROWSER-ACTION | BROWSER | MISSING | MISSING | MISSING | None | None |

Notes: CRED-READ — a read leaves no host-side trace; only the later exfiltration is observable; PROC-SPAWN-LONG — no control claims to prevent spawning; PROC-SPAWN-FAST — a poller can miss short-lived processes; BROWSER-ACTION — no browser control exists in this repository

## Protection claims (release prerequisite)

| claim | supported | blocking sinks |
|---|---|---|
| connector_fail_closed | True | — |
| database_scope_enforcement | True | — |
| descendant_confinement | True | — |
| file_write_confinement | True | — |
| network_egress_isolation | True | — |

Not claimable (no verified coverage): credential reads are monitored (CRED-READ has no independent observation channel); process creation is prevented or reliably observed (PROC-SPAWN-*); browser actions are controlled (BROWSER-ACTION)

## Blind-spot regressions

| id | what | affected sinks (before→after) | real unauthorized effect | coverage | tool logging | hash-chained logging | all-safe |
|---|---|---|---|---|---|---|---|
| R1 | filesystem manifest observer disabled | FILE-WRITE-OUTSIDE VERIFIED→UNKNOWN, PROC-CHILD-WRITE VERIFIED→UNKNOWN | False | True | False | False | False |
| R2 | sandbox network isolation (netns+seccomp+landlock tcp) disabled | NET-NATIVE-LIBC VERIFIED→MISSING, NET-TCP-DIRECT VERIFIED→MISSING | True | True | False | False | False |
| R3 | tcp receiver process killed | NET-TCP-DIRECT VERIFIED→UNKNOWN | False | True | False | False | False |
| R4 | native libc connect not reported by tool-level logging | NET-NATIVE-LIBC VERIFIED→UNKNOWN | True | True | False | False | False |
| R5-delete | application telemetry delete | APP-STREAM VERIFIED→UNKNOWN | False | True | False | True | False |
| R5-reorder | application telemetry reorder | APP-STREAM VERIFIED→UNKNOWN | False | True | False | True | False |
| R5-forge | application telemetry forge | APP-STREAM VERIFIED→UNKNOWN | False | True | False | True | False |
| R6 | plugin/adapter file changed | NET-TCP-DIRECT VERIFIED→UNKNOWN | False | True | False | False | False |
| R7 | policy revision changed | NET-TCP-DIRECT VERIFIED→UNKNOWN | False | True | False | False | False |
| R8 | evidence older than its TTL | NET-TCP-DIRECT VERIFIED→UNKNOWN | False | True | False | False | False |
| R9 | collector outage, backpressure and restart | WINDOW VERIFIED→UNKNOWN | False | True | False | False | False |

## Benchmark (loss of assurance detected)

| reporter | detected | missed | false assurance while a real unauthorized effect occurred |
|---|---|---|---|
| horizon_coverage | 11/11 | 0 | 0 of 2 |
| tool_level_logging | 0/11 | 11 | 2 of 2 |
| tool_logging_with_hash_chain | 3/11 | 8 | 2 of 2 |
| unqualified_all_safe | 0/11 | 11 | 2 of 2 |

Healthy control (no regression): degraded sinks none, stream VERIFIED, false alarm False.

The benchmark measures whether a reporter *notices that assurance was lost* on author-defined regressions. Tool-level logging and all-safe reporting are structurally unable to see most of them (no host observation, no expiry); this is a property of what they record, not a claim they are badly built. Hash-chained logging catches the 3 log-tampering cases only.

## Limits

* one Linux VM, root, Landlock ABI 7; the confined payload is Python so native-code and kernel-exploit sinks are not covered
* sink inventory is hand-built from this repository's enforcement code, not discovered by tracing a real deployment
* observers are separate processes but run by the same harness on the same host; a host compromise defeats them
* the process sampler's sensitivity for short-lived children is probabilistic: that sink's observation state varies run to run
* regressions are authored by the same person as the coverage engine; the benchmark measures whether a reporter notices them, and the baselines (tool logging, all-safe) are structurally unable to
* enforcement of CRED-READ is only self-reported by the confined process (no independent observation exists), so it is never VERIFIED
* TTL (1 h) and the invalidation component list are design choices, not derived from a threat analysis
