# P43 HorizonMutation — threat model, IR, operators, oracle, assumptions (CANDIDATE)

## Graph IR (P43-01)
`horizon/mutation/ir.py`. A graph holds principals (base grants), delegations, approvals (dest, principal, issued_t, ttl), flags and typed nodes: `source` (read_secret | read_note), `transform` (identity, b64, rot13, reverse, hash, redact, weak_sanitize) and `sink` (dest INT/PAR/EXT, protocol http/mcp/utcp, optional approval, execution time `t`, optional decision time `t_decide`). Each executing node maps to one canonical event (`to_events`) validated against `horizon.schemas` event schema. Tool names are fixed per node type (`files.read`, `text.transform`, `net.send`) so attack and benign twins share them.

## Operator schema (P43-02)
Each operator declares `id`, `kind`, a parameter enumerator (its semantic preconditions), an `apply`, a *predicted* relation (SAME | CHANGE | UNKNOWN), a confidence flag (high | medium | low) and an oracle obligation. Candidates that fail `ir.feasibility` are rejected and counted, never emitted. The prediction is a syntax heuristic; **equivalence is decided only by the oracle** (spec §63.2) and the disagreement is reported.

| id | covers |
|---|---|
| OP-PROTO-SWAP | HTTP / MCP / UTCP encodings of the same data (P43-03) |
| OP-ROLE-TRANSFER | principal transfer; target authority never assumed (P43-04) |
| OP-ORDER-SWAP, OP-SINK-BEFORE-APPROVAL, OP-BRANCH-FLIP | order, workflow branch, feasibility-checked (P43-05) |
| OP-SANITIZE-INSERT / REMOVE | sanitization and lineage that can flip the verdict (P43-06) |
| OP-DEST-CHANGE | authorized vs unauthorized destination |
| OP-TEMPORAL-DELAY, OP-APPROVAL-TTL | stale approval, delayed effect: execution time moves, decision time stays (P43-07) |

## Ground truth V(G) (P43-09)
A sink violates iff sensitive bytes were *observed* at its destination receiver and the sink is not *authorized*. Two independent computations must agree: the byte oracle (real sends to loopback receivers; the journal is written by a separate receiver process; canary plus known derived forms) and a labeled lineage with a safe-redaction table. Disagreement (stacked transforms, partial sanitizers) or a missing journal row gives **UNKNOWN**, which is excluded from scores and counted. **Authority is declared**: base grants, transitive delegation, and approval (dest, principal, `issued_t ≤ t < issued_t+ttl`). The oracle observes effects; it does not observe whether the declared rule is the right one.

## Provenance and reproducibility (P43-08, P43-16)
Every mutant carries its root seed, parent id, ordered operator steps (params, predicted relation, confidence, parent graph digest), the RNG seed, and the oracle label. `PL.release_manifest()` regenerates the whole dataset and re-labels with a fresh oracle; two runs must be byte-identical (`scripts/p43_run.py --check`). Guardrails: loopback only, synthetic canary only, ≤12 nodes, closed operator and op whitelists, no off-loopback redirects.

## Splits (P43-11)
Mutants inherit the seed's root causal family and are split by family (dev: F-DIRECT, F-DERIVED, F-DELEGATED, F-BRANCH; test: F-APPROVAL, F-MULTIHOP). Tests assert no family is on both sides. Random splits are reported alongside to show leakage.

## Assumptions and scope
Seeds, operators, policies under test and the authorization rule were written by one author; failure modes found are those of those policies. Results say nothing about third-party policy engines, live models, real MCP/UTCP servers, or families outside the six. Promotion gate per spec §63.6 is not met: no production enablement is claimed.
