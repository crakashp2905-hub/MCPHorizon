# P46 HorizonDowngrade — ordering assumptions, counterexamples and limits (CANDIDATE)

Status: **CANDIDATE**. Nothing here is VERIFIED. Evidence level: author-written implementation, same-author oracle and scenarios, loopback endpoints in a separate process, deterministic failure injection. No live model, no independent reviewer, no pilot (L3/L5 not met).

## 1. The order (P46-01, P46-16)

A *guarantee vector* maps each mandatory dimension to a value. Values live in a per-dimension poset; the vector order is the **product order** over the dimensions a task makes mandatory.

| dimension | kind | order (weak → strong) |
|---|---|---|
| `authn` | chain | none < api_key < oauth |
| `transport` | chain | plaintext < tls1.2 < tls1.3 |
| `audit` | chain | none < local < remote_tamper_evident |
| `egress` | chain | unmediated < mediated |
| `scope`, `data_scope` | set, **smaller is stronger** | least privilege: {read} is stronger than {read, admin} |
| `region` | member | values pairwise **incomparable**; a requirement is a set of allowed values |

`None` (missing, unattested, expired, revoked) is **UNKNOWN**, and UNKNOWN never satisfies a requirement. Out-of-domain values raise instead of becoming "unknown but fine".

`classify(floor, profile)` returns:

- **ADMIT** — every mandatory dimension is satisfied (≥ the floor in its poset).
- **DOWNGRADE** — some dimension is violated and none of the satisfied ones is strictly better than required.
- **INCOMPARABLE** — some dimension is violated while another is strictly *better* than required (a trade-off the order cannot rank).
- **UNKNOWN** — nothing is violated but some mandatory dimension has no verified value. A known violation is reported as such before UNKNOWN.

The engine maps these to **ADMIT / REVIEW / BLOCK**: a violation in a *non-waivable* dimension (here `authn`, `audit`) is BLOCK; DOWNGRADE/INCOMPARABLE in a waivable dimension is REVIEW (needs a bound approval); UNKNOWN is never ADMIT.

### Laws checked by tests
`compare` on profiles is reflexive, antisymmetric, transitive and dual (GT↔LT) on a sampled grid of vectors (`OrderLaws`). `join` and `at_least_as_strict` (used for delegation) are checked per dimension kind. These are tests over a sample (about 1/7 of a 3×3×3×3×2 grid for reflexivity/antisymmetry, 24 vectors for transitivity), not a proof; the product of finite posets is a poset, which is the argument.

### Scoped statement (not a theorem about the world)
*If* (A1) the evaluated profile is attested and its claim for each mandatory dimension is true of the endpoint, (A2) the endpoint's behaviour does not change between attestation and use, (A3) the floor is the one bound to the task by the floor-authority token, (A4) the mandatory dimensions are the ones listed above, *then* an ADMIT decision implies the endpoint's actual guarantee is ≥ the floor in each mandatory dimension, so the fallback cannot lower a mandatory guarantee relative to the floor. Proof: ADMIT ⇔ all dimensions SAT, and SAT is defined as ≥ in the dimension's poset; requested credential scope is unioned into the profile scope before the check. Everything the statement does not cover is listed in §4.

### Counterexamples (why there is no single score)
1. **Incomparable regions.** `eu` and `us` are not ordered. A fallback in `us` is not "weaker" or "stronger"; it violates a data-locality requirement that names `eu`.
2. **Trade-off across dimensions.** Floor {transport ≥ tls1.2, region ∈ {eu}}; candidate {tls1.3, us}: stronger transport, forbidden region. Any weighting that admits it invents an exchange rate between encryption and locality (scenario A09; `ScalarScoreCounterexamples`).
3. **Equal scalar, incomparable vectors.** {oauth, tls1.3, audit none, mediated} and {oauth, tls1.3, audit remote, unmediated} get the same score from the baseline `scalar_score` yet compare as INCOMPARABLE (tested). The scalar ablation (`guard-scalar-score`) admits unsafe fallbacks in the recorded run.
4. **Audit loss offset by transport.** Floor {tls1.2, remote audit}; candidate {tls1.3, local audit}: INCOMPARABLE, not ADMIT.
5. **Relative to the floor, not to the original.** The order protects the *task floor*. If the original endpoint was stronger than the floor, a fallback exactly at the floor is admitted (scenario B04). This is deliberate (the floor is the contract) and is a limit: nothing keeps the task at the original's quality.

## 2. Evidence rules
- Profiles are operator-signed (Ed25519) but count as evidence only with an ATTESTATION token from the attestor role, bound to the endpoint name and the profile's digest, level `ATTESTED`, unexpired. Anything else yields all-UNKNOWN.
- Version rollback is rejected; each declare, revoke or expiry bumps a registry epoch that invalidates the verdict cache. The cache key also holds the policy version, the floor digest, the requested scope and the profile status.
- The task floor is bound by a floor-authority ATTESTATION (`claim.type = task-floor`) over a digest of (floor, non-waivable set); the token must be for this task. Delegation can only *tighten* (`FLOOR_WEAKENED` otherwise).
- Approvals are APPROVAL tokens whose `args_digest` is the digest of (task, floor, profile digest, endpoint, tool, operation, argument digest, credential scope). They are single use, must come from a principal other than the requester, and do not lower the floor for any later evaluation. Modules never issue evidence themselves (static test); the harness holds the issuers.
- The credential broker issues 60-second bearer tokens whose scope is the intersection of the request and the floor's scope.

## 3. Oracle and independence
The oracle (`scenarios.observe`) reads only journals written by the separate endpoint process (`endpoints.jsonl`, `audit.jsonl`, `side.jsonl`) and the probe-calibrated authentication level of each endpoint. It does not import or call the engine, registry or classifier (static test). Measured per request: TLS version actually negotiated, scope presented vs the floor, audit entry by request id, region by the endpoint's address block, canary at the side sink, and authentication measured by probes with and without credentials.

It is nevertheless the same author's: the endpoints, the profiles' truthfulness (except the deliberate liar), the floors and the oracle's notion of violation are all written by the same hand.

## 4. Limits (what this does not show)
1. **Attested profiles can be wrong or stale.** An endpoint that lies *and* gets attested defeats the check, and a real change between attestation and use is only caught if the operator re-declares. The liar scenario (A06) tests an *unattested* lie only.
2. **Dimensions are a closed list.** Properties outside the vector (data retention, sub-processors, content logging, timing, rate limits) are not compared.
3. **Twelve attack and seven benign scenarios, three repetitions.** The guard's 0/12 is not a bound; the confidence intervals in `RESULTS.md` are wide at this n.
4. **Static allowlist and "scripted-suggest"** are deterministic stand-ins. No LLM planner was run, so claims about model-driven replanning are untested. The allowlist includes endpoints that were approved for other tasks by construction; a different allowlist would score differently.
5. **Loopback only.** TLS versions, authentication, audit and the side sink are real sockets in a child process, but there is no real network, certificate authority, clock skew or partial failure beyond timeout/5xx/drop.
6. **Authentication is measured by probes**; an endpoint that behaves differently for probes is outside the model.
7. **Approvals** depend on a human reading the screen; the golden test checks the screen's content, not that a person would understand it. No usability study was run.
8. **Credential clamp** is redundant with the engine's requested-scope check in these scenarios (ablation shows no difference); it is unit-tested directly and kept as defence in depth.
9. **Time** — the harness uses the wall clock with a settable offset; attestation expiry uses that clock. Clock attacks are not tested.
10. **Concurrency** — the engine, cache and consumed-approval set are not synchronized; one decision at a time is assumed.
