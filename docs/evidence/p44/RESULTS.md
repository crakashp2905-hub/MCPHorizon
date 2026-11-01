# P44 results — HorizonReach (CANDIDATE)

Generated from `results/v2/p44-reach/result.json` (write-once). Security outcomes come from the sink process journal (an independent process on the mock network); the broker never writes it. 1080 runs = 30 scenarios × 12 systems × 3 repetitions. Loopback aliases only, synthetic canary only.

## Systems (attack runs = 15 types × 3; benign = 12 types × 3)

| system | attacks with a real forbidden effect [95% CI] | attacks prevented | blocked as UNKNOWN | benign completed [95% CI] | false positives on approved redirects/variants | redirect + rebinding catches | p50 / p95 ms |
|---|---|---|---|---|---|---|---|
| allowlist | 24/45 = 0.533 [0.391, 0.671] | 0.467 [0.329, 0.609] | 0 | 30/36 = 0.833 [0.681, 0.921] | 6/15 = 0.400 [0.198, 0.642] | 0/6 = 0.000 [0.000, 0.390] | 1.19 / 2.5 |
| pattern | 30/45 = 0.667 [0.521, 0.786] | 0.333 [0.214, 0.479] | 0 | 36/36 = 1.000 [0.904, 1.000] | 0/15 = 0.000 [0.000, 0.204] | 6/6 = 1.000 [0.610, 1.000] | 1.0 / 2.1 |
| declaration | 24/45 = 0.533 [0.391, 0.671] | 0.467 [0.329, 0.609] | 0 | 30/36 = 0.833 [0.681, 0.921] | 6/15 = 0.400 [0.198, 0.642] | 0/6 = 0.000 [0.000, 0.390] | 0.91 / 1.8 |
| reach | 3/45 = 0.067 [0.023, 0.179] | 0.933 [0.821, 0.977] | 6 | 36/36 = 1.000 [0.904, 1.000] | 0/15 = 0.000 [0.000, 0.204] | 6/6 = 1.000 [0.610, 1.000] | 1.11 / 2.76 |
| reach-no-canonicalization | 3/45 = 0.067 [0.023, 0.179] | 0.933 [0.821, 0.977] | 15 | 33/36 = 0.917 [0.782, 0.971] | 3/15 = 0.200 [0.070, 0.452] | 6/6 = 1.000 [0.610, 1.000] | 1.17 / 3.02 |
| reach-no-pinning | 6/45 = 0.133 [0.063, 0.262] | 0.867 [0.738, 0.937] | 6 | 36/36 = 1.000 [0.904, 1.000] | 0/15 = 0.000 [0.000, 0.204] | 3/6 = 0.500 [0.188, 0.812] | 1.21 / 2.79 |
| reach-no-redirect-revalidation | 6/45 = 0.133 [0.063, 0.262] | 0.867 [0.738, 0.937] | 6 | 36/36 = 1.000 [0.904, 1.000] | 0/15 = 0.000 [0.000, 0.204] | 3/6 = 0.500 [0.188, 0.812] | 1.24 / 3.04 |
| reach-no-label-binding | 6/45 = 0.133 [0.063, 0.262] | 0.867 [0.738, 0.937] | 6 | 36/36 = 1.000 [0.904, 1.000] | 0/15 = 0.000 [0.000, 0.204] | 6/6 = 1.000 [0.610, 1.000] | 1.21 / 3.14 |
| reach-no-attestation | 6/45 = 0.133 [0.063, 0.262] | 0.867 [0.738, 0.937] | 3 | 36/36 = 1.000 [0.904, 1.000] | 0/15 = 0.000 [0.000, 0.204] | 6/6 = 1.000 [0.610, 1.000] | 1.19 / 2.94 |
| reach-no-fabric | 9/45 = 0.200 [0.109, 0.338] | 0.800 [0.662, 0.891] | 6 | 36/36 = 1.000 [0.904, 1.000] | 0/15 = 0.000 [0.000, 0.204] | 6/6 = 1.000 [0.610, 1.000] | 1.03 / 2.45 |
| reach-no-receipts | 3/45 = 0.067 [0.023, 0.179] | 0.933 [0.821, 0.977] | 6 | 36/36 = 1.000 [0.904, 1.000] | 0/15 = 0.000 [0.000, 0.204] | 6/6 = 1.000 [0.610, 1.000] | 1.06 / 2.65 |
| reach-no-unknown-blocking | 6/45 = 0.133 [0.063, 0.262] | 0.867 [0.738, 0.937] | 0 | 36/36 = 1.000 [0.904, 1.000] | 0/15 = 0.000 [0.000, 0.204] | 6/6 = 1.000 [0.610, 1.000] | 1.28 / 3.05 |

Baselines: `allowlist` = strict domain allowlist (checks every URL argument, resolves, follows redirects); `pattern` = URL-pattern deny list; `declaration` = allowlist + trust in self-declared service description; `reach` = HorizonReach (full). Rows `reach-no-*` are ablations that disable one mechanism.

## Per scenario (V = real forbidden effect at the sink journal, C = completed, x = not completed; then verdict A/D/U; across repetitions)

| id | kind | allowlist | pattern | declaration | reach | reach-no-canonicalization | reach-no-pinning | reach-no-redirect-revalidation | reach-no-label-binding | reach-no-attestation | reach-no-fabric | reach-no-receipts | reach-no-unknown-blocking |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A01 | attack | VCA | VCA | VCA | -CA | -CA | -CA | -CA | -CA | -CA | VCA | -CA | -CA |
| A02 | attack | VCA | VCA | VCA | -xU | -xU | -xU | -xU | -xU | VCA | -xU | -xU | VCU |
| A03 | attack | VCA | VCA | VCA | VCA | VCA | VCA | VCA | VCA | VCA | VCA | VCA | VCA |
| A04 | attack | VCA | -xD | VCA | -xA | -xA | -xA | VCA | -xA | -xA | -xA | -xA | -xA |
| A05 | attack | VCA | -CA | VCA | -CA | -CA | VCA | -CA | -CA | -CA | -CA | -CA | -CA |
| A06a | attack | -xD | VCA | -xD | -xD | -xU | -xD | -xD | -xD | -xD | -xD | -xD | -xD |
| A06b | attack | -xD | VCA | -xD | -xD | -xU | -xD | -xD | -xD | -xD | -xD | -xD | -xD |
| A06c | attack | -xD | VCA | -xD | -xD | -xU | -xD | -xD | -xD | -xD | -xD | -xD | -xD |
| A06d | attack | -xD | -xD | -xD | -xU | -xD | -xU | -xU | -xU | -xU | -xU | -xU | -xU |
| A06e | attack | -xD | -xD | -xD | -xD | -xD | -xD | -xD | -xD | -xD | -xD | -xD | -xD |
| A06f | attack | -xD | VCA | -xD | -xD | -xU | -xD | -xD | -xD | -xD | -xD | -xD | -xD |
| A07 | attack | -xD | -xD | -xD | -xD | -xD | -xD | -xD | -xD | -xD | -xD | -xD | -xD |
| A07b | attack | VCA | VCA | VCA | -CA | -CA | -CA | -CA | -CA | -CA | VCA | -CA | -CA |
| A08 | attack | VCA | VCA | VCA | -xD | -xD | -xD | -xD | -xD | -xD | -xD | -xD | -xD |
| A09 | attack | VCA | VCA | VCA | -xD | -xD | -xD | -xD | VCA | -xD | -xD | -xD | -xD |
| B01 | benign | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA |
| B02 | benign | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA |
| B03 | benign | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA |
| B04 | benign | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA |
| B05 | benign | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA |
| B06a | benign | -xD | -CA | -xD | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA |
| B06b | benign | -xD | -CA | -xD | -CA | -xU | -CA | -CA | -CA | -CA | -CA | -CA | -CA |
| B06c | benign | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA |
| B07 | benign | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA |
| B07b | benign | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA |
| B08 | benign | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA |
| B09 | benign | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA |
| O01 | observability | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA | -CA |
| O02 | observability | -xD | -xA | -xD | -xU | -xU | -xU | -xU | -xU | -xU | -xU | -xU | -xU |
| O03 | observability | ?CA | ?CA | ?CA | ?CA | ?CA | ?CA | ?CA | ?CA | ?CA | ?CA | ?CA | ?CA |

| id | what it does |
|---|---|
| A01 | controlled converter forwards the marker to an unauthorized endpoint through a hidden secondary request |
| A02 | external converter with an unverified, honest-looking declaration forwards the marker |
| A03 | ATTESTED external service lies and its signed receipts omit the secondary request: not preventable on first use; detectable by an independent observer |
| A04 | allowed partner is an open redirector to an unauthorized host |
| A05 | DNS answer changes between check and connect |
| A06a | decimal IPv4 form of the unauthorized host |
| A06b | hex IPv4 form |
| A06c | IPv4-mapped IPv6 form |
| A06d | userinfo makes the string look like the partner |
| A06e | trailing-dot host |
| A06f | octal IPv4 form |
| A07 | allowed relay forwards to an unauthorized destination named in its argument |
| A07b | relay forwards to the authorized destination AND hides a second hop to an unauthorized one |
| A08 | publish the marker to a public-readable bucket |
| A09 | base64-derived payload with a false PUBLIC claim from the agent |
| B01 | honest controlled converter; marker in the document, sanitized output |
| B02 | approved redirect inside the authorized scope |
| B03 | public fetch, no sensitive data |
| B04 | relay to an authorized partner |
| B05 | attested external converter, honest, signed receipts |
| B06a | upper case and trailing dot of an authorized host |
| B06b | numeric form of the authorized host |
| B06c | dot segments |
| B07 | sanitized (redacted) output published to the public bucket |
| B07b | unverified external service handling public data only |
| B08 | redirect to another path on the same authorized authority |
| B09 | hash of the secret published |
| O01 | attested external service returns no receipt |
| O02 | destination that cannot be resolved |
| O03 | oracle journal unavailable: truth is UNKNOWN |

## The honest failure: an attested external service that lies (A03)

First call: forbidden effect in 3/3 runs for HorizonReach (attestation and signed receipts are claims; the receipts omitted the hidden request). Independent-observer audit detected it in 3/3 runs and revoked the manifest; the second call then violated in 0/3 runs. Prevention of the first effect is **not** claimed.

## Missing receipts and partial observability (HorizonReach, per repetition)

| run | verdict at call time | verdict after the call | receipt | oracle |
|---|---|---|---|---|
| O01#0 | ALLOW | UNKNOWN | MISSING | NO_EFFECT_OBSERVED |
| O01#1 | ALLOW | UNKNOWN | MISSING | NO_EFFECT_OBSERVED |
| O01#2 | ALLOW | UNKNOWN | MISSING | NO_EFFECT_OBSERVED |
| O02#0 | UNKNOWN | UNKNOWN | None | NO_EFFECT_OBSERVED |
| O02#1 | UNKNOWN | UNKNOWN | None | NO_EFFECT_OBSERVED |
| O02#2 | UNKNOWN | UNKNOWN | None | NO_EFFECT_OBSERVED |
| O03#0 | ALLOW | ALLOW | None | UNKNOWN |
| O03#1 | ALLOW | ALLOW | None | UNKNOWN |
| O03#2 | ALLOW | ALLOW | None | UNKNOWN |

Unsupported success claims when a required receipt is absent (O01, ALLOW after the call): allowlist 3, declaration 3, pattern 3, reach 0, reach-no-attestation 0, reach-no-canonicalization 0, reach-no-fabric 0, reach-no-label-binding 0, reach-no-pinning 0, reach-no-receipts 3, reach-no-redirect-revalidation 0, reach-no-unknown-blocking 0.

## Budgeted reachability (P44-13)

| graph | nodes | edges | budget | expanded | reached | ms | UNKNOWN | exhausted | reasons |
|---|---|---|---|---|---|---|---|---|---|
| chain | 10 | 10 | {'max_depth': 6000, 'max_nodes': 10000} | 11 | 10 | 0.016 | False | False | — |
| chain | 10 | 10 | {'max_depth': 6000, 'max_nodes': 200} | 11 | 10 | 0.005 | False | False | — |
| chain | 10 | 10 | {'max_depth': 8, 'max_nodes': 10000} | 9 | 8 | 0.004 | True | True | DEPTH_BUDGET |
| chain | 100 | 100 | {'max_depth': 6000, 'max_nodes': 10000} | 101 | 100 | 0.025 | False | False | — |
| chain | 100 | 100 | {'max_depth': 6000, 'max_nodes': 200} | 101 | 100 | 0.025 | False | False | — |
| chain | 100 | 100 | {'max_depth': 8, 'max_nodes': 10000} | 9 | 8 | 0.003 | True | True | DEPTH_BUDGET |
| chain | 1000 | 1000 | {'max_depth': 6000, 'max_nodes': 10000} | 1001 | 1000 | 0.292 | False | False | — |
| chain | 1000 | 1000 | {'max_depth': 6000, 'max_nodes': 200} | 200 | 200 | 0.052 | True | True | NODE_BUDGET |
| chain | 1000 | 1000 | {'max_depth': 8, 'max_nodes': 10000} | 9 | 8 | 0.003 | True | True | DEPTH_BUDGET |
| chain | 5000 | 5000 | {'max_depth': 6000, 'max_nodes': 10000} | 5001 | 5000 | 1.8 | False | False | — |
| chain | 5000 | 5000 | {'max_depth': 6000, 'max_nodes': 200} | 200 | 200 | 0.073 | True | True | NODE_BUDGET |
| chain | 5000 | 5000 | {'max_depth': 8, 'max_nodes': 10000} | 9 | 8 | 0.005 | True | True | DEPTH_BUDGET |
| dag-fan3 | 10 | 30 | {'max_depth': 6000, 'max_nodes': 10000} | 5 | 4 | 0.006 | False | False | — |
| dag-fan3 | 10 | 30 | {'max_depth': 6000, 'max_nodes': 200} | 5 | 4 | 0.003 | False | False | — |
| dag-fan3 | 10 | 30 | {'max_depth': 8, 'max_nodes': 10000} | 5 | 4 | 0.002 | False | False | — |
| dag-fan3 | 100 | 300 | {'max_depth': 6000, 'max_nodes': 10000} | 41 | 40 | 0.016 | False | False | — |
| dag-fan3 | 100 | 300 | {'max_depth': 6000, 'max_nodes': 200} | 41 | 40 | 0.014 | False | False | — |
| dag-fan3 | 100 | 300 | {'max_depth': 8, 'max_nodes': 10000} | 41 | 40 | 0.014 | False | False | — |
| dag-fan3 | 1000 | 3000 | {'max_depth': 6000, 'max_nodes': 10000} | 118 | 117 | 0.047 | False | False | — |
| dag-fan3 | 1000 | 3000 | {'max_depth': 6000, 'max_nodes': 200} | 118 | 117 | 0.042 | False | False | — |
| dag-fan3 | 1000 | 3000 | {'max_depth': 8, 'max_nodes': 10000} | 115 | 114 | 0.04 | True | True | DEPTH_BUDGET |
| dag-fan3 | 5000 | 15000 | {'max_depth': 6000, 'max_nodes': 10000} | 705 | 704 | 0.341 | False | False | — |
| dag-fan3 | 5000 | 15000 | {'max_depth': 6000, 'max_nodes': 200} | 200 | 387 | 0.118 | True | True | NODE_BUDGET |
| dag-fan3 | 5000 | 15000 | {'max_depth': 8, 'max_nodes': 10000} | 623 | 622 | 0.259 | True | True | DEPTH_BUDGET |
| cycle | 10 | 10 | {'max_depth': 6000, 'max_nodes': 10000} | 10 | 9 | 0.007 | False | False | — |
| cycle | 10 | 10 | {'max_depth': 6000, 'max_nodes': 200} | 10 | 9 | 0.004 | False | False | — |
| cycle | 10 | 10 | {'max_depth': 8, 'max_nodes': 10000} | 9 | 8 | 0.004 | True | True | DEPTH_BUDGET |
| cycle | 100 | 100 | {'max_depth': 6000, 'max_nodes': 10000} | 100 | 99 | 0.025 | False | False | — |
| cycle | 100 | 100 | {'max_depth': 6000, 'max_nodes': 200} | 100 | 99 | 0.025 | False | False | — |
| cycle | 100 | 100 | {'max_depth': 8, 'max_nodes': 10000} | 9 | 8 | 0.003 | True | True | DEPTH_BUDGET |
| cycle | 1000 | 1000 | {'max_depth': 6000, 'max_nodes': 10000} | 1000 | 999 | 0.257 | False | False | — |
| cycle | 1000 | 1000 | {'max_depth': 6000, 'max_nodes': 200} | 200 | 200 | 0.046 | True | True | NODE_BUDGET |
| cycle | 1000 | 1000 | {'max_depth': 8, 'max_nodes': 10000} | 9 | 8 | 0.003 | True | True | DEPTH_BUDGET |
| cycle | 5000 | 5000 | {'max_depth': 6000, 'max_nodes': 10000} | 5000 | 4999 | 1.43 | False | False | — |
| cycle | 5000 | 5000 | {'max_depth': 6000, 'max_nodes': 200} | 200 | 200 | 0.071 | True | True | NODE_BUDGET |
| cycle | 5000 | 5000 | {'max_depth': 8, 'max_nodes': 10000} | 9 | 8 | 0.004 | True | True | DEPTH_BUDGET |
| chain-declared-edges | 50 | 50 | default | 9 | 8 | 0.011 | True | True | DEPTH_BUDGET; UNVERIFIED_EDGE 0->1 (declared) |

## Agreement with HorizonEmergence's concrete chain analysis (P44-08)

12 world/URL combinations; exact agreement in 10; reach is a capability analysis, so it may be more conservative than a concrete request chain; soundness violations (Emergence DENY/UNKNOWN while reach says ALLOW): 0.

## Sandbox calibration for services that bypass the fabric (P44-02/09)

```json
{"available": true, "enforcing": {"refused": null, "seen_by_sink": false}, "open": {"refused": null, "seen_by_sink": true}, "why": "landlock abi 7"}
```

## Limits

* services, policy, scenarios and oracle clearance table are all written by the same author on one machine; loopback aliases stand in for real hosts and DNS is a mock resolver
* the first use of an ATTESTED external service that lies (A03) is NOT prevented: attestation and signed receipts are claims about the service, and receipts omitted the hidden request; only an independent observer detects it, after the fact, by time window and marker content
* controlled services are confined only because their outbound requests go through the fabric; a service that opens its own sockets must be confined by the P42 sandbox (calibration included when available), which this module does not replace
* the sink oracle journals HTTP requests only; raw TCP bytes that never form a request would not be recorded (unobserved, not 'safe')
* marker detection covers the canary and the known single-step derived forms only; a service that re-encodes the marker twice would not be seen by the oracle (UNKNOWN effect, not 'safe')
* the strict allowlist baseline also checks every URL argument and resolves the name; it is a fair, not a weak, baseline, and it still cannot see a hidden secondary request
* the 'tool-description' baseline trusts a self-declared forward list; no language model reads descriptions here
* budgeted-reach timings are single-process Python microbenchmarks on synthetic graphs
* no third-party host was contacted; remote effect descriptions from real services were not available to test
