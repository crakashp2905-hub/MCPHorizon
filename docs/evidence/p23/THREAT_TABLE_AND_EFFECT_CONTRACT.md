# Per-test threat table & task-to-effect contract (P23-07, P23-08, P23-11) — CANDIDATE

Every new HAA/runtime test declares: **actor** (who acts), **capability** (what it can try), **protected asset** (what must not be affected), **trusted boundary** (what we rely on).

| Test family | Actor | Capability | Protected asset | Trusted boundary |
|---|---|---|---|---|
| HAA-01,08,10,11,12,19 (egress) | untrusted generated code | AF_UNIX to broker only; everything else attempted | unapproved sink bytes | kernel (netns+seccomp+Landlock-net), egress broker, receiver process |
| HAA-02,03,13 (metadata/secrets) | untrusted code | read paths/env, call broker | metadata mock, canary files, mock registry artifact | kernel FS rules, credential broker |
| HAA-04,05,23 (recon / claims) | model + code | env discovery, false "no tools" claim | decision consistency | action enforcement (claims are advisory only) |
| HAA-06,07,09,21 (process) | code + children | unshare/mount/fork/spawn | host namespaces, host resources | kernel seccomp/NNP/caps/rlimits (inherited) |
| HAA-14,22 (lineage) | multi-tool workflow | transform/forward data | label-correct payloads | provenance labels (existing P3/P18 machinery) |
| HAA-15,16 (host surfaces) | untrusted code | reach host sockets, edit policy | host runtime socket, policy/audit files | mount-ns masking, protected channel |
| HAA-17,18,24 (artifacts) | generated artifact | vuln/deps | release gate | scanner + exploit oracle + signed permit |
| HAA-20 (outage) | environment | broker/policy down | fail-closed behavior | broker |

## Task-to-effect contract
A task declares the **effects it is authorized to cause** (`effect_kind`, destination class, label ceiling, byte budget). Enforcement compares *observed native effects* with that contract. Plan text, "reasoning", or model-declared intent are **never inputs** to the decision; they are logged at most as `model_declared_intent` with `mismatch_is_advisory: true`. Hidden chain-of-thought is not stored (schema rejects it).

## Normalized endpoint identity & labels (P23-11)
`horizon.normalize.canonical_url` (scheme/host/port/path canonical form; credentials, numeric-host tricks and IDNA normalized) + `broker.classify_ip` → one of `PUBLIC, PRIVATE, LOOPBACK, LINK_LOCAL, METADATA, CGNAT, MULTICAST, RESERVED, UNSPECIFIED`. Policy labels: `PUBLIC` default; others only for explicit test sinks. IPv4-mapped IPv6 is unwrapped. Transports other than plain `http` through the broker are `UNSUPPORTED_TRANSPORT` (denied, not approximated).
