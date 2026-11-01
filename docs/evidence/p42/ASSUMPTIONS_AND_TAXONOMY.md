# P42 HorizonCoverage — taxonomy, inventory format, method, assumptions (CANDIDATE)

## Sink taxonomy (P42-01)
Families: FILE, CREDENTIAL, NETWORK, PROCESS, DATABASE, CONNECTOR, BROWSER. A *sink* is an interface through which a confined run could cause an effect outside its scratch area. Inventory entry fields: `id`, `family`, `interface` (how the effect is produced), `enforcement_point` (the trusted component that should stop it), `observation_channel` (an independent component that sees the effect without trusting the run), `note`. The inventory lives in `horizon/coverage/harness.py::INVENTORY` (13 sinks) and is recorded in `results/v2/p42-coverage/manifest.json` definitions; `scripts/p42_run.py --check` fails if code and record diverge.

## Discovery (P42-02/04) — what it is and is not
The inventory is hand-built from this repository's enforcement code (sandbox, commit layer, collector) and the interfaces a Python payload can reach. It is not discovered by tracing a live deployment, so an interface nobody listed is invisible. The bundle records exact component hashes (sandbox policy and code, observer code, enforcement code, adapters, policy revision, kernel) so a rerun on another profile gives a different, comparable bundle.

## States (P42-09)
VERIFIED: effect absent under enforcement in all reps AND observer saw it under the weakened config in all reps. UNKNOWN: observer sensitivity partial or evidence stale/invalidated. MISSING: no enforcement or no independent observation channel exists. Overall = worst of enforcement and observation. There is no ALLOW state.

## Expiry/invalidation (P42-11)
Bundle TTL 3600 s. Any change in a recorded component hash, the policy revision or the kernel degrades stored VERIFIED to UNKNOWN. Evaluation never upgrades a state.

## Independent observers (P42-03/12)
Filesystem manifest, UDP journal process, TCP receiver process and a process sampler are separate from the run. `compare_streams` diffs host effects against application events; host-only effects are the blind spot of tool-level logging.

## Assumptions / theorem scope
Single host, root, Landlock ABI ≥ 4; the harness and the observers share that host (host compromise defeats both). Claim supported ⇔ every sink it names is VERIFIED *now*. This says nothing about sinks outside the inventory, native-code payloads, or kernel exploits.
