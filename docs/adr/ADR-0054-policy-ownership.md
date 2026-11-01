# ADR-0054: shared contracts, threat assumptions and who owns policy authority (P54-03)

Status: accepted for the CANDIDATE research tranche P39–P53. Nothing described here is verified.

## Context

Fifteen modules (P39–P53) were written one at a time. Each has its own synthetic world, its own independent oracle (a receiver or record that the module under test cannot write to) and its own recorded paired result. P54 has to say what they share and who owns what, without pretending they run in one world.

## Decision

1. **One policy authority.** The shared `HorizonPolicy` (`horizon/hpolicy/authority.py`) is the only place a policy version, a trust store and issuer keys live. Enforcement modules receive a `Verifier` (public keys only) and never an `Issuer`.
2. **Issuers belong to evidence services**, not to guards: the approver, CI/test service, budget owner, privacy owner, checkpointer, attestor and (in P54) the receipt service. An evidence service holds one role and a fixed set of token kinds (APPROVAL, TEST_STATUS, SIGNATURE, SMOKE_TEST, REVIEW, ATTESTATION). A claim is at most 1024 bytes.
3. **Modules must not self-sign.** A guard that produces its own verdict token is a duplicate authority. Fixtures (`world.py`, `harness.py`, `scenarios.py`, `experiment.py`) may create authorities because they play the evidence services in a synthetic world.
4. **Oracles are independent of the system under test.** The oracle reads only records the system cannot write (the receiver's log, the ledger's own entries, the approver's record) and must not import decision code of the module it judges. `horizon/integration/review.py` checks this statically on transitive intra-package imports.
5. **UNKNOWN is a result.** A module that cannot establish the facts reports UNKNOWN (and blocks), separately from a verified prohibited effect. A missing or unverifiable receipt is UNKNOWN, never PASS.
6. **Evidence receipts.** `ReceiptService` issues one ATTESTATION per module binding the module id to the hash of its recorded result and of its oracle and system files. The verdict is INTACT / TAMPERED / UNKNOWN and speaks about evidence integrity only.

## Threat assumptions shared by all modules

* The agent (and any content it reads) is hostile and may try to widen its own authority, replay or retarget approvals, race a check, forge or delete its own evidence, and reach hosts outside the task.
* The enforcement point, the evidence services and the independent receivers are trusted and not compromised, except in the scenarios that say otherwise (P49 compromised collectors, P53 U02 deceived attestor).
* All traffic is to local mocks. The synthetic canary is `TEST_CANARY_NOT_SECRET`. No real model, no third-party or metadata host is contacted.

## Data schemas

Each module's result is `results/v2/<id>/result.json` with a `manifest.json` (definitions, python, machine, head, `result_sha256`). The integration harness reads only the fields `registry.headline` names; the mapping is explicit and tested. Evidence tokens follow `validate()` in `authority.py` (exact field set, claim ≤ 1024 bytes).

## Consequences

* The static check currently finds **six files outside fixtures and evidence services that create their own signer or authority** (`horizon/agents/isolation.py`, `horizon/coverage/regress.py`, `horizon/obligation/diff.py`, `horizon/reach/network.py`, `horizon/telemetry/collector.py`, `horizon/vision/browser_run.py`). Until each is moved onto the shared authority or justified as a fixture, ES-G2 is FAIL. A test pins this list so it cannot grow silently.
* The P39 oracle imports the system's `Endpoints` model for its port list; ES-G3 is FAIL until that dependency is removed or reviewed and recorded as data-only.
* A single shared end-to-end world for all fifteen modules does not exist. Each module keeps its own world; P54-04 is therefore not done.

## Alternatives not taken

* Letting each module keep its own signer: rejected by decision 1; it is the state ES-G2 flags.
* A single world with all fifteen guards chained: not built; the interactions between guards (for example P52 approval binding together with P53 migration) have not been studied here and are not claimed.
