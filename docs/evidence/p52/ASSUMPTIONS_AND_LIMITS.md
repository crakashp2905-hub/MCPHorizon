# P52 HorizonTemporal — assumptions and limits (CANDIDATE)

Status: **CANDIDATE**. Nothing here is VERIFIED. The promotion gate (independent review, a real service integration, a live-model agent) is not met and is not simulated.

## State vector and version semantics (P52-01, 02)
An export approval is granted in a state vector: object (id, version, class), content digest, principal grant (version, scopes), a digest of exactly the two rules that decide the action (`export.<class>`, `dest.<host>`, each with its own version), destination (host and a digest of the addresses it resolved to), and a logical revocation clock (event-log sequence number). An approval is valid at the effect boundary iff every field is unchanged, the policy function still permits the action in the current state, and the token is unexpired on the authority's clock, unrevoked and unused. "Unchanged" is conservative: a version bump with no policy consequence invalidates the approval; the legitimate path is re-approval, counted separately as a justified re-approval when the state really changed and as a false block when it did not.

## Scoped theorem (what the suite can support, and what it cannot)
*If* (a) the effect service evaluates the check and applies the effect in one transaction (or the sink supports a conditional write on the object version), (b) the revocation feed is readable and a revocation is appended to the event log before it is observed by anyone, (c) the dispatch worker consults the authority's clock, not its own, (d) the approval service issues only for the state it reads inside its own transaction, and (e) approvals are signed by the shared HorizonPolicy authority and verified with public keys only, *then* no approval is honoured in a state other than the one it was granted in, and no approval is honoured twice. This is **not a proof**. It is a statement checked on 13 attack scenarios under every interleaving of their steps, 10 benign controls, 2 unsupported-sink paths and 2 telemetry-offline paths, all written by the same author as the gateway (machine-checkable form: `results/v2/p52-temporal/invariants.json`, I1–I5).

## What the interleaving explorer is, and is not
It enumerates every order of the actors' steps that respects the declared "happens before" constraints (a scenario's `before` list). That is exhaustive for the scenario as written; it says nothing about orders of steps the scenario does not contain, about more than a few actors, or about real thread scheduling, partial failures or crashes mid-transaction. The store tests include a threaded compare-and-swap and last-write-wins test on a shared SQLite file, which is a real-concurrency check of those two operations only.

## Unsupported cross-provider atomicity and delayed effects (P52-15)
- **No conditional write at the sink (U01).** The check and the provider's application of the effect are two steps; a reclassification can land between them. The gateway cannot prevent that. It reports the outcome UNKNOWN, never a verified success.
- **Deferred external effect (U02).** The provider queues the export and applies it later, without revalidation. Same: a deferred effect is reported UNKNOWN.
- **The UNKNOWN flag is produced by the sink interface**, not by any system's cleverness: every system, baselines included, receives the same status for those sinks. The claim for the gateway is only that it never reports such an effect as verified. Cross-provider atomicity needs the provider's cooperation (a conditional write, an idempotency key plus a status endpoint, or a two-phase commit) which this module cannot supply.
- **Revocation feed outage.** With the feed down, the gateway fails closed (UNKNOWN, no effect); a benign export is blocked as well (F02). That is the intended availability cost; the `fail-closed` ablation shows the alternative lets a cancelled approval through.

## Other limits
- The HTTP carrier is a model: DNS and redirects are a dictionary (`net.py`), there is no network access, only synthetic hosts (`*.test`) and the canary `TEST_CANARY_NOT_SECRET`. TOCTOU between a real resolver and a real connect is not exercised; the model pins the addresses the check saw, which is the mitigation, not a demonstration of it.
- The reviewer is a mechanical ideal-attentive proxy (approves iff the policy permits the action now). No human study.
- The oracle, the store, the gateway and the baselines are by one author. The oracle imports nothing but `json` and reads only the effect service's record, the approval ledger and the event log; that makes it independent of the gateway code, not independent of the author's idea of the property.
- Ablations: several mechanisms overlap (object-version covers class/content/id; policy re-evaluation covers the slice digest and the grant check). The ablation table lists the redundant ones; `tests.p52.test_temporal.EachMechanismAlone` exercises each with its overlapping mechanisms switched off so none can regress unnoticed.
- Overhead is measured with `scripts/p52_bench.py` (machine-specific, not recorded) and relative only; the gateway adds a bounded number of local store reads, one signature verification and a name lookup per effect.
- Not covered: multi-object transactions, partial exports, approval delegation chains, clock jumps on the authority itself, or crash recovery of the ledger.

## Mutation testing
`scripts/p52_mutants.py` applies each mutant to a copy of the tree and requires `tests/p52` to fail; a timeout counts as killed. Mutants of `scenarios.py` are not included.
