# P40-16 — Supported temporal operators, semantic limits, proof assumptions (CANDIDATE)

## Exactly these operators (`horizon/obligation/terms.py: OPERATORS`; a test pins this table to the code)

| Operator | Meaning |
|---|---|
| `PRE(e, a)` | action `a` may occur only if evidence `e` (valid *at the time of `a`*) was presented earlier |
| `ORDER(e1 < e2)` | evidence `e2` counts only if `e1` was valid when `e2` was presented |
| `POST(a -> e within d)` | after `a` commits, `e` must be presented within `d` seconds, else the task is frozen for guarded actions |
| `VALID(e, [from, until))` | evidence and obligation are only effective inside their validity windows, re-checked at action time |
| `ONCE(e)` | single-use evidence, consumed by the commit it authorised |

**Not supported:** unbounded `until`/`eventually`/`always`, negation over future events, quantification over principals or objects, real-valued or branching time, liveness ("the smoke test will eventually be presented" is only enforced as a deadline that freezes later actions — it does not force the test to happen), cross-task obligations, obligations whose discharge depends on an unmodeled external fact.

## Semantic choices that matter
* **Latest counted evidence wins.** Per obligation the engine keeps the most recent *counted* token. An older, still-valid approval is not a fallback. The reference model encodes the same choice, so the differential test checks the implementation against the stated semantics, not that the semantics are the only reasonable ones.
* **ORDER is checked at presentation time.** An approval presented while its prerequisite was missing or expired is rejected and not retained; presenting the test afterwards does not resurrect it.
* **Consumption.** `ONCE` evidence is consumed when the commit it authorised is ALLOWed, tracked in one verifier shared by all branches of an engine instance. Forks inherit presented tokens, not consumed state. Two separate engine instances (separate processes) do **not** share the consumed set: replay protection across processes needs a shared store, which is not built.
* **Idempotent retry.** A retried `op_id` returns the recorded decision and the caller must not re-send; this relies on the caller honouring `IDEMPOTENT_REPLAY`.
* **Unknown actions are denied** (`UNKNOWN_ACTION`), never assumed harmless; only actions the owner lists as unguarded pass without evidence.
* **Time** is an integer clock injected into the engine and authority; skew handling and monotonicity are the caller's problem.

## Proof assumptions (what the differential test does and does not show)
Claim tested: for every event string of length ≤ 6 over {T,A,S,X,K,C}, the engine's ALLOW/DENY decisions equal the reference model's (55,986 sequences, 618 ALLOW decisions in the reference). This is *bounded exhaustive testing against a second implementation of the same stated semantics*, not a proof. Assumptions: (1) one requester, one artifact, one argument set, one object version; (2) `K` expires all earlier evidence at once, so partial expiry and TTL interleavings are not explored; (3) cryptographic verification is correct (Ed25519 from the `cryptography` package); (4) the policy catalog is trusted and correctly authored.

## Other limits
Scenarios, catalog and engine share an author; the "static workflow" baseline is a run-record presence/order check, one plausible lint; evidence services run in-process (separate keys and state, same process) and only the deploy target is a separate process; no real CI, approval or signing systems were used.
