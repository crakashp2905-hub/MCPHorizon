# P45 HorizonPrivacy — semantics, assumptions and limits (CANDIDATE)

## Units, threat model, accounting semantics (P45-01)
See the docstring of `horizon/privacy/units.py`. Protected unit: the individual (add/remove all rows of one person, per-individual row cap 1, values clamped to dataset-declared bounds). Budget scope: the dataset — one ledger shared by every principal, tenant, task and delegated agent; per-task and per-tenant allocations can only restrict. Principals are not part of the ledger key, so a new identity does not get a new budget.

## What is accounted, exactly (P45-03)
* Mechanisms: discrete Laplace (pure eps-DP, integer-valued) and classical Gaussian (0<eps<1). Sensitivity is computed by the service from dataset-declared bounds; a caller-supplied bound that differs is rejected.
* Accountants (each stateless over all charged entries): **basic** (exact rational arithmetic), **advanced** (Kairouz–Oh–Viswanath 2015, Thm 3.5, heterogeneous, delta chosen so total delta equals the budget's), **zCDP** (rho sums; Laplace eps costs eps²/2; conversion eps = rho + 2·sqrt(rho·ln(1/delta))). Float accountants accept only with a 1e-9 relative safety margin, so rounding can only make them stricter.
* The independent reference accountant (`reference.py`, 60-digit decimals, no shared code) agrees on every one of 9,802 random reserve/cancel/begin/expire decisions (see RESULTS.md) with zero ledger-allow/reference-deny cases.

## Release rule (P45-05, 13)
reserve → begin (mechanism starts) → commit (answer released with a signed receipt). Cancel before begin refunds; cancel or timeout **after** begin does not (the noisy value may exist). Unstarted reservations expire and refund. The same request id and query digest is idempotent (no second charge, stored answer returned, noise is keyed by request id so a re-execution cannot draw a new sample); the same id with a different query is refused.

## Non-DP disclosure is separate (P45-08, 09)
Raw aggregates need an authorization, an allowed purpose, a minimum cell count (10) and pass a differencing guard; exports need a signed approval bound to principal, dataset and purpose. None of them touches the DP ledger and none is described as private. Public datasets bypass both.

## What is NOT claimed (P45-15)
* No DP claim for raw aggregates, exports, record counts, error messages, response timing, response sizes, denial patterns (a denial itself reveals that budget was spent), or anything an LLM does with a released answer.
* The differencing guard is a heuristic over pairs of answered cells; combinations of three or more queries, or cells that differ by more than the minimum, are not detected. It is not a k-anonymity or DP guarantee.
* Accounting is per dataset. A person who appears in several datasets, or whose data was copied into a derived dataset, is not accounted across them.
* The Gaussian sampler is a double-precision Box–Muller and is not claimed to be exactly DP; Laplace noise is integer-valued to avoid the known floating-point attacks, but the geometric inversion still uses doubles.
* Tamper-evidence, not tamper-proofing: the owner-signed budget and the hash chain detect edits made without the owner key; someone who controls the database file and the service secret could rewrite everything.
* Collusion with a data owner or with the service operator is out of scope.
* MCP/UTCP/Code Mode are represented by carrier-level codecs (`carriers.py`); they are not wired into McpGate or the UTCP adapter.

## Findings worth knowing
* zCDP accounting is *stricter* than basic composition for a few pure-eps Laplace queries (2 vs 8 answers at eps 0.25) and far more permissive for many Gaussian or many small-eps queries (e.g. 5000 vs 100). Pick the accountant for the workload, not by name.
* Ablations: dropping the transaction overcommitted in every trial (+6 to +7 grants of 12) and broke the audit chain; dropping idempotency never exceeds the budget but resamples noise 8× for a retried id and denied later legitimate queries; the other ablations each lost exactly the scenario designed for them.
