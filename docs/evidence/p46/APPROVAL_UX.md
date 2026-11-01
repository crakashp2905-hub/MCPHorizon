# P46-15 Approval UX for a necessary but risk-increasing fallback (CANDIDATE)

When no candidate meets the floor but one violates only *waivable* dimensions (or is an incomparable trade-off), the guard returns REVIEW and the gateway produces an approval request bound to the exact action. The screen is rendered by `engine.render_ux` and pinned by a golden test (`tests/p46/golden_approval_ux.txt`).

## What the approver sees
- The task, who asked, and the exact action: operation, endpoint, tool, credential scope.
- A table with one row per mandatory guarantee: **required**, **original endpoint**, **this fallback**, and a result: `ok`, `WEAKER THAN REQUIRED` or `NOT VERIFIED`.
- Why it needs a human, as machine reasons (for example `transport:UNSAT`).
- The authority being granted: *this action, once, for 300 seconds*; it does not lower the task's floor; it cannot be reused for another endpoint, tool, argument or credential scope; the requester cannot approve their own request.

## What the approval is
An APPROVAL token whose `args_digest` is the digest of {task, floor digest, the endpoint's profile digest, endpoint, tool, operation, argument digest, credential scope}. Change any of them — a different endpoint, a different file, a wider scope, a newer profile of the same endpoint — and the digest differs, so the approval is refused (`APPROVAL_NOT_BOUND_TO_THIS_ACTION`). A used approval is refused (`APPROVAL_ALREADY_USED`); an approval signed by the requester is refused (`SELF_APPROVAL`); one for another task is refused.

## What cannot be approved
Non-waivable dimensions (authentication and audit in the recorded scenarios) are BLOCK, not REVIEW: no screen is shown. UNKNOWN values show as `NOT VERIFIED`.

## Evidence and limits
Tests check the screen contains the weaker-guarantee marker and the single-use / not-reusable / no-self-approval statements, and that the golden text does not change. They do not show that a human reads it, that the wording is understood, or that approvers do not habituate; no user study was run. Scenario A12 (replayed approval) and B06 (approved necessary fallback completes once and is not counted as a violation) exercise the binding.
