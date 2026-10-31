# Artifact assurance: residual risk, exception process, measured cost (P28-14/15/17/18) — CANDIDATE

## What the gate decides (and does not)
Scanner findings (bandit SAST, SCA against a pinned advisory snapshot, secret scan, dependency policy) and exploit-oracle results are **separate fields**; they are never averaged into a score. `ALLOW` requires every control to have produced evidence; missing evidence is `UNKNOWN`, which is not releasable.

On the 4 vulnerable fixtures bandit **blocked 1 of 4** (command injection, B602). SQL injection was only a MEDIUM/LOW-confidence advisory; path traversal and the header-trust authorization flaw produced no finding at all. The local exploit oracle confirmed all 4 and confirmed all 4 patched counterparts clean with identical benign behavior. This is a fixture set of 4 classes, not a detection rate.

## Residual unknowns (P28-17)
* Vulnerability classes with **no dynamic oracle** here: memory-safety bugs, race conditions/TOCTOU, cryptographic misuse, deserialization gadgets, supply-chain compromise inside an *allowed* pinned package, business-logic flaws without a hand-written exploit, anything needing a real network peer. Gate output lists `NO_DYNAMIC_ORACLE` as residual for such artifacts.
* The oracle only knows the exploit we wrote; a different exploit of the same flaw class is not tried.
* SCA is only as good as the snapshot (a 2-entry synthetic DB in tests; no real advisory feed was pulled).
* Languages: Python only (bandit). Other languages are unsupported, not "clean".

## Release exceptions (P28-18)
A blocked artifact may be released only with an `exception_permit`, which requires a signed approval whose **role is `admin`**, scoped to the exact artifact digest and destination, bound to the policy digest, and unexpired. Agents and ordinary users cannot mint approvals (`ROLE_NOT_AUTHORIZED`). Exceptions are recorded in the release row. *Authentication of the human is out of scope here:* the approval signature proves possession of an admin key, not identity.

## False blocks & cost (P28-14/15)
* Benign apps + patched fixtures: **0 of 7** blocked (denominator 7; no rate claim). Changed-dependency cases: 3 of 3 decided as intended (pinned fixed version ALLOW, vulnerable pin BLOCK). Bandit `LOW` findings (e.g. B404/B603 on the patched command fixture) do not block by design.
* Cost on the fixture set: whole evidence collection ≈0.2 s per fixture; bandit peak RSS and seconds are recorded per run in `evidence()["scanner"]["sast"]`. Sandboxed build of a 2-file project: well under a second. Legitimate build completion under the sandbox: 2/2 builds in tests (plus the compiler/test-runner workflow in P27).

## CI status labels (P28-16)
`scripts/security_gate.py` prints `PASS` only if every expectation was met with all tools available; `UNSUPPORTED` when the oracle cannot run (no root/Landlock); `UNKNOWN` when evidence is missing; `FAIL` otherwise. CI runs it under sudo on every branch and reports the branch name.
