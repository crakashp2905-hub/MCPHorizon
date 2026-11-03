# ENG-PR03 — CanonicalEffect + commit-time permit verification (E03-01..03; HARD-B03 subset) — CANDIDATE

Source: main 2fe4a69 + this PR. Code: `horizon/effects/canonical.py`, tests `tests/e03` (16), mutants `scripts/e03_mutants.py` (7/7 killed).

Design: reuses the existing P13 signed AuthorizedEffect + `Verifier` (unchanged, frozen schema). `CanonicalEffect` derives every verifier input from one object; session and server are bound via a
domain-separated args digest, so a permit minted for one session/server is refused in another. Unknown effect types fail closed. A refused check does not consume the nonce.

Negative tests: altered args, destination, session, server, tenant, principal, effect type, policy version, expiry, missing token, empty/NUL fields, replay.
Limits: issuers must compute the same `bound_args_digest` (no issuer-side helper wired into CallAuthority yet); nonce store is the existing SQLite store (atomicity/crash tests are ENG-PR04); not wired
into any adapter (ENG-PR05); no independent review. Reproduce: `python3 -B -m unittest discover -s tests/e03 && python3 -B scripts/e03_mutants.py`
