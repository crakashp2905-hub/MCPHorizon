# ENG-PR04 — Durable EffectLedger, atomic nonce reservation, at-most-once dispatch (E04; HARD-B04..B08 subset) — CANDIDATE

Source: main 2fe4a69 + this PR (independent of ENG-PR03). Code: `horizon/effects/ledger.py`; tests `tests/e04` (17); `scripts/e04_mutants.py` (12/12 killed).

Guarantees tested: illegal transitions rejected (full state x state matrix); `begin()` is won by exactly one of 100 concurrent threads; a nonce can authorise exactly one effect (100-way race, one winner);
state and nonces persist across close/reopen; crash after STARTED -> recover() marks UNKNOWN, `begin()` then refuses, only an independent sink observation reconciles; failed transitions leave no history.

Limits (honest): SQLite on one node, threads in one process (cross-process contention not tested here); no leader fencing/epochs, so multi-instance takeover (HARD-B05) is NOT covered and is BLOCKED_EXTERNAL
(needs an external durable store); a hard power-loss test was not run; not wired to the gateway or Verifier's NonceStore (ENG-PR05 integrates); no independent review.
Reproduce: `python3 -B -m unittest discover -s tests/e04 && python3 -B scripts/e04_mutants.py`
