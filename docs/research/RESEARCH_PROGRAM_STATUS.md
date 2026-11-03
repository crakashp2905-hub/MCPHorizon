# Research program status (HorizonZero/Forge, HorizonSpectra, Weight-Space Programming) — 2026-11-03

Nothing here is VERIFIED. States: DONE_CANDIDATE (code+tests, author-run), OPEN (doable, not started), BLOCKED_EXTERNAL (needs reviewers/compute/models/accounts), PRIOR_ART_NOT_RUN.

## HorizonForge / HorizonZero (HF-001..098)
| Items | State | Note |
|---|---|---|
| HF-008,010,011,013 (finite IR, unknown fails closed) | DONE_CANDIDATE (toy) | `horizon/forge/ir.py` |
| HF-031,032,034..039,041 (bounded enumerator, relocation, min cost) | DONE_CANDIDATE (toy, partial) | no SMT backend, no delegation/redaction synthesis |
| HF-040 (independent checker) | DONE_CANDIDATE (same author) | signed plan/proof artifact not done |
| HF-043..048 (indistinguishable worlds, negative certificate, missing witness) | DONE_CANDIDATE (toy) | HF-047 machine-checkable within the finite model only |
| HF-050..052,057 (durable ledger/nonce/permit/reconcile) | partly via ENG-PR02/03/04 | revocation epochs not done |
<<<<<<< HEAD
| HF-016..023 HorizonZero claim registry | OPEN | next candidate slice |
=======
| HF-016..021 HorizonZero claim registry | DONE_CANDIDATE (prototype) | `horizon/assurance/registry.py`; HF-022 crash-consistent revocation OPEN, HF-023 EXTERNAL |
>>>>>>> claude/novel-ideas
| HF-001..004,006,007 prior-art ledger/preregistration | PRIOR_ART_NOT_RUN / OPEN | the spec's cited sources were NOT re-verified here |
| HF-053..056,058,059 real protected sinks | OPEN (ENG-PR05) | |
| HF-060..067 30 world families, HF-068..075 baselines, HF-076..082 proofs, HF-083..098 eval/release | OPEN | large; no held-out data exists |
| HF-003,005,015,023,030,042,049,059,066,075,082,095,096,098 | BLOCKED_EXTERNAL / OWNER | independent experts, owner approval |

## HorizonSpectra (SP-01..30)
<<<<<<< HEAD
All OPEN. SP-02/03/05/21/29 BLOCKED_EXTERNAL (searches by independent reviewer, independent fixture author, external security reviewer). Doable next: SP-06,07,11..14,16,17,20 (toy worlds, random-probe baseline, UNKNOWN reporting).

## Weight-Space Programming (HP/HS/HT/HR)
BLOCKED: requires a pinned open-weight model, model downloads/inference compute (not allowlisted in this sandbox), a high-capability editor model run, and independent evaluators. The author-reported
figures in the source blog (7.9%->48.1% etc.) were NOT verified. Code-only pieces that need no model (patch manifest/validation, copy-on-write apply with rollback, stats helpers; HP-008,009,020,022) are OPEN and can be built as a small slice.
=======
SP-06,07,11,12,15..18,20 DONE_CANDIDATE (toy, `research/spectra`). SP-02/03/05/21/29 BLOCKED_EXTERNAL (searches by independent reviewer, independent fixture author, external security reviewer). Doable next: SP-06,07,11..14,16,17,20 (toy worlds, random-probe baseline, UNKNOWN reporting).

## Weight-Space Programming (HP/HS/HT/HR)
BLOCKED: requires a pinned open-weight model, model downloads/inference compute (not allowlisted in this sandbox), a high-capability editor model run, and independent evaluators. The author-reported
figures in the source blog (7.9%->48.1% etc.) were NOT verified. Model-free plumbing (HP-008,009,020,022,026 partial) is DONE_CANDIDATE in `research/weightspace/patch.py`; model experiments remain BLOCKED (HF hosts 403 as of 2026-11-03).
>>>>>>> claude/novel-ideas

## Stop conditions
No novelty, "first", or security-gain claim is made. Fair baselines (HF-070/071, SP-22) have not been run; if they match, the thesis changes.
