# Negative results and post-hoc changes register (blueprint S0-05)

Append-only. Entries are never reworded into successes. Each states what failed, how it was found, and what changed afterwards (post-hoc changes are labelled).

| # | Result | Source | Post-hoc change / status |
|---|---|---|---|
| N1 | HorizonReach: a dishonest external service leaked on the FIRST call in 3 of 45 attack runs of the original suite | blueprint §5; `paper/MANUSCRIPT.md` | First-call disclosure remains an open limitation; not fixed. |
| N2 | SecBench: the full system tied the simple read-then-send baseline | blueprint §5; `paper/MANUSCRIPT.md` | Baseline B1 is mandatory in every future comparison. |
| N3 | Live-agent lab (Qwen2.5-0.5B, n=24/cell): gate cut attacker effects 18/24 -> 0/24 but user task under attack succeeded 0/24 (model loops on the blocked call) | `research/live/results/live_qwen05.json`, `docs/evidence/live/ASSUMPTIONS_AND_LIMITS.md` | Gate rule was changed POST HOC (word tokens blocked a legitimate email -> identifier-token rule). Utility is NOT recovered. |
| N4 | Weight-space run: a 64-entry edit moved a target logit and rolled back exactly; it is NOT a safety repair | `research/weightspace/results/real_qwen05.json` | Kept research-only; no security-effect metric exists yet. |
| N5 | Commit protocol: reconcile-by-read let a late worker write after RECONCILED_BLOCKED (zombie race); AUTHORIZED effects with a dead authorizer were never resolved | `docs/evidence/commitproof/ASSUMPTIONS_AND_LIMITS.md` | Fixed post hoc with sink-side fence-and-observe and orphan expiry (PR #60). Model is bounded, one effect, one host. |
| N6 | Permit fuzzer flake: `sig_flip` was a no-op for ~1/256 signatures because the last base64url char carries 4 ignored padding bits | `docs/evidence/novel/ASSUMPTIONS_AND_LIMITS.md` | Fuzzer fixed. The verifier still accepts the 16 non-canonical spellings of a signature (malleability, not forgery); UNFIXED, needs owner decision (Rust/TS parity). |
| N7 | p30 HAA-02 `test_b6_prevents_and_controls_pass` failed once on CI, passes locally, did not recur | CI run on PR #57 | Root cause UNEXPLAINED. |
| N8 | My own earlier PR-comment attributing the novel_mutants failure to a "runner flake" was wrong | PR #57 | Corrected on the PR after root-causing N6. |
| N9 | PR #60 CI: a mutation-script pattern went stale after a model edit, so the mutant run failed with MISSING | PR #60 | Pattern fixed (3e6bc00); local run before push had not exercised the final source. |
| N10 | No independently signed module closure: 0/282 hardening gate tasks closed by an independent reviewer | `docs/evidence/hardening/ASSUMPTIONS_AND_LIMITS.md` | Unchanged. |
| N11 | Offline replay cannot measure downstream agent adaptation | blueprint §5 | Live runs are small and weak (N3). |
