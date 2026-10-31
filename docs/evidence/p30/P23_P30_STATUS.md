# P23–P30 status (CANDIDATE — nothing VERIFIED)

Exact commit: the commit that adds this file (see `git log -1 -- docs/evidence/p30/P23_P30_STATUS.md`); earlier phases merged in PR #22 and PR #23. Machine-derived task mapping: `docs/evidence/p23/BASELINE_GAP_REPORT.md`. Gates: `docs/evidence/HR_GATES.md`.

## Commands
```
python3 -W ignore -m unittest tests.p23.test_p23 tests.p29.test_haa
sudo -E env "PATH=$PATH" python3 -W ignore -m unittest tests.p24.test_sandbox tests.p25.test_broker tests.p26.test_creds tests.p27.test_managed tests.p28.test_artifacts tests.p30.test_p30
python3 bench/haa/aggregate.py results/v2/haa-main --check ; python3 bench/haa/report.py --check
python3 scripts/hr_gates.py --check ; python3 scripts/p30_no_external.py ; python3 scripts/p30_claims_audit.py
sudo -E env "PATH=$PATH" python3 bench/haa/run.py main --repeats 2   # refuses to overwrite results/v2/haa-main
```

## Results (derived from `results/v2/haa-*`)
B6 (full runtime): 0/24 unsafe effects, 24/24 matched controls; B0 24/24 effects; B4 (sandbox only) 3/24 effects but only 10/24 controls completed; B5 5/24 effects; scanners B1/B2 16/24 and 18/24. Held-out (6 tool families, new destination): B6 0 effects, 6/6 controls. Adaptive (60 attempts, seed 7): B6 0 bypasses, B0 31, B3 23. Launch latency p50 ≈ 0.06 s (B6) vs 0.05 s (B0).

## Failures and mistakes found along the way (disclosed)
- Real sandbox bugs found by new tests and fixed: inheritable fd 3 leaked without a broker; relay process held pipe ends so child stdin never saw EOF.
- Importer (L1) initially missed `/dev/tcp` and perl sockets; fixed.
- Early B6 pilot: HAA-21 (fork loop) had an effect and HAA-23's control failed (DLP applied to labelled reads); both fixed **after** being seen, so those two scenarios were tuned on and are not held out.
- `aggregate --check` initially reported MISMATCH (a `description` field added by run.py); fixed in the checker, not by editing results.
- A first benchmark pass was too slow (repeated settle sleeps); patched before the recorded run.

## Unsupported / not done here
- IPv6 channels (VM has no IPv6) — **P30-02 is therefore only partly covered and left unmapped.**
- P29-07 (event-level audit/oracle agreement at every layer) is covered only at broker/receiver level — left unmapped.
- P29-15 (origin distinctions) is encoded in the schema vocabulary and prereg but never exercised with a live model — left unmapped.
- P30-10 (reproducer for every failed scenario): `scripts/p30_repro.py` reproduces baseline failures (e.g. HAA-14 under B5); B6 has none. Left unmapped pending a test.
- P30-11 (regression test per discovered bypass) and P30-16 (Paper D/E from raw runs) — not completed.
- L3 live model, L5 pilot, independent review (HR-G7, HR-G9), P24-02/-03/-12/-18, Cohere dataset licence.

## Next actions
1. Independent reviewer runs the signed bundle (`scripts/p30_reviewer_bundle.py`) on a different kernel and IPv6-capable host.
2. Run L3 from the pre-registration when a model endpoint is available.
3. Add P30-10/11 tests; write Paper D/E from `docs/evidence/p29/RESULTS.md`.
