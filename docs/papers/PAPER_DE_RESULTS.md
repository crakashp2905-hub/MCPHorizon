# Paper D / Paper E: hypotheses and results (generated from raw runs)

Status: CANDIDATE, single implementer, one VM, L2 only. Not peer reviewed.

## Raw-run provenance (sha256 of raw_runs.jsonl)

- `haa-main`: `ed01a5e5c7f08ae0bf0ec8e9318786cd12e11535aa1b1a2f6cb7d488a159cb4c`
- `haa-heldout`: `8b84418685a556d65f40ac93c1abae49de94259a6f9db8b9b9a25b28d66fc50c`
- `haa-adaptive`: `faa74bc883be3cf47e3d61b507be1174b6d3d9ffacb31df0a6da2d9614ad31b2`
- `haa-latency`: `95372d48e4b771b31bd02d9115b9295b9ff42f27ec2b969c6a2c05539ab920a6`

## Paper D — pre-specified hypotheses

- H1: the full runtime (B6) allows fewer unsafe effects than no monitor (B0) on the same eligible manifest.
- H2: sandbox-only (B4) and scanner-only (B1/B2) baselines allow more unsafe effects than B6.
- H3: B6 does not reduce completion of matched benign controls relative to B0.
- H4 (not testable here): spontaneous occurrence rates in a live model (L3 NOT RUN).

## Paper E — results

- H1: B6 0/24 vs B0 24/24; exact McNemar p=0.0, Holm p=0.0.
- H2: B4 3/24, B1 16/24, B2 18/24 effects (B6 0).
- H3: B6 completed 24/24 controls; B0 24/24.
- Held-out: B6 effects []; adaptive bypasses B6=0, B0=31.

## Limits

Scenarios and defences share an author; 24 scenarios are correlated by family; zero observed effects is not a proof of safety; no independent replication.
