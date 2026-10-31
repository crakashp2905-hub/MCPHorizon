# results/v2 — immutability rules (P0-18)

New v2 experiment evidence lives only under `results/v2/<experiment-id>/`.
1. Never edit or delete anything in `results/`, `MCPWEEK5/`, `MCPWEEK6/`, `MCPTox/`, `MCPSecBench/`, `TAMAS/` (legacy/frozen; hashes in `docs/implementation/p0/frozen_hashes.json`).
2. Each `<experiment-id>/` has a `manifest.json` (git SHA, command, seed, environment digest, input hashes) written once; corrections are new run directories, never overwrites.
3. Negative, failed and inconclusive runs are kept with the same rigor as positive ones.
4. Nothing here is labeled PASS unless a recorded command exited 0 on the manifest's revision.
