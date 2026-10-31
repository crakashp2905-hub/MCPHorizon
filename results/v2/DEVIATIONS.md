# Deviations from the results/v2 immutability rules (P0-18)

Recorded honestly; nothing here was hidden, but the rules were not followed in two respects.

1. **Overwrite.** `results/v2/p8_secbench_dev.json` and `p8_secbench_test.json` (SecBench 0.1, commit e11e2e6, PR #13) were overwritten in PR #14 when the benchmark was bumped to 0.2. The originals are restored byte-identically under `results/v2/p8-secbench-0.1/` with a manifest, and remain in git history. The files with the old names now hold 0.2 results.
2. **Layout.** Earlier experiment outputs (`p3_load_test.json`, `p7_paired_study.json`, `p8_*`, `p9_*`) were written as flat files with their own checksums (`p9_MANIFEST.json`) instead of `results/v2/<experiment-id>/manifest.json`. From P11 on, new evidence uses experiment directories with a write-once manifest, and corrections are new directories.
3. The P9 study ran on code later modified (`bench/secbench/runner.py`, a comment-only change for the secret scan); `p9_MANIFEST.json` warns on code drift rather than failing.
