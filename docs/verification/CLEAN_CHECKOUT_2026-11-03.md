# Clean-checkout reproduction (AUTHOR-RUN — not independent verification)
Commit `2a917ffa71c131a69d252bed20cdcb8a0e0ef607` (PR #48 head), fresh `git clone` into an empty directory, `python3 -I -B`, same sandbox host (so not a separate environment).
Results: tests e02 12, e03 16, e04 17, e05 15, hf 23 -> all OK. Mutants: e02 8/8, e03 7/7, e04 12/12, e05 13/13, hf 18/18 killed. Scans: secret_scan, p30_no_external, p31_inventory --check, p23_freeze --check, p94_status --check -> rc=0.
Meaning: the committed code reproduces its own checks from a clean tree. It does NOT establish correctness of the checks, absence of shared-author blind spots, or any research/release gate.
Host-limits: same machine class, same author, no hostile review. Independent verification still requires the sign-off below.
