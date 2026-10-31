# P9 results, negative results and bounded claims (P9-21, P9-24)

Source: `results/v2/p9_comparative.json` (regenerate with `scripts/repro_p9.sh`; integrity in `results/v2/p9_MANIFEST.json`). SecBench 0.2, scripted agents, **exploratory**: see `P9_PREREGISTRATION.md`. Gate G6 is **not** opened.

## Test split (30 harmful + 30 benign; attacker success / benign utility)
| system | attacker success | benign utility |
|---|---|---|
| B0 open | 30/30 | 30/30 |
| B1 name heuristic (blinded) | 30/30 | 30/30 |
| B2 endpoint allowlist | 28/30 | 28/30 |
| B3 read+send pair | 2/30 | 26/30 |
| B4 exact taint | 14/30 | 30/30 |
| labels_only | 12/30 | 26/30 |
| full | 2/30 | 26/30 |

Primary pre-registered comparisons (full vs B0/B1/B2/B4, Holm over four): all satisfy the registered rule, but the template-cluster intervals are wide (only 10 test templates) and B0/B1 are trivial baselines.

## Negative and uncomfortable results
1. **B3 ties `full` on attack success in the 0.1 templates (2/26 each) and has *better* utility (26/26 vs 22/26).** In those templates benign runs never touch a SECRET source, so a crude "no external send after a secret read" rule is enough. H4 (competitor hypothesis) is therefore supported for SecBench 0.1.
2. The advantage of `full` over B3 appears only on the post-hoc S templates (sensitive-but-benign: the run reads a SECRET but sends only public bytes): B3 blocks all 8 benign S runs, `full` completes 8/8 and blocks 0/8 harmful. These templates were written after seeing result 1, 8 benign cases, one author: treat as a counterexample to B3, not as evidence of general superiority.
3. `full` still leaks the reversed-secret case (C5 on test, chunked C4 on dev) and costs benign utility (K1/K2/E1/E2/U4: unknown transport, unmapped endpoint, true-but-untrusted claims, CLI).
4. B1 equals B0 once names are blinded; it only "works" on the unblinded leaky view (P8 demonstrates this).
5. B2 (endpoint allowlist) stops almost nothing: the exfiltration goes to an *approved* host with secret bytes.
6. `full-no-manual-trust` lost benign utility relative to `full` (24/30 vs 26/30) although removing a check should not reduce completions; not investigated, so no claim is made about it.
7. Transport equivalence (P9-17): secret bytes are blocked on every transport, but benign public bytes are blocked on `cli.upload` and `ws.send` in all gated systems (semantic disagreement = utility loss, not a leak).
8. Found by running at scale: the P3 audit log leaked one file descriptor per service instance, crashing a ~1000-run sweep (`select()` fd limit). Fixed (`AuditLog.close`, `__del__`) with regression tests. The first P9 sweep had 14 spurious ERROR rows from this; all committed results are from the fixed code and contain no ERROR/TIMEOUT rows.

## Denominators
Attacker success is over harmful scenarios of the subset; utility over benign scenarios. BLOCKED/REFUSED = attack prevented and utility lost. TIMEOUT/ERROR would be reported separately; none occur in the committed run.

## Not done (not simulated)
P9-02 and P9-19 model-seed variance (no LLM is used; determinism across 5 world seeds is shown, which is a different property); P9-08 legacy D3; P9-09 text-level guard; P9-10 CaMeL (not run, no compatible harness here); P9-12 capability-closure ablation (no separable module in this implementation); P9-16 static-preflight ablation (the scanner is not on the benchmark path). Intervals use template clusters because scenarios within a template are near-duplicates.

## Bounded claims
Supported (exploratory): on SecBench 0.2, `full` prevents the scripted exfiltration patterns that no-defence, endpoint-allowlist and exact-match baselines miss. Not supported: that `full` beats a coarse run-level read+send rule on attack success; that results transfer to LLM agents or real deployments; any detection rate for unseen attacks.
