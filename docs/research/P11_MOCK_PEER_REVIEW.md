# Mock peer review (P11-19) — SELF-REVIEW, not independent

Written by the same author as the work. It lists the objections a hostile reviewer would raise. It does not replace an independent review.

| # | Fatal or serious flaw | Rebuttal available? |
|---|---|---|
| F1 | A trivial run-level rule ties the full system on the original benchmark. | **No.** Conceded in the paper; claim narrowed. |
| F2 | The workloads that separate them were written after seeing F1, by the same author, 8 benign cases. | No. Disclosed as post-hoc and non-confirmatory; needs an independent set. |
| F3 | Scripted agents, no LLM; templates authored by the defence author. | Partial: blinded handles, independent oracles. Does not remove author bias. |
| F4 | Labels not independently annotated (P8-17). | No. |
| F5 | No comparison with CaMeL or any published system; baselines are author-implemented and simple. | No. |
| F6 | Known misses (reversed, chunked) and undetected paraphrase. | Conceded; documented as limits. |
| F7 | Tiny test split, clustered scenarios; intervals wide. | Partial: cluster bootstrap reported. |
| F8 | No performance/overhead measurement for the full pipeline. | No. |
| F9 | Epistemic extension could be read as truth inference. | Rebuttal: stated as conditional risk only. |
| F10 | Results directory rules were broken once (overwrite). | Disclosed in `results/v2/DEVIATIONS.md`; originals restored. |

**Verdict of the self-review: do not submit.**
