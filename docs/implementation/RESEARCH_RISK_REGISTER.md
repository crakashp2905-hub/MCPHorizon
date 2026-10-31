# Research risk register — legacy ML predictor and detector claims (P0-13)

Initial entries derived only from the repo's own artifacts; severity is a proposed rating for maintainer review.

| ID | Risk / limitation | Evidence | Proposed severity | Consequence for claims |
|---|---|---|---|---|
| R-01 | Predictor "honest" evaluation has only 2 benign samples; AUROC cannot support deployment claims | `predictor_v2_honest_eval.json`: q1_n_benign=2 | High | No false-positive-rate or deployment claim |
| R-02 | Step-1 AUROC 0.18 (below chance) in the honest eval, contradicting headline P(DH)=0.998 | same file vs `README.md` | High | Headline number must be qualified or withdrawn until reconciled |
| R-03 | Detection equals a name flagger (D0≡D3) on TAMAS | `MCPWEEK6/ablation_report.md` | High | Do not claim detection superiority over name-based baselines |
| R-04 | sequence_injection LOOCV 68.8% and 44 failed week-2 cases (architectural gaps, TOOL_DB coverage) | `generalization_report.md`, `week2_score.json`, `week1_corrected_verdict.md` | Medium | Coverage claims limited to tools in TOOL_DB |
| R-05 | Circularity: horizon/hyperedges authored by the researchers; recovery by LLM proposer was "gated" on an experiment | `MCPWEEK6/circularity_report.md` | Medium | Treat discoverability as unproven until T2-10 numbers are archived |
| R-06 | Corpus is small and labels derived from the same authors; train/test partitions of one benchmark | LOOCV partitions files | Medium | Out-of-distribution claims need independent data |
| R-07 | Engine and predictor are proprietary/absent, so results are not reproducible from the public tree | `README.md` note; B-04 | High | No reproducibility claim for legacy results |
| R-08 | Live LLM evaluation is 10 scenarios with one small local model | `README.md` TAMAS table | Medium | Not generalizable across models |

Invalid deployment claims to avoid: "production-ready", "0% false positives" (n is tiny), "outperforms baselines" (R-03).
