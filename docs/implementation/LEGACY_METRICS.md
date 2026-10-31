# Legacy metrics archive (P0-12)

Archived verbatim from existing artifacts at base commit `0ebad0c`. **Not re-run** (engine source absent; see BLOCKERS B-04). Values are the repo's own claims, not independently verified.

| Metric | Value | Definition / scope | Source |
|---|---|---|---|
| D0 vs D3 detection equivalence | identical alerts: Colluding 42, DPI 26, IPI 14 (of 50 each); 0 FP on 50 benign runs | D0 = alert iff any malicious-labeled tool invoked (no lattice); D3 = capability detector. Set of "D3 fires, D0 misses" is empty and so is the reverse. Reason given: every danger-horizon hyperedge needs a HIJACKED-scope premise produced only by malicious-labeled tools; TAMAS has no benign external-egress tool | `MCPWEEK6/ablation_report.md` lines 3–25 |
| Datalog ↔ Python closure equivalence | 218/218 (MCPTox 205, MCPSecBench 13), 0 mismatches | Same closure on every trajectory | `MCPWEEK5/equivalence_report.md` |
| LOOCV class detection | compositional_emergence 3/3, scope_corruption 59/59, sequence_injection 97/141 (68.8%) | Hold-out by attack class | `MCPWEEK5/generalization_report.md` |
| Week-2 in-scope detection | 158/203 = 77.8% (sequence_injection 97/141 clean, 44 failed; scope_corruption 58/59; compositional 3/3; benign 2/2) | Verdict string: "PREMISE PARTIALLY HOLDS — lattice helps but architectural gaps remain" | `MCPWEEK5/week2_score.json` |
| Honest predictor eval | step-1 AUROC 0.182 on 203 attacks / 2 benign; residual mean max-p 0.032 vs benign 0.0003 (44 residual, 2 benign) | Only 2 benign examples | `MCPWEEK5/predictor_v2_honest_eval.json` |
| README predictor claims | IPI in-dist P(DH)=0.998; MCPSecBench OOD 100% | Contrast with the row above | `README.md` §ML Trajectory Predictor |
| TAMAS colluding/legal live | 6/6 attack-conditional detections; 0/4 FP; 10 scenarios; qwen2.5:7b CPU | 4 non-detections attributed to model non-compliance | `README.md` |

## Reading note
The D0≡D3 result means the lattice, on TAMAS, added labeling/characterization but **no extra detections** over a malicious-tool-name flagger. Any v2 claim of "capability detection beats a name flagger" needs data where that gap exists (spec §0 / line 99).
