# Paper D (draft): Can model-agnostic external enforcement prevent the effects of rare or unknown model-internal trigger activations?

**Status: DRAFT, CANDIDATE. Scripted toy models only; no real weights, no live model.** Every number is generated from committed result files by `scripts/p38_papers.py`.

**Hypothesis (spec §53.2):** external enforcement (artifact intake + isolated runtime) prevents verified forbidden effects of rare or unknown model-internal trigger activations even when behavioural screening misses them, without degrading legitimate workflow success.

## Completed experiments used
* P32 trigger lab (`results/v2/p32-triggerlab`): scripted toy model with a conditional behaviour, 4 trigger families, 10 seeds, 1,200 runs, paired clean/near-trigger/triggered tasks.
* HMIB (`results/v2/h4-main`): 16 attack and 4 benign model-supply-chain scenario types.
* P29 HAA runtime results (`results/v2/haa-main`) for the runtime layer.

## Results
| Policy | Triggered runs with forbidden effect | exact 95% CI | False blocks on clean tasks | Clean tasks completed |
|---|---|---|---|---|
| B0_none | 40/40 | 0.912–1.000 | 0/120 | 120/120 |
| B1_tool_name_classifier | 30/40 | 0.588–0.873 | 0/120 | 120/120 |
| B2_output_filter | 30/40 | 0.588–0.873 | 0/120 | 120/120 |
| B4_isolated_runtime | 20/40 | 0.338–0.662 | 0/120 | 120/120 |
| B6_full_horizon | 0/40 | 0.000–0.088 | 0/120 | 120/120 |

Zero forbidden effects in 40 triggered runs gives an exact one-sided 95% upper bound of 0.0722 on the per-run rate **for this toy model and these 4 families**.

Leave-one-trigger-family-out (policies tuned on the other families):
* B1_tool_name_classifier: f_cmd 3/3, f_dest 3/3, f_path 3/3, f_tool 3/3
* B2_output_filter: f_cmd 3/3, f_dest 3/3, f_path 3/3, f_tool 3/3
* B4_isolated_runtime: f_cmd 0/3, f_dest 3/3, f_path 3/3, f_tool 0/3
* B6_full_horizon: f_cmd 0/3, f_dest 0/3, f_path 0/3, f_tool 0/3

Model-supply-chain suite HMIB, attack types with a forbidden effect (of 16):

| B0 | B4 intake+codegate | B6 | B7 |
|---|---|---|---|
| 16 | 1 | 0 | 0 |

## Negative and limiting findings
* B1 (tool-name classifier) and B2 (output filter) each leave 30/40 triggered runs with a forbidden effect: behavioural screening misses what it was not fit on, as hypothesised.
* B4 (isolated runtime alone) leaves 20/40: containment without egress policy for a family does not help.
* Intake (B4 on HMIB) stops all but HMIB-19 (the behavioural scenario): **intake cannot see a dormant trigger inside approved weights**, and the report marks behavioural trust UNASSESSED by design.

## Not shown by this draft
* any statement about real models: a toy model's trigger is a function we wrote (live-model testing, L3, NOT RUN)
* prevalence of backdoors in public model hubs
* that screening cannot work: the screens here were deliberately simple
* independent replication
