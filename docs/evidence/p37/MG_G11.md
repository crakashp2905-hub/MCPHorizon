# MG-G11 — independent actual-effect oracle (P37) — CANDIDATE

**Statement.** For every one of the 63 attack scenario types in HMIB, HCCB, HECB and HIEB, the recorded `effect` comes from an oracle that does not consult the guard's own decision (see `ORACLES.md`; `tests/p37/test_h4.py::Oracles` feeds each oracle a world where the guard says "fine" and checks the oracle still reports the effect). 74 scenario types have a matched benign control (63 attack types each with a paired control, plus 11 benign-only types); 0 harness errors and 0 unstable outcomes in `results/v2/h4-main`.

**Gate status: MET for the narrow claim above. NOT a security-effectiveness claim.**

## What remains only synthetic
* All fixtures are local, inert and synthetic: byte strings instead of weights, a scripted toy model instead of a trained one, loopback `SyntheticService` instead of real infrastructure, an in-process broker instead of a deployed one.
* HMIB-19/20 use the P32 scripted toy model. **Live-model testing (L3) is NOT RUN.** A real backdoored model, a real agent runtime and real tool traffic have not been exercised.
* HCCB: 4 of 18 scenario types have a behavioural exploit oracle; 11 use ground truth by construction (the defect was built in). Generated code comes from a scripted toy model, not an LLM.
* HECB: single-process; no network, timing or resource-contention covert channels; collector death is simulated in-process (the real out-of-process collector is covered by P35 tests).
* HIEB: 7 types are live loopback probes; 7 are configuration-fact oracles; **no off-loopback listener was ever bound**. B3 is an emulation of generic scanners, not a real scanner.
* **Pilot / real-user deployment (L5) is NOT RUN.** No independent reviewer has reproduced or audited any of this (MG-G12 is not claimed here).

## Known uncovered case (a measured negative finding)
`HCCB-06` (debug interface left enabled) is exposed under **every** baseline including B7: no layer has a rule or an oracle for it. 62/63 is the honest number, not 63/63.

## Authorship / selection bias
The suites, guards and baselines were written together by one author around the same threat classes. The high B7 reduction is therefore *coverage of designed-for classes*. B1/B2 showing zero benefit here does not generalize: the P29 benchmark shows the sandbox's value on a different class.
