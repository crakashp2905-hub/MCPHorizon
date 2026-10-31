# Claims boundary (P30-18)

**Supported (CANDIDATE):** on one Linux VM, for 24 synthetic scenarios against local mock services, the full runtime (B6) allowed 0/24 unsafe effects and completed 24/24 matched benign controls; weaker baselines allowed more (see `docs/evidence/p29/RESULTS.md`, derived from `results/v2/haa-*`).

**Runtime containment is a different claim from model-weight attribution.** These experiments run scripted attacks; they say nothing about why a model would emit such code, whether weights are backdoored, or how often it happens spontaneously. Trace replay, prefix completion and spontaneous occurrence are not conflated; L3 (live model) was not run and the pre-registration is unexecuted.

**Not supported:** any statement that the system is secure, verified, or independently reviewed; any VERIFIED status; IPv6 coverage; behaviour on other kernels; behaviour against real cloud metadata services or third-party infrastructure (never contacted).

`scripts/p30_claims_audit.py` scans the evidence docs for weight/intent attribution and absolute-security language.
