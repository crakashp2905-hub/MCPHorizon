# Paper G (draft): Can agent-runtime provenance and AI-specific configuration contracts supplement existing CSPM/SAST tools?

**Status: DRAFT, CANDIDATE. Synthetic configurations; the one real-tool comparison was format-limited and is reported as such.** Every number is generated from committed result files by `scripts/p38_papers.py`.

**Hypothesis (spec §53.2):** provenance plus AI-specific configuration contracts catch AI-service exposure regressions earlier, as a complement (not a replacement) to commodity posture scanners.

## Completed experiments used
* P36 comparison (`results/v2/p36-checkov-compare`): checkov 3.2.0 vs InfraGuard on 4 bad and 1 good fixtures.
* HIEB (`results/v2/h4-main`): 14 attack types, live loopback probes (7) and configuration-fact oracles (7).

## Results
* P36: InfraGuard flagged 4/4 bad fixtures (false positives 0); checkov flagged 1/4 with 4 fixtures in a format it does not parse.

HIEB attack types with a live exposure (of 14):

| B0 | B3 emulated generic scanners | B7 |
|---|---|---|
| 14 | 10 | 0 |

## Negative and limiting findings
* The P36 comparison cannot support a claim that InfraGuard beats checkov: the fixtures use InfraGuard's own annotated format.
* The HIEB 'generic scanner' is a three-pattern emulation, not a product.
* Seven of fourteen HIEB oracles are configuration facts, weaker than live probes; no off-loopback listener was ever bound.
* Drift between reviewed and deployed configuration is caught only if the deployed document is linted at deploy time.

## Not shown by this draft
* any real cloud environment or provider
* breadth parity with CSPM products
* earlier detection in a real pipeline (no timing study)
