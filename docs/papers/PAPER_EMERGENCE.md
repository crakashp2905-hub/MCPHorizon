# Paper artifact — Effect-aware discovery of unsafe composition from individually allowed calls (CANDIDATE)

*Falsifiable claims, scoped assumptions and a verified witness. Synthetic loopback only; not a security guarantee.*

## Claim C1 (witness)
Under a direct-call policy that allows every call below, the sequence `read_secret → b64 → get(partner /redir?to=<third party>)` delivers the canary to a third party. Verified by the receiver journal: leak = **True**. The matched control (`hash` instead of `b64`, same endpoint) leaks = **False**. Tool-name co-occurrence cannot separate the two (D3 alerts on both).

## Claim C2 (scoped bounded completeness)
**Assumptions.** (A1) Each transform summary over-approximates taint (unknown transforms preserve taint). (A2) The delegation table of every *modeled* endpoint is complete. (A3) Chains have at most 4 steps and 4 live values. (A4) The sink policy is "tainted data may only reach secure sinks".
**Statement.** With unbounded search budget, every chain within A3 that violates A4 through modeled endpoints is enumerated as a candidate. Chains touching an unmodeled endpoint are reported UNKNOWN.
**Falsifier.** An oracle-confirmed leak through modeled endpoints within A3 that is not a candidate. `tests.p39.test_emergence.Completeness` checks this on the labeled corpus: none found (corpus has only 4 leaking chains, so this is weak evidence).

## Claim C3 (what it does not claim)
No claim of general recall on real MCP deployments; no claim about covert channels, timing, partial-content leaks (the oracle cannot see them), or nested encodings (unscored).

## Measured
D0 recall 0.000; D3 recall 1.000 at FPR 0.491; emergence FPR 0.018 before and 0.000 after one evidence-scoped refinement; 2 leaking chains behind UNKNOWN. See `docs/evidence/p39/RESULTS.md`.
