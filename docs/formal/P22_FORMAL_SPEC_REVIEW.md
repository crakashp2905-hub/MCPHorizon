# Formal-spec self-review (P22-15) — by the author, NOT independent
Premises that are not justified or that fail in places:
1. **Honest mediation.** All proofs assume every effect passes a gate. Raw network/process access in the agent runtime voids them (P21 `raw` channel succeeds without the mediation layer). The repo contains no enforcement of egress closure beyond the arena model.
2. **Label soundness.** Taint results assume labels are attached by the runtime, not by the agent. Model re-typing of read data (no lineage) is untracked; DLP in the arena knows only plain/b64/hex.
3. **Independence of evidence (P16).** "Independent" means disjoint provenance roots as declared by the evidence producer; roots are not themselves authenticated beyond the HMAC. A forger who controls two roots defeats it.
4. **Attenuation theorem (P15)** is conditional on signature soundness and uncompromised issuer/delegator keys (stated). It says nothing about what a *permitted* action does.
5. **Equivalence (P14)** is a kernel of a projection over six fields; causality is optional; algebraic invariance (P14-12) was *not* proved.
6. **Clock and revocation freshness** are assumed current; no distributed revocation protocol is specified.
7. **Transactions (P17)** assume the resource ledger is trustworthy and written by the resource, not the agent.
8. **Simulated components (P22)** make all cost/latency claims illustrative.
Proof gaps: no mechanised proofs; property tests only. This review must be redone by an independent party before any claim of soundness.
