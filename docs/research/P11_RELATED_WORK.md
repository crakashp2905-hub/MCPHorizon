# Related work and novelty review (P11-05) — INCOMPLETE

**Verification status.** Only the CaMeL entry below was confirmed against a live source in this session (arXiv listing 2503.18813). Every other entry is cited from memory and is **unverified**; check each before use. A systematic literature search has not been done, and novelty is not established.

| Work | Relevance | Status |
|---|---|---|
| Debenedetti et al., *Defeating Prompt Injections by Design* (CaMeL), arXiv 2503.18813 | Separates control and data flow, capabilities on values, custom interpreter; closest design to lineage-at-boundary. Not compared here (P9-10). | verified exists |
| Denning, *A lattice model of secure information flow*, CACM 1976 | Label lattice and join used here (a 4-chain). | from memory |
| Myers & Liskov, decentralized label model (SOSP 1997) | Declassification by owners; our signed purpose-bound declassifier is a much weaker analogue. | from memory |
| Leveson, *Engineering a Safer World* (STPA), MIT Press 2011 | Hazard-analysis framing for the threat model. | from memory |
| Multi-agent / "multi-CaMeL" and tracked-capability systems; MCP and tool-poisoning protocol studies | Required by P11-05; not reviewed. | NOT REVIEWED |

**Honest novelty statement.** Applying operator-labelled lineage at the byte boundary across MCP, UTCP and Code Mode, with an independent-oracle benchmark, is an engineering integration. Whether it adds anything beyond CaMeL-style capability tracking is unknown.
