# Lineage coverage limits and claim vocabulary (P7-24)

Status: **CANDIDATE.** The study behind these claims is synthetic and self-authored (`bench/p7/study.py`, `results/v2/p7_paired_study.json`); it is not an independent benchmark.

## Claim vocabulary (use exactly these words)
| Word | Means | Evidence required |
|---|---|---|
| **possible** (`POSSIBLE_FLOW`) | A declared input has confidentiality ≥ CONFIDENTIAL (directly or by ancestry), so secret-derived content *may* be in the payload. | Lineage labels only. Says nothing about the actual bytes. |
| **blocked** | A request was denied and nothing was sent (decision service DENY, or `BOUNDARY` deny before send). | The gate's response plus the sink recording zero bytes. |
| **verified** (`VERIFIED_OUTBOUND_LEAK`) | A registered sensitive value's bytes (raw, or after percent/JSON/base64/base64url/hex decoding, bounded depth) were found in the payload about to leave. | Exact byte match at the boundary. Never inferred from names, labels or text claims. |

"Leak prevented" may be claimed only for scenarios where the oracle (ground-truth canary bytes) observed zero canary bytes leave under enforcement and ≥1 under the baseline. "Secure" or "no leaks" is never claimed.

## What the P7 code does
- Trusted sidecar assigns ids, labels (from operator config), parents and provenance; agents get opaque handles; forged label/lineage/provenance fields are rejected and audited.
- Conservative joins (max confidentiality, min trust); an unknown parent makes the value SECRET, UNTRUSTED and partial-lineage.
- Per-tenant sidecars; cross-tenant sharing only by an admin grant (scoped, expiring, single-use, revocable) that yields a *new*, untrusted, partial-lineage artifact.
- Purpose-bound, signed, one-time, expiring declassification; the declassified copy is usable only for its purpose and sink zones.
- Delegation can only narrow handles/purposes/expiry.
- Boundary check on the actual outgoing bytes (MCP tool arguments, UTCP URL and body) before send, in both gates.
- Verification relations require an independent, trusted verifier with non-empty independent evidence; unverified dependencies of a protected action get REVIEW. Factual truth appears nowhere in deployable code.

## Known coverage limits
1. **Paraphrase / semantic leaks are not detected.** If lineage is lost *and* the content is rewritten so no registered bytes survive, nothing flags it (study scenario `leak_paraphrase_lost_lineage` is allowed under enforcement). If lineage is kept, labels still catch it as a possible flow.
2. **Lineage is only as good as instrumentation.** Values processed outside `TV`/the sidecar lose tracking; only the byte-level boundary backstops that, and only for *registered* sensitive values of length ≥ 8.
3. **Agent-declared lineage can only add restriction.** Handles an agent lists (e.g. `_lineage`) cannot lower a label; omitting them is caught by the byte check, not by labels.
4. **Encodings covered are finite**: percent, JSON-unescape, base64/base64url, hex, one extra nesting level. Encryption, compression, splitting across multiple requests, steganography, or partial/fragmentary leaks (e.g. 7 of 24 characters per request) are not detected.
5. **Registered values only**: sensitive values come from sources the operator labelled CONFIDENTIAL or higher. Secrets from an unlabelled source (default INTERNAL) are not fingerprinted.
6. **Epistemic checks are structural.** Independence = no shared ancestry or origin, trusted verifier, non-empty independent evidence. A verifier that is trusted and structurally independent but wrong is accepted.
7. **Channels exercised**: MCP and UTCP gates directly, and Code Mode through the same mediator. Not exercised: stdio/HTTP transports end to end, multi-agent message passing through a real agent runtime (only the `agent` protocol label in lineage), real LLM paraphrase, streaming bodies.
8. The UTCP gate sends a JSON-encoded single argument as body (`body_arg`); multipart, streaming and large bodies are not modelled.
9. Declassification signatures are symmetric HMACs held by the process; there is no key rotation or separate signing service.
10. P7-23 "task-completion study" is 10 scenarios per channel, authored by the same party as the defence. It demonstrates mechanism, not generalisation.
