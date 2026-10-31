# P13 effect-bound authorization: threat-model proof sketch and counterexamples (P13-15)

Status: candidate, written by the implementer, **no independent cryptography/API review (P13-16 open)**. The envelope is a JWS-compact profile (RFC 7515, EdDSA per RFC 8037) with a custom claim set, not an IETF-standard per-call-proof token; P13-01 (survey of the relevant Internet-Drafts) has **not** been done, so interoperability and draft maturity are unassessed.

## Claim (GX1, bounded)
Assume: (a) the signing key is held only by the call authority; (b) gateways hold only public keys and run `Verifier.verify` immediately before executing, computing target and argument digest from the bytes they will execute; (c) the nonce store is the only consumer of nonces and is atomic and durable; (d) the decision service is correct for the policy; (e) no unmediated path to the effect exists.
Then a protected effect executes only if the authority issued a proof for exactly that (principal, tenant, effect, canonical target, argument digest, contract version, audience), under the policy version current at execution time, and that proof has not been used before.
Sketch: forging a proof requires the signing key (EdDSA unforgeability); altering any bound field changes the comparison or the signed bytes; replays are rejected by the atomic `insert` on a unique nonce; stale policy proofs fail the policy-version comparison; wrong-audience proofs fail the audience check.

## Counterexamples and limits (all exercised or documented)
1. **Consumption before effect.** The nonce is consumed before the effect runs; if the effect then fails, the proof is spent and a retry needs a new proof. Safe, not available-optimal.
2. **Proof ≠ safety.** A proof attests that policy allowed the effect given the labels it saw. Mislabelled data, covert channels and paraphrase still defeat the downstream guarantees (see P8/P9).
3. **Authority compromise.** Anyone controlling the authority process or its key mints arbitrary proofs. Key custody outside agent workers is a deployment property, not enforced by this code.
4. **Digest semantics.** The argument digest covers canonical JSON; a gateway that executes something other than the digested value (e.g. re-serialises or follows a redirect) breaks (b). Redirect hops need their own proofs or egress revalidation.
5. **Clock skew.** Skew is bounded (default 5 s) but the verifier trusts its own clock.
6. **Nonce store capacity and cost.** Full store → fail closed. Measured cost is dominated by the durable nonce insert (milliseconds, see `results/v2/p13-overhead/`).
7. **Transport coverage.** Tests use function-level guards shaped like the MCP forward and UTCP send hooks and a per-dispatch Code Mode mediator; they are **not** wired into the production `McpGate`/`UtcpGate`, and no stdio or HTTP transport was tested with proofs on the wire.
8. **Single-process.** Authority, verifier and nonce store ran in one process in tests; multi-gateway nonce sharing is unaddressed.
