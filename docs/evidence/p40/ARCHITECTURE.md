# P40 architecture — shared HorizonPolicy authority (CANDIDATE)

The spec refers to existing "HorizonEvidence" and "HorizonPolicy" components. **No module of either name existed in this repository**; `horizon/hpolicy/authority.py` is created here as the single authority P40–P54 are required to share. It builds on the existing `horizon.authz` Ed25519 `Signer`/`TrustStore`.

* `HorizonPolicy` owns the trust store, the role → evidence-kind table, the policy version and an envelope key. `register_issuer(role, kinds)` returns an `Issuer` (holds a private key) to an evidence **service**.
* Enforcement modules (`Engine`, `Proposals`) receive only a `Verifier` (public keys). `tests.p40.test_obligation.Structure` asserts statically that `horizon/obligation/engine.py` and `infer.py` never import `Signer`/`Issuer` and never call `.issue(`; modules cannot mint approvals.
* Evidence is a strict JWS-like token bound to artifact digest, exact argument digest, object version, policy version, role, issuer and validity window.
* `seal`/`open` give handoff envelopes integrity under the authority's key (not confidentiality).
* Limit: key custody is by object reference inside one process in these tests; separation of duties across hosts is not demonstrated.
