# P44 HorizonReach — effect model, trust limits, safe business use (CANDIDATE)

## Effect model (P44-01)
`EffectiveEffect(principal, intermediary, destination, effect, label, trust)`. A call to an intermediary is expanded into the effects it may induce: the service itself receives the payload (`call`), a `fetch` argument sends only a URL, a `relay` argument forwards the payload. Each effect is checked against the **resolved address** (policy clearances are resolved at load time), not the string. Verdicts: ALLOW, DENY, UNKNOWN. UNKNOWN never executes sensitive data. Trust of a remote effect description: `direct` (no intermediary), `unverified-declaration` (operator-signed only), `attested` (an evidence service bound the exact manifest digest and receipt key), and, after the call, receipt-evidenced.

## Mechanisms and what each defends
* Canonicalization (`urlnorm.py`): userinfo, decimal/hex/octal/short IPv4, IPv4-mapped IPv6, trailing dot, percent-encoded host, IDNA, backslash/control characters, default ports, dot segments. Ambiguous input fails closed (UNKNOWN).
* Pinned resolution: the address validated at decision time is the address connected to; a different DNS answer at connect time is never used.
* Redirect revalidation: no automatic redirect following; every hop is re-canonicalized and re-checked against the payload label.
* Label binding: payload bytes and labels come from the trusted artifact store; an agent-supplied label is ignored.
* Attestation: the registry holds only a public-key verifier. A manifest is ATTESTED only if an evidence-service token binds its exact digest and receipt key; the module never signs one (a static test checks this).
* Fabric: outbound requests of controlled services go through a fabric that applies the call's label and the service's attested egress list; unknown or borrowed call contexts are treated as SECRET; only the exact URLs the caller authorized for fetching are exempt.
* Receipts: for external attested services a signed receipt is required; missing or invalid receipts downgrade the result to UNKNOWN after the call; a receipt that reveals an unauthorized effect revokes the manifest.

## Trust limits (read before any business use)
1. An external service's behaviour is not observable by this module. Attestation and receipts are claims by the service or its attestor. A service that attests honestly and then lies (A03) causes its first forbidden effect; only an independent observer detects it, after the fact, by time window and content.
2. Controlled-service confinement relies on the service using the fabric. A service that opens its own sockets must be confined by the sandbox (P42); the calibration in RESULTS shows the sandbox blocks the same effect that an open policy allows.
3. Marker detection in the oracle is limited to known derived forms; the sink oracle records HTTP requests only.
4. Open-ended external graphs: claims are restricted to modeled intermediaries and brokered endpoints.
5. Nothing here is a third-party measurement; all services are local fixtures written by the same author.

## Safe business use policy examples
`spec/reach_policy_examples.json` holds three examples (internal documents to partner converters; public research fetch only; no external relays). Each is validated by a test: every destination has a clearance, every service is either attested or limited to PUBLIC data, and external services require receipts. Example intent: *"Send CONFIDENTIAL files only to attested converters whose manifests list the fetch hosts; treat unattested converters as PUBLIC-only; block, never allow, when a destination cannot be resolved."*
