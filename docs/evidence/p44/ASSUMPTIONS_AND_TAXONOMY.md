# P44 HorizonReach — assumptions and attack taxonomy (CANDIDATE)

## What was built
A local intermediary network (loopback aliases 127.0.1.x, one shared port, mock DNS with rebinding), an independent sink process that journals every request it receives, an egress broker (canonicalize → resolve once → pin → label-bind → attestation → fabric → receipts), three baselines (strict allowlist, URL-pattern, trust-in-declaration), a budgeted reachability search with a HorizonEmergence adapter, and a 30-scenario experiment (15 attack types, 12 benign pairs, 3 observability cases) × 12 systems × 3 repetitions.

## Taxonomy of attacks tested
| id | mechanism | defended by |
|---|---|---|
| A01 | attested *controlled* service forwards the document to an unauthorized host | fabric (per-call label + attested egress list) |
| A02 | unattested external service forwards (declared otherwise) | UNKNOWN for sensitive data without attestation |
| A03 | **attested external service that lies**, receipts omit the hidden request | NOT prevented on the first call; independent audit detects, manifest revoked, 2nd call blocked |
| A04 | allowed partner is an open redirector to an unauthorized host | per-hop revalidation |
| A05 | DNS rebinding between check and connect | pinned resolved address |
| A06a-f | decimal / hex / octal IPv4, IPv4-mapped IPv6, userinfo, trailing dot | canonicalization (fail closed) |
| A07/A07b | relay forwards payload to an unauthorized destination, double hop | relay effect checked with the payload label |
| A08/A09 | label laundering: agent-claimed label, reversible re-encoding | broker takes labels from the trusted artifact store; reversible transforms keep the label |

Benign pairs (B01–B09 incl. numeric forms of an *approved* host, approved redirects, public fetches, hashed/redacted payloads) check that blocking is not bought with availability.

## Assumptions (explicit)
1. **Same-author world.** Services, policy, scenarios and the oracle's clearance table are written by one author on one machine. Results show the mechanisms work against these attacks, not that they hold against unseen ones.
2. **Oracle independence.** Security outcome = the sink process's own journal plus an independent literal clearance table (`ORACLE_SECRET_OK`); the broker never writes either. Marker detection covers the canary and single-step known encodings only.
3. **Declared authority.** The grants and per-destination clearances are declared inputs, not learned.
4. **Attestation** is issued by a separate evidence service via the shared HorizonPolicy authority; this module only verifies. A token is bound to service name, manifest digest and receipt key.
5. **Fabric** confinement of controlled services holds only because those services route through it; real confinement of arbitrary code is the sandbox's job (P42). A calibration shows the Landlock sandbox stops the same effect that the open configuration lets through.
6. **Remote observation.** For external attested services, only receipts and an after-the-fact independent observer exist. Missing/invalid receipts → UNKNOWN after the call, never a success claim (spec P44-12).
7. **Reachability** is a capability analysis; it may be more conservative than a concrete request chain. Agreement with Emergence: 10/12 exact, 12/12 sound (never ALLOW where Emergence denies).

## Not claimed
No prevention of the first effect of a lying attested external service; no claim about real third-party services; no live-model agent; no claim of VERIFIED status for any gate.
