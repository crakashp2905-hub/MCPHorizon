# MCPHorizon threat model and deployment assumptions (P10-01)

Scope: the supported deployment is a **single-host, operator-run** policy service with in-process adapters (MCP, UTCP, Code Mode). Anything outside it (multi-region, hosted multi-tenant SaaS, Windows/macOS isolation) is unsupported until reviewed.

## Assets
Operator policy bundles and approvals; tenant secrets in the credential broker; labelled artifacts and lineage; audit log and its stamps; signing/declassifier keys.

## Trust boundaries
1. **Agent / model output** — untrusted. Never decides labels, roles, tenants, policy or approvals.
2. **Tool servers, manuals, tool descriptions, tool outputs** — untrusted content; outputs enter as UNTRUSTED artifacts.
3. **Adapters (gates)** — trusted code holding the `adapter` role; they assert effects and targets from their own registry, not from agent text.
4. **Policy service** — trusted; authenticated bearer tokens map to (tenant, principal, role); local Unix socket 0600 with SO_PEERCRED allowlist (`horizon/ops/peer.py`) or loopback TCP only.
5. **Operator / reviewer humans** — trusted, separated by role (`horizon/ops/approvals.py`).
6. **Code Mode isolate** — semi-trusted execution of untrusted code; NOT a hardened sandbox (`CODE_MODE_SECURITY_LIMITS.md`).

## Attacker capabilities considered
Prompt injection into tool outputs; malicious or compromised tool servers (rug pull, lookalike names, endpoint swap); agent-supplied arguments trying to override policy fields; SSRF/redirect/DNS rebinding; confused-deputy token passthrough; cross-tenant access; log/telemetry leakage; resource exhaustion; replay.

## Controls and where they live
| Threat | Control | Evidence |
|---|---|---|
| Token passthrough / confused deputy | issuer+audience-bound credentials, no alg negotiation | `ops/audience.py`, `tests/p10/test_ops.py` |
| Secret exposure | `Secret` wrapper, allowlisted env, private-file provider, tenant-scoped broker, honeytoken absence checks | `ops/secrets.py`, `adapters/utcp/creds.py`, `tests/p10/test_negative.py::LogSecrecy` |
| Unreviewed policy/manual change | role separation, digest-bound approvals, two-person rule, version-monotonic policies, manifest digest pinning | `ops/approvals.py`, `service/core.py`, `adapters/*/manifest|manual` |
| Cross-tenant access | per-tenant policy/artifact stores, tenant-checked artifact writes, tenant-scoped audit | `tests/p10/test_negative.py::TenantIsolation` |
| SSRF / rebinding | canonical target, forbidden ranges, any-bad-answer rejects, address pinning, per-hop revalidation | `adapters/utcp/egress.py`, `tests/p5`, `tests/p10` |
| DoS | size/rate/in-flight/tenant bounds, rlimits for workers | `ops/guard.py` |
| Policy outage | fail-closed wrapper with emergency mode | `ops/guard.py::FailClosed` |
| Audit tampering | hash chain + signed stamps with key lifecycle | `service/audit.py`, `ops/keys.py` |
| Telemetry leakage | allowlisted attributes, salted-hash identifiers | `ops/otel.py` |

## Explicit non-goals and residual risks
- Lineage is bounded: paraphrase with lost lineage is undetected (`LINEAGE_COVERAGE_LIMITS.md`); SecBench shows chunked and reversed exfiltration leaking in some cases.
- A compromised service host, kernel, or operator account defeats all controls.
- Symmetric (HS256) credentials mean any holder of a validator key can mint tokens; use per-resource keys and short TTLs. Asymmetric issuers are future work.
- State in `ResourceGuard`, replay guards and key rings is in-memory; a restart forgets it.
- No independent security review has been done (P10-23/24 open). Do not describe this as audited.
