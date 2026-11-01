# Integrate-versus-build boundary (P36-01)

| Capability | Decision | Why |
|---|---|---|
| Broad IaC / cloud posture scanning (hundreds of providers and rules) | **Integrate** (checkov, trivy, kube-bench, cloud-native CSPM) | mature, maintained rule sets; rebuilding them would be worse and unreviewed |
| AI-service-specific exposure rules (public DB bind, anonymous model-service admin/metrics, log-UI tenant isolation, telemetry retention, baked secrets, over-privileged service account) | **Build narrowly** (`horizon/infraguard/guard.py`, rules IG001-IG009) | needs to read this project's own `x-*` annotations (auth mode, tenant isolation) which generic scanners do not know |
| Authenticated vs anonymous behaviour of a *running* service | **Build, local synthetic services only** | generic IaC scanners cannot observe behaviour; probes are loopback-only and refuse other targets |
| Posture evidence into runtime risk | **Build** (signed evidence, read-only `RiskView`) | the agent must not gain admin authority over infrastructure |
| Scanning third-party or production infrastructure | **Forbidden by default** | `scan_allowed()` admits only loopback / reserved names; no DNS lookups |

Non-goals: network discovery, vulnerability scanning of real services, cloud API calls, compliance mapping.
