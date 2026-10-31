# UTCP SDK compatibility (P5-01, P5-23, P5-24)

Status: **CANDIDATE evidence, not conformance.** Inspected by installing `@utcp/sdk@1.2.0` and `@utcp/http@1.1.14` with `--ignore-scripts` and reading the
published `dist/index.d.ts` and `dist/index.js`. The SDK was NOT executed against a real manual or server, and the upstream test suite was NOT run.

## What was inspected
| Item | Evidence |
|---|---|
| `@utcp/sdk` exports | `UtcpClient`, `CommunicationProtocol`, `CallTemplateSerializer`, `UtcpManualSerializer`, `DefaultVariableSubstitutor`, `ensureCorePluginsInitialized`, `setPluginInitializer`, … |
| `@utcp/http` exports | `HttpCommunicationProtocol`, `SseCommunicationProtocol`, `StreamableHttpCommunicationProtocol`, `OpenApiConverter`, `register` |
| Call funnel | `UtcpClient.callTool(toolName, toolArgs)` and `callToolStreaming(...)` (d.ts ~L799/806); protocol plugins implement `callTool(caller, toolName, toolArgs, toolCallTemplate)` (L1016). This is the host-side interception point named in `PINNED_VERSIONS.md`. |
| HTTP dispatch | `@utcp/http` uses axios with its own `safeRequestWithRedirects` (maxHops 5). |
| Built-in SSRF protection | Only **loopback** is checked (manual-declared tool URLs, OAuth token URLs, OpenAPI base URLs, redirect targets). No private-range, link-local or cloud-metadata (169.254.169.254) check was found (grep for `169.254`/private-range helpers: 0 hits). No DNS-resolution check was found. |
| Version string | `UTCP_PACKAGE_VERSION` is declared as `"1.0.0"` while the package is 1.2.0: do not use that constant as the version pin. |

## What this repo implements (Python, `horizon/adapters/utcp/`)
This adapter is a **policy layer that does not import or wrap the SDK**. It re-implements the checks the SDK lacks and expects a host to route
UTCP calls through `UtcpGate.call(...)` instead of calling `UtcpClient.callTool` directly. Nothing here intercepts an unmodified SDK client: wiring
`UtcpClient.callTool` to this gate (e.g. by subclassing and delegating over the P3 SDK) is **not built or tested**.

## Transports
| Transport | Status |
|---|---|
| `http` call template | Supported by the gate (GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE) over an injected `send`; **no real network client is shipped**, so DNS pinning/TLS verification is the host's `send` responsibility and is only specified, not tested against a real TLS stack. |
| `cli` call template | Supported via argv-array facade with executable allowlist, scrubbed env, rlimits, output bounds. **Not a sandbox** (no filesystem or network confinement). |
| WebSocket (P5-16) | **Unsupported.** Manuals declaring it are rejected at ingest. No frame-level authorization interface exists yet. |
| gRPC (P5-17) | **Blocked/unsupported.** No verified plugin was inspected; rejected at ingest. |
| SSE, streamable HTTP, `mcp`, `text`, OpenAPI conversion | **Unsupported**; rejected at ingest. |

## Open items
- P5-01: versions are pinned (see `PINNED_VERSIONS.md`) but the cli/websocket/grpc plugin packages were not inspected.
- P5-23: no SDK/plugin conformance run; export signatures above are read from type declarations only.
- Upstream advisory noted in `PINNED_VERSIONS.md` (zod memory exhaustion via `@utcp/sdk`): `parse_manual` enforces size/depth limits before any SDK parsing, which mitigates but does not remove the issue for a host that also feeds the SDK.
