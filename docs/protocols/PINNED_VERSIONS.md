# Pinned protocol and package versions (P1-01, P1-04, P1-05 partial, P1-06 partial)

Retrieved 2026-10-31 from the npm/PyPI registries and modelcontextprotocol.io. Re-verify before any release.

| Item | Pin | Source / note |
|---|---|---|
| MCP protocol, primary | `2026-07-28` | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports (official) |
| MCP protocol, compatibility | `2025-11-25` (Streamable HTTP with sessions); `2025-03-26` assumed when `MCP-Protocol-Version` is absent | https://modelcontextprotocol.io/specification/2025-11-25/basic/transports |
| MCP TypeScript SDK | `@modelcontextprotocol/sdk` 1.32.2 (npm `latest`, modified 2026-10-23) | npm registry. **Which protocol revisions this SDK version implements is NOT verified** |
| MCP Python SDK | `mcp` 2.3.0 on PyPI (1.30.0 is the last 1.x) | PyPI index; codec feature support NOT verified (P1-04 open) |
| UTCP | `@utcp/sdk` 1.2.0; `@utcp/http` 1.1.14; `@utcp/mcp` 1.2.0; PyPI `utcp` 1.2.0 | registries. Spec version string and other transport plugins (cli, websocket, grpc) NOT pinned; no `package-lock.json` created (nothing installed) |
| Code Mode | `@utcp/code-mode` 1.2.13 (modified 2026-08-25) | registry only. **Sandbox implementation and real interception points NOT inspected (P1-06 open)** |

P1-01 is **partial**: versions pinned; compatibility behavior documented in the two wire documents.
P1-04, P1-05, P1-06 are **open**: they need package installation in an approved sandbox, lockfiles, and source inspection.
