# Pinned protocol and package versions (P1-01, P1-04, P1-05, P1-06)

Verified 2026-10-31 by installing in an isolated scratch directory with `npm install --ignore-scripts` and a fresh Python venv (nothing executed from the packages). Lockfiles: `third_party_pins/npm/package-lock.json`, `third_party_pins/python-requirements.lock.txt`.

| Item | Pin | Finding |
|---|---|---|
| MCP protocol, primary | `2026-07-28` | official spec |
| MCP protocol, compatibility | `2025-11-25` (sessions); `2025-03-26` assumed if `MCP-Protocol-Version` absent | official spec |
| MCP TypeScript SDK | `@modelcontextprotocol/sdk` **1.32.2** (MIT) | `types.js`: `LATEST_PROTOCOL_VERSION='2025-11-25'`, supported = 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05, 2024-10-07. **It does NOT implement 2026-07-28.** A 2026-07-28 adapter cannot use this SDK's codec |
| MCP Python SDK | `mcp` **2.3.0** (MIT) | `mcp.types.LATEST_PROTOCOL_VERSION == '2026-07-28'`; `PROTOCOL_VERSION_META_KEY == 'io.modelcontextprotocol/protocolVersion'`; has `UnsupportedProtocolVersionErrorData`. Older-version support list not located by grep (open) |
| UTCP (npm) | `@utcp/sdk` 1.2.0, `@utcp/http` 1.1.14, `@utcp/mcp` 1.2.0 (all MPL-2.0) | pinned in lockfile. UTCP spec version string and cli/websocket/grpc plugins not pinned (open) |
| UTCP (PyPI) | `utcp` 1.2.0 (MPL-2.0) | in python lock |
| Code Mode | `@utcp/code-mode` 1.2.13 (MPL-2.0) | sandbox = `isolated-vm` 6.2.0 (V8 isolate); default timeout 30 000 ms, memory 128 MB (`callToolChain(code, timeout, memoryLimit)`) |

## Code Mode interception points (from `dist/index.js` reading, not runtime-tested)
1. `callToolChain` creates an `ivm.Isolate`, a context, and injects `__callToolRef` (an `ivm.Reference`) via `jail.set`.
2. Every generated tool stub in the isolate calls `__callToolRef.applySyncPromise(undefined, [toolName, JSON.stringify(args)])`; the host-side callback runs `this.callTool(toolName, args)`.
3. `setupToolBridges(..., callTool = (n,a)=>this.callTool(n,a))` takes an overridable `callTool` parameter, and `callTool` on `UtcpClient` is the shared funnel → the supported **pre-effect interception point** for MCPHorizon is the host-side `callTool` (subclass/wrap), evaluated **before** delegation.
4. `console.*` output is captured and returned; not a mediation point.
Limits: only calls through bridged tools are mediated here; whether the isolate has any other egress (it has no Node APIs by default under isolated-vm) and whether `isolated-vm` memory/timeout escapes exist were **not** tested. The dependency tree reported npm-audit findings (see below); `isolated-vm` has had sandbox-escape CVEs historically — review before relying on it as a security boundary.

`npm audit` at pin time: 5 high findings, all one root cause — `zod` < 4.6.6 memory exhaustion on oversized constrained collections (GHSA-mrhx-c7xc-m3w5), reached through `@utcp/sdk`; no fix available without a new `@utcp/sdk`. Impact for MCPHorizon: untrusted tool manuals/args validated by zod could cause DoS, so adapters must enforce their own input size limits before UTCP parsing. Raw report: `third_party_pins/npm_audit.json`.

## Licence note for P0-09
UTCP packages are MPL-2.0 (file-level copyleft); MCP SDKs MIT. The repo root licence is proprietary. Counsel review is still required; nothing from these packages is vendored here (only lockfiles).
