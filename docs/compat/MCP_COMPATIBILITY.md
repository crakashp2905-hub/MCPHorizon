# MCP adapter compatibility report (generated; do not edit)

Modern: `2026-07-28` (stateless). Legacy: `2025-11-25` (sessions). Codecs are separate and never merged.

## Supported methods

| Method | Modern | Legacy |
|---|---|---|
| `initialize` | no | yes |
| `ping` | no | yes |
| `prompts/get` | yes | yes |
| `prompts/list` | yes | yes |
| `resources/list` | yes | yes |
| `resources/read` | yes | yes |
| `server/discover` | yes | yes |
| `tools/call` | yes | yes |
| `tools/list` | yes | yes |

Every supported method except `initialize` and `ping` is subject to a pre-call policy decision; denial or any error means it is not forwarded.

## Unsupported (safe fallback)

| Method | Behaviour |
|---|---|
| `any extension method` | denied by default (unknown methods are UNMAPPED => denied for protected effects, never forwarded). |
| `completion/complete` | not forwarded (no policy mapping). Safe fallback: -32601. |
| `elicitation/create` | server-initiated user input; not forwarded. Safe fallback: -32601. Elicited text is never an approval. |
| `logging/setLevel` | not forwarded. Safe fallback: -32601. |
| `resources/subscribe` | stateful push; not forwarded. Safe fallback: -32601. |
| `resources/unsubscribe` | not forwarded. Safe fallback: -32601. |
| `roots/list` | server-initiated; not forwarded. Safe fallback: -32601. |
| `sampling/createMessage` | server-initiated model call; not forwarded. Safe fallback: JSON-RPC -32601; no sampling capability is advertised. |
| `subscriptions/listen` | 2026 long-lived stream; not forwarded. Safe fallback: -32601. |
| `tasks/*` | Tasks extension: no verified method list; denied until an explicit allowlist entry and policy mapping exist. |

## Known gaps

- `input_required` (MRTR) results are returned marked `input_required_is_not_approval`; the field names follow secondary sources and are UNVERIFIED against the official schema.
- Official MCP conformance suites were NOT run (P4-21 not done); only project fixtures were.
- `server/discover` is mapped as a read; its cache-metadata fields are not interpreted (P4-09 partial).
- Arguments using JSON-Schema keywords outside the bounded validator are UNVALIDATED; protected effects with unvalidated arguments are denied.
