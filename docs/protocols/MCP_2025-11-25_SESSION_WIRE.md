# MCP 2025-11-25 session / Streamable HTTP behavior (P1-03)

Source: official `/specification/2025-11-25/basic/transports` (fetched 2026-10-31).

- Single endpoint supporting **POST and GET**. Body of a POST is a single request, notification **or response**. Notification/response accepted → `202`.
- Lifecycle starts with an `initialize` request / `initialized` notification. Server MAY assign a session id in the `MCP-Session-Id` response header (visible ASCII 0x21–0x7E, globally unique, cryptographically secure); if assigned, client MUST send it on all subsequent requests. Missing id on a session-requiring server → `400`; terminated session → `404` (client must re-initialize); client SHOULD `DELETE` with the header to end it (server MAY answer `405`).
- `MCP-Protocol-Version` MUST be sent on subsequent requests (value negotiated at initialize); absent and undeterminable → server SHOULD assume `2025-03-26`; invalid/unsupported → `400`.
- SSE: server MAY send requests/notifications before the response, may prime with an event id, resumable via `GET` + `Last-Event-ID` (per-stream cursors; MUST NOT replay another stream's messages). Disconnect is NOT cancellation; client SHOULD send `notifications/cancelled`.
- Optional standalone `GET` SSE stream for server-initiated messages; each server message goes on exactly one stream.
- `Origin` MUST be validated (`403` if invalid); bind localhost when local.
- Note the official page spells the header `MCP-Session-Id`; header names are case-insensitive, so adapters must compare case-insensitively.

Differences from 2026-07-28: sessions, `initialize`, GET stream, resumption and server-initiated requests exist here and are removed there; mirrored `Mcp-Method`/`Mcp-Name` headers do **not** exist here, so header-based gateways cannot see the operation for 2025 traffic.
