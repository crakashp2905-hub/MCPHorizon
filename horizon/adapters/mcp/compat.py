"""Supported-method tables and the generated compatibility report (P4-11, P4-22). The report is generated from these tables; a test fails on drift."""
from .gate import SUPPORTED, READ_METHODS
from .wire import MODERN, LEGACY

UNSUPPORTED = {
    "sampling/createMessage": "server-initiated model call; not forwarded. Safe fallback: JSON-RPC -32601; no sampling capability is advertised.",
    "elicitation/create": "server-initiated user input; not forwarded. Safe fallback: -32601. Elicited text is never an approval.",
    "roots/list": "server-initiated; not forwarded. Safe fallback: -32601.",
    "logging/setLevel": "not forwarded. Safe fallback: -32601.",
    "completion/complete": "not forwarded (no policy mapping). Safe fallback: -32601.",
    "resources/subscribe": "stateful push; not forwarded. Safe fallback: -32601.",
    "resources/unsubscribe": "not forwarded. Safe fallback: -32601.",
    "subscriptions/listen": "2026 long-lived stream; not forwarded. Safe fallback: -32601.",
    "tasks/*": "Tasks extension: no verified method list; denied until an explicit allowlist entry and policy mapping exist.",
    "any extension method": "denied by default (unknown methods are UNMAPPED => denied for protected effects, never forwarded).",
}
NOTES = [
    "`input_required` (MRTR) results are returned marked `input_required_is_not_approval`; the field names follow secondary sources and are UNVERIFIED against the official schema.",
    "Official MCP conformance suites were NOT run (P4-21 not done); only project fixtures were.",
    "`server/discover` is mapped as a read; its cache-metadata fields are not interpreted (P4-09 partial).",
    "Arguments using JSON-Schema keywords outside the bounded validator are UNVALIDATED; protected effects with unvalidated arguments are denied.",
]


def render_report() -> str:
    L = ["# MCP adapter compatibility report (generated; do not edit)\n", f"Modern: `{MODERN}` (stateless). Legacy: `{LEGACY}` (sessions). Codecs are separate and never merged.\n", "## Supported methods\n", "| Method | Modern | Legacy |", "|---|---|---|"]
    for m in sorted(SUPPORTED[MODERN] | SUPPORTED[LEGACY]): L.append(f"| `{m}` | {'yes' if m in SUPPORTED[MODERN] else 'no'} | {'yes' if m in SUPPORTED[LEGACY] else 'no'} |")
    L += ["", "Every supported method except `initialize` and `ping` is subject to a pre-call policy decision; denial or any error means it is not forwarded.\n", "## Unsupported (safe fallback)\n", "| Method | Behaviour |", "|---|---|"]
    L += [f"| `{k}` | {v} |" for k, v in sorted(UNSUPPORTED.items())]
    L += ["", "## Known gaps\n"] + [f"- {n}" for n in NOTES]
    return "\n".join(L) + "\n"
