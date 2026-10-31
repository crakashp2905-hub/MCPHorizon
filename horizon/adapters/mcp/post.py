"""Post-tool output handling (P4-17, P4-18): labels, redaction, chunk assembly. Output is DATA, labelled untrusted by default."""
from __future__ import annotations
import hashlib, json
from ...core.labels import C, CONF
from .manifest import INJECT
from ...service.redact import redact

MAX_RESULT = 1 << 20


def _text(result) -> str:
    return "\n".join(c.get("text", "") for c in result.get("content", []) if isinstance(c, dict) and c.get("type") == "text") if isinstance(result, dict) else ""


def label_output(*, tenant: str, event_id: str, tool_default_conf: str, trusted: bool, input_artifacts: dict[str, dict], input_ids: list[str], result) -> tuple[dict, dict]:
    """Return (artifact, safe_result). Confidentiality = max(tool default, inputs); unknown input => SECRET + partial lineage; trust UNTRUSTED unless operator marked the tool trusted."""
    labels, partial = [tool_default_conf], False
    for i in input_ids:
        a = input_artifacts.get(i)
        if a is None: labels.append("SECRET"); partial = True
        else: labels.append(a["confidentiality"]); partial = partial or a["partial_lineage"]
    raw = json.dumps(result, sort_keys=True, default=str)
    if len(raw) > MAX_RESULT: result, partial = {"content": [{"type": "text", "text": "[TRUNCATED: result exceeded size limit]"}], "isError": True}, True
    art_id = "out-" + hashlib.sha256((event_id + raw).encode()).hexdigest()[:40]
    art = {"id": art_id, "producer_event_id": event_id, "parents": sorted(set(input_ids)), "confidentiality": max(labels, key=lambda x: C[x]),
           "trust": "TRUSTED" if trusted else "UNTRUSTED", "tenant_id": tenant, "partial_lineage": partial}
    safe = redact(result)
    flagged = bool(INJECT.search(_text(result)))
    return art, {"result": safe, "instruction_like": flagged, "artifact_id": art_id}


class ChunkAssembler:
    """Streaming results: redaction and labelling run on the ASSEMBLED text so a secret split across chunk boundaries cannot slip through."""
    def __init__(self, max_bytes: int = MAX_RESULT): self.max, self.buf, self.size, self.closed = max_bytes, [], 0, False

    def add(self, chunk: str) -> None:
        if self.closed: raise ValueError("stream already finalized")
        self.size += len(chunk.encode())
        if self.size > self.max: self.closed = True; raise ValueError("streamed result exceeds size limit")
        self.buf.append(chunk)

    def finish(self) -> dict:
        self.closed = True; return {"content": [{"type": "text", "text": "".join(self.buf)}]}
