"""Heuristic scanner for MCP tool descriptions that try to instruct the MODEL (tool poisoning). CANDIDATE, research prototype.
It scores structural signals; it is NOT a proof of safety and a low score is NOT a clean bill: an attacker who knows the rules can phrase around them (adaptive attacks are untested), and the benign set it was tuned/evaluated on is author-written.
Signals: cross-tool invocation ('before X, call tool_y'), coercion ('MUST', 'failure to ... will cause'), sensitive targets, concealment, override, literal argument payloads.
Pure stdlib, no network. Weights/threshold live in WEIGHTS/THRESHOLD and were fitted on the DEV data only (see research/guard/evaluate.py)."""
from __future__ import annotations
import json, re

IDENT = r"(?:[`'\"][A-Za-z][\w\-\.]{2,}[`'\"]|(?-i:\b[a-z]+_[a-z0-9_]+\b|\b[a-z]+[A-Z][A-Za-z0-9]+\b))"   # case-sensitive inside: snake_case or camelCase only (a case-insensitive version matched every word)
SIGNALS = {
    "cross_tool_call": re.compile(r"\b(?:use|using|call|calling|run|running|invoke|invoking|execute|executing|request|requesting|trigger|triggering)\b[^.\n]{0,40}?" + IDENT, re.I),
    "sequencing": re.compile(r"\b(?:before|after|prior to|first|instead of|in order to|to do this|to complete this)\b", re.I),
    "coercion": re.compile(r"\b(?:must|mandatory|required to|you have to|failure to|failing to|skipping|will cause|will result|otherwise|do not skip|should (?:first|always)|make sure|(?:this )?step is (?:critical|essential|required|necessary|mandatory)|(?:critical|essential) for|never)\b", re.I),
    "sensitive_target": re.compile(r"(?:\.ssh|id_rsa|\.env\b|/etc/passwd|credential|api[_ ]?key|secret|password|passwd|private key|\btoken\b|~/|\bcookie)", re.I),
    "concealment": re.compile(r"(?:do not (?:tell|mention|inform|reveal|show)|don't (?:tell|mention|inform)|without (?:telling|informing|notifying)|silently|hide (?:this|it)|not (?:be )?visible to the user|keep (?:this|it) secret)", re.I),
    "override": re.compile(r"(?:ignore (?:all |any |the )?(?:previous|prior|above)|disregard|override|supersede|new instructions?|system prompt|you are now)", re.I),
    "literal_payload": re.compile(r"(?:\b(?:uid|id|user[_ ]?id|customer)\b[^.\n]{0,12}\b\d{3,}\b|'[A-Z0-9_\-]{4,}'|\bwith the (?:string|value|query)\b)", re.I),
    "exfil": re.compile(r"\b(?:send|forward|post|upload|email|transmit|exfiltrate|copy)\b[^.\n]{0,60}\b(?:to|into)\b[^.\n]{0,40}(?:@|https?://|\bremote\b|\bexternal\b)", re.I),
}
WEIGHTS = {"cross_tool_call": 2.0, "sequencing": 0.5, "coercion": 1.5, "sensitive_target": 1.0, "concealment": 3.0, "override": 3.0, "literal_payload": 1.5, "exfil": 2.5}
THRESHOLD = 2.5


def features(text: str) -> dict: return {k: bool(r.search(text or "")) for k, r in SIGNALS.items()}


def score(text: str, weights=None) -> float:
    w = weights or WEIGHTS; f = features(text); return sum(w[k] for k, v in f.items() if v)


def scan_tool(tool: dict, threshold=None, weights=None) -> dict:
    """tool: {name, description, inputSchema?}. Descriptions of parameters are scanned too (they reach the model the same way)."""
    texts = [("description", tool.get("description") or "")]
    props = ((tool.get("inputSchema") or {}).get("properties") or {})
    for pn, ps in props.items():
        if isinstance(ps, dict) and isinstance(ps.get("description"), str): texts.append((f"param:{pn}", ps["description"]))
    best = max(((score(t, weights), where, t) for where, t in texts), key=lambda x: x[0])
    s, where, t = best; th = THRESHOLD if threshold is None else threshold
    return {"tool": tool.get("name"), "score": round(s, 2), "flagged": s >= th, "where": where, "signals": sorted(k for k, v in features(t).items() if v)}


def scan_manifest(tools: list, threshold=None) -> dict:
    rows = [scan_tool(t, threshold) for t in tools]
    return {"tools": len(rows), "flagged": sum(r["flagged"] for r in rows), "findings": [r for r in rows if r["flagged"]], "all": rows,
            "note": "heuristic; absence of a flag is not evidence of safety"}
