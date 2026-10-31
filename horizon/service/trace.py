"""Minimal local tracing (P3-16): JSONL spans with W3C-style ids, redacted attributes, experiment correlation. No network export."""
from __future__ import annotations
import json, os, threading, time
from .redact import redact


class Tracer:
    def __init__(self, path: str | None): self.path, self.l = path, threading.Lock()

    def span(self, name: str, trace_id: str, start: float, end: float, attrs: dict, experiment_id: str | None = None) -> None:
        if not self.path: return
        rec = {"name": name, "trace_id": trace_id, "start": start, "end": end, "experiment_id": experiment_id, "attrs": redact(attrs)}
        with self.l, open(self.path, "a") as f: f.write(json.dumps(rec, sort_keys=True) + "\n")
