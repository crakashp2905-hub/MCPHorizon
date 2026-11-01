"""Typed operation summaries (P39-02) and the versioned abstraction (P39-03). Taint lattice: PUB < ENC < SEC (ENC = a reversible transform of a secret; still a leak)."""
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass, field, asdict

ABSTRACTION_VERSION = "emergence-abs/1.0.0"
PUB, ENC, SEC = "PUB", "ENC", "SEC"
RANK = {PUB: 0, ENC: 1, SEC: 2}


def join(*ts):
    return max(ts, key=lambda t: RANK[t]) if ts else PUB


@dataclass(frozen=True)
class OpSummary:
    """name: tool; kind: source|transform|sink; out_taint: taint of the produced value for source ops; transform: 'identity'|'encode'|'sanitize'|'unknown';
    delegates: for sinks, (path-prefix -> name of the query parameter that the remote forwards to) – a delegated REMOTE effect; confidence/provenance record how the summary was obtained."""
    name: str
    kind: str
    out_taint: str = PUB
    transform: str = "identity"
    principal: str = "agent"
    confidence: float = 1.0
    provenance: str = "declared"
    modeled: bool = True


@dataclass(frozen=True)
class EndpointSummary:
    """Delegated REMOTE effects (P39-02): what a remote endpoint does with a request beyond receiving it. delegates = ((path_prefix, query_param), ...): the endpoint forwards/redirects the caller to the URL in that parameter.
    modeled=False means the analyst has no knowledge of the endpoint, so its effects are UNKNOWN, never silently safe."""
    name: str
    port: int
    modeled: bool = True
    delegates: tuple = ()
    secure_sink: bool = False      # policy: protected data may legitimately terminate here


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def digest(obj) -> str:
    return hashlib.sha256(canon(obj).encode()).hexdigest()


def library_summaries(*, unmodeled=()):
    """The tool library the experiments use. `unmodeled` names ops/endpoints whose summary the analyst does NOT have (P39-15)."""
    s = {
        "read_secret": OpSummary("read_secret", "source", SEC, provenance="declared"),
        "read_note": OpSummary("read_note", "source", PUB),
        "b64": OpSummary("b64", "transform", transform="encode"),
        "hash": OpSummary("hash", "transform", transform="sanitize", provenance="declared:one-way"),
        "redact": OpSummary("redact", "transform", transform="sanitize", provenance="declared:replaces-content"),
        "weak_sanitize": OpSummary("weak_sanitize", "transform", transform="unknown", confidence=0.4, provenance="inferred:name-only"),
        "get": OpSummary("get", "sink", provenance="http-semantics"),
        "post": OpSummary("post", "sink", provenance="http-semantics"),
    }
    for n in unmodeled:
        if n in s: s[n] = OpSummary(n, s[n].kind, modeled=False, provenance="unmodeled")
    return s


def serialize_summaries(sm: dict) -> str:
    return canon({"abstraction": ABSTRACTION_VERSION, "ops": {k: asdict(v) for k, v in sorted(sm.items())}})
