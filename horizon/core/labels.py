"""Confidentiality/trust lattices, join, and trusted declassification (P2-16, P2-17)."""
from __future__ import annotations
import hashlib, hmac, json

CONF = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"]
TRUST = ["UNTRUSTED", "UNVERIFIED", "TRUSTED"]          # ascending trust; join of inputs = MIN trust
C = {n: i for i, n in enumerate(CONF)}; T = {n: i for i, n in enumerate(TRUST)}


def join_conf(labels: list[str]) -> str:
    return CONF[max((C[x] for x in labels), default=0)] if labels else "PUBLIC"


def meet_trust(labels: list[str]) -> str:
    return TRUST[min((T[x] for x in labels), default=2)] if labels else "TRUSTED"


def output_label(input_conf: list[str], input_trust: list[str]) -> dict:
    """Opaque transformation: output is at least as confidential as every input and no more trusted than any input."""
    return {"confidentiality": join_conf(input_conf), "trust": meet_trust(input_trust)}


def sign_declassification(key: bytes, req: dict) -> str:
    return hmac.new(key, json.dumps(req, sort_keys=True).encode(), hashlib.sha256).hexdigest()


def declassify(artifact: dict, to_conf: str, req: dict, sig: str, keys: dict[str, bytes], used: set[str]) -> dict:
    """Lower confidentiality ONLY via a signed request from a registered declassifier bound to this artifact, level change,
    and a one-time nonce. Anything else raises. Returns a NEW artifact dict; the original is untouched."""
    need = {"artifact_id": artifact["id"], "from": artifact["confidentiality"], "to": to_conf, "nonce": req.get("nonce"),
            "declassifier": req.get("declassifier"), "reason": req.get("reason")}
    if req != need or not req.get("reason") or not req.get("nonce"): raise PermissionError("declassification request malformed or not bound to artifact")
    if C[to_conf] >= C[artifact["confidentiality"]]: raise PermissionError("not a lowering")
    k = keys.get(req["declassifier"])
    if k is None or not hmac.compare_digest(sig, sign_declassification(k, req)): raise PermissionError("invalid declassifier signature")
    if req["nonce"] in used: raise PermissionError("declassification nonce replayed")
    used.add(req["nonce"])
    return {**artifact, "confidentiality": to_conf, "declassified_by": req["declassifier"]}
