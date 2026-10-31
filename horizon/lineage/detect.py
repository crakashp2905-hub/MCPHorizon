"""Outgoing-boundary classification (P7-03, P7-04, P7-08, P7-14). Works on the bytes that are actually about to leave, using
(a) lineage labels of the declared inputs (POSSIBLE flow) and (b) the sidecar's registry of sensitive values (VERIFIED leak).
Never uses tool names, fixture truth annotations, or free-text claims."""
from __future__ import annotations
import base64, binascii, hashlib, json, re
from urllib.parse import unquote
from ..core.labels import C

POSSIBLE_FLOW, VERIFIED_LEAK, PARTIAL_LINEAGE, UNKNOWN_INPUT, PURPOSE_VIOLATION, CREDENTIAL_IN_PAYLOAD = "POSSIBLE_FLOW", "VERIFIED_OUTBOUND_LEAK", "PARTIAL_LINEAGE", "UNKNOWN_INPUT", "PURPOSE_VIOLATION", "CREDENTIAL_IN_PAYLOAD"
_B64 = re.compile(rb"[A-Za-z0-9+/_\-]{16,}={0,2}"); _HEX = re.compile(rb"(?:[0-9a-fA-F]{2}){8,}")


def variants(b: bytes, depth: int = 0) -> list[bytes]:
    """The payload as it may be re-encoded to dodge a substring check: raw, percent-decoded, JSON-unescaped, base64/base64url and hex runs decoded (bounded, one level of recursion)."""
    out = [b]
    try: u = unquote(b.decode("utf-8", "ignore")).encode()
    except Exception: u = b
    if u != b: out.append(u)
    try:
        j = json.loads(b); strs = []
        def walk(o, d=0):
            if d > 8: return
            if isinstance(o, str): strs.append(o.encode())
            elif isinstance(o, dict): [walk(v, d + 1) for v in o.values()]
            elif isinstance(o, list): [walk(v, d + 1) for v in o]
        walk(j); out.extend(strs)
    except Exception: pass
    for base in list(out):
        for m in _B64.findall(base)[:50]:
            for dec in (base64.b64decode, base64.urlsafe_b64decode):
                try: out.append(dec(m + b"=" * (-len(m) % 4)))
                except Exception: pass
        for m in _HEX.findall(base)[:50]:
            try: out.append(binascii.unhexlify(m))
            except Exception: pass
    if depth == 0:
        for v in list(out[1:]):
            if len(out) < 200: out.extend(variants(v, 1)[1:])
    return out[:300]


class Boundary:
    """Callable installed as the gates' `boundary` hook. Returns {"allow": bool, "reason_codes": [...], "possible": [...], "verified": [...]}."""
    def __init__(self, sidecar, credential_secrets=lambda: ()): self.sc, self.cred = sidecar, credential_secrets

    def __call__(self, ev: dict) -> dict:
        body = ev.get("body", b"") + b"\n" + str(ev.get("url", "")).encode()
        reasons, verified, possible = [], [], []
        ids = ev.get("input_artifacts", [])
        for i in ids:
            if i not in self.sc.art: reasons.append(UNKNOWN_INPUT); possible.append(i); continue
            a = self.sc.art[i]
            if a["partial_lineage"]: reasons.append(PARTIAL_LINEAGE)
            if C[self.sc.art[i]["confidentiality"]] >= C["CONFIDENTIAL"] or C[_eff(self.sc, i)] >= C["CONFIDENTIAL"]: reasons.append(POSSIBLE_FLOW); possible.append(i)
            if not self.sc.use_allowed(i, ev.get("purpose"), ev.get("sink_zone")) and self.sc.meta[i]["kind"] == "declassified": reasons.append(PURPOSE_VIOLATION)
        vs = variants(body)
        exempt = {m["digest"] for i in ids if i in self.sc.meta and (m := self.sc.meta[i])["kind"] == "declassified" and self.sc.use_allowed(i, ev.get("purpose"), ev.get("sink_zone"))}
        for fp, v in self.sc.sensitive.items():
            n = v["s"].encode()
            if any(n in x for x in vs):
                if self.sc.meta[v["handle"]].get("digest") in exempt: continue         # same bytes, but a valid purpose-bound declassification is among the inputs
                verified.append(v["handle"]); reasons.append(VERIFIED_LEAK)
        for s in self.cred():                                                  # token-as-payload (P7-04): a broker secret in the body/URL is never legitimate
            if s and s.encode() in body: reasons.append(CREDENTIAL_IN_PAYLOAD)
        deny = any(r in (VERIFIED_LEAK, PURPOSE_VIOLATION, CREDENTIAL_IN_PAYLOAD) for r in reasons)
        return {"allow": not deny, "reason_codes": sorted(set(reasons)), "possible": sorted(set(possible)), "verified": sorted(set(verified))}


def _eff(sc, h):
    from .. import schemas
    return schemas.effective_confidentiality(h, sc.art)
