"""Signed tool effect contracts, compatibility, approval invalidation, dispatch drift detection, behavioural probes (P19).
Three separate questions: (1) is the contract METADATA authentic (signature), (2) does behaviour CONFORM (probes in an isolated mock), (3) what did the tool ACTUALLY do (audited effects). Each is reported separately; opaque services stay UNVERIFIED."""
from __future__ import annotations
import base64, hashlib, json
from dataclasses import dataclass, field
from horizon import normalize as N

DOMAIN = b"mcphorizon.tool-contract.v1\x00"
COMPAT, INCOMPAT, UNKNOWN = "COMPATIBLE", "INCOMPATIBLE", "UNKNOWN"


def _canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def digest(o): return "sha256:" + hashlib.sha256(_canon(o)).hexdigest()


def contract(tool_id, *, version, impl_id, schema, transport, endpoint, effects, tenant, sbom=None, pinned_deps=None, schema_compatible=False):
    """effects: list of {"effect": "send", "host": "api.example.com"}. impl_id=None means opaque (no code/image attestation)."""
    return {"tool_id": tool_id, "version": version, "impl_id": impl_id, "schema_hash": digest(schema), "transport": transport, "endpoint": N.canonical_url(endpoint), "effects": sorted(({"effect": e["effect"], "host": e["host"]} for e in effects), key=lambda x: (x["effect"], x["host"])),
            "tenant": tenant, "sbom": sbom, "pinned_deps": bool(pinned_deps), "schema_compatible": schema_compatible}


def sign(signer, c: dict) -> dict: return {"contract": c, "kid": signer.kid, "sig": base64.urlsafe_b64encode(signer.sign(DOMAIN + _canon(c))).decode()}


def verify_metadata(env, trust, issuer="release") -> dict:
    try: trust.resolve(env["kid"], issuer).verify(base64.urlsafe_b64decode(env["sig"]), DOMAIN + _canon(env["contract"])); return env["contract"]
    except Exception: raise ValueError("CONTRACT_SIGNATURE_INVALID") from None


def _eff(c): return {(e["effect"], e["host"]) for e in c["effects"]}


def compatibility(old: dict, new: dict) -> dict:
    """COMPATIBLE only when the new version can do nothing the approved one could not. Missing implementation attestation => UNKNOWN, never COMPATIBLE."""
    why = []
    if old["tool_id"] != new["tool_id"]: return {"status": INCOMPAT, "why": ["TOOL_ID"]}
    if _eff(new) - _eff(old): why.append("EFFECT_SCOPE_EXPANDED")
    if new["endpoint"] != old["endpoint"]: why.append("ENDPOINT_CHANGED")
    if new["tenant"] != old["tenant"]: why.append("TENANT_CHANGED")
    if new["transport"] != old["transport"]: why.append("TRANSPORT_CHANGED")
    if new["schema_hash"] != old["schema_hash"] and not new["schema_compatible"]: why.append("SCHEMA_CHANGED_UNDECLARED")
    if why: return {"status": INCOMPAT, "why": why}
    if new["impl_id"] is None: return {"status": UNKNOWN, "why": ["OPAQUE_IMPLEMENTATION"]}
    if not new["sbom"] or not new["pinned_deps"]: return {"status": UNKNOWN, "why": ["NO_SBOM_OR_UNPINNED_DEPS"]}
    return {"status": COMPAT, "why": []}


class Approvals:
    def __init__(self): self.a = {}
    def approve(self, c: dict): self.a[c["tool_id"]] = c
    def usable(self, current: dict) -> dict:
        old = self.a.get(current["tool_id"])
        if old is None: return {"usable": False, "why": ["NOT_APPROVED"]}
        r = compatibility(old, current); return {"usable": r["status"] == COMPAT, "status": r["status"], "why": r["why"]}


def dispatch_check(c: dict, *, resolved_host: str, resolved_ip_ok: bool, tenant: str, redirected_to: str | None, impl_id: str | None) -> list:
    """Run at every dispatch against the PINNED contract: redirect, DNS/service substitution, tenant remap, implementation swap."""
    bad = []
    hosts = {e["host"] for e in c["effects"]}
    if resolved_host not in hosts: bad.append("HOST_NOT_IN_CONTRACT")
    if not resolved_ip_ok: bad.append("DNS_TARGET_CHANGED")
    if tenant != c["tenant"]: bad.append("TENANT_REMAPPED")
    if redirected_to is not None and N.canonical_url(redirected_to).split("/")[2] not in hosts: bad.append("REDIRECT_OUTSIDE_CONTRACT")
    if c["impl_id"] is not None and impl_id != c["impl_id"]: bad.append("IMPLEMENTATION_SWAPPED")
    return bad


class MockNet:
    """Isolated mock: records ACTUAL outgoing effects, never touches a real host (P19-10)."""
    def __init__(self): self.log = []
    def send(self, host, payload): self.log.append(("send", host))
    def read(self, host): self.log.append(("read", host))


def probe(tool_fn, probes: list, declared: dict) -> dict:
    """Run the tool on probe inputs against the mock; compare ACTUAL effects with the declared contract (P19-11)."""
    net = MockNet()
    for p in probes: tool_fn(p, net)
    actual = set(net.log); undeclared = sorted(actual - _eff(declared)); return {"actual": sorted(actual), "undeclared": undeclared, "conforms": not undeclared}


def opaque_status(c: dict) -> str: return "UNVERIFIED" if c["impl_id"] is None else "ATTESTED_IMPL_ONLY"      # never 'safe'
