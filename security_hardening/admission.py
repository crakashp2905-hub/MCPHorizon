"""Gate G5 mechanism (CANDIDATE): versioned module manifest + DEFAULT-DENY admission.

Nothing here certifies a module.  It only refuses to install a module unless an operator-owned
TrustStore verifies a signature by someone OTHER than the module author, the manifest is complete
and unambiguous, its threat model / evidence digests match the bytes on disk, its dependencies are
already admitted at the exact pinned version, the running platform is supported, and any elevated
capability was explicitly allowed by the operator.  Any error, unknown field or unsupported
contract version is a DENY.  There is deliberately NO aggregate 'safe score' (see coverage_map).
"""
from __future__ import annotations
import hashlib, json, os, platform, re
from horizon.authz.keys import TrustStore, TrustError, Signer

CONTRACT_VERSION = "1"
REVIEW_ISSUER = "module-reviewer"
COVERAGE = ("protected", "blocked", "observed_only", "unknown", "unsupported")
ELEVATED = ("mandatory_enforcement", "kernel_patch", "trust_root_change", "approval_issuance", "ambient_network", "ambient_filesystem")
REQUIRED = ("name", "version", "contract_version", "authored_by", "effects", "dependencies", "supported_platforms", "signer", "threat_model", "evidence_digest", "feature_flags", "track")
OPTIONAL = ("signature",)
TRACKS = ("kernel", "adapter", "research")
SHA = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[a-z][a-z0-9_.-]{0,63}")


def canon(m: dict) -> bytes:
    return json.dumps({k: v for k, v in m.items() if k != "signature"}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sign(m: dict, signer: Signer) -> dict:
    m = {k: v for k, v in m.items() if k not in ("signature",)}; m["signer"] = {"kid": signer.kid, "issuer": signer.iss}
    m["signature"] = signer.sign(canon(m)).hex(); return m


def file_sha(path: str) -> str:
    with open(path, "rb") as f: return hashlib.sha256(f.read()).hexdigest()


def shape_problems(m) -> list:
    if not isinstance(m, dict): return ["NOT_AN_OBJECT"]
    p = [f"UNKNOWN_FIELD:{k}" for k in m if k not in REQUIRED and k not in OPTIONAL]
    p += [f"MISSING_FIELD:{k}" for k in REQUIRED if k not in m]
    if p: return p
    if not (isinstance(m["name"], str) and NAME.fullmatch(m["name"])): p.append("BAD_NAME")
    if not (isinstance(m["version"], str) and re.fullmatch(r"\d+\.\d+\.\d+", m["version"])): p.append("BAD_VERSION")
    if m["contract_version"] != CONTRACT_VERSION: p.append("UNSUPPORTED_CONTRACT_VERSION")
    if m["track"] not in TRACKS: p.append("BAD_TRACK")
    if not (isinstance(m["authored_by"], str) and m["authored_by"]): p.append("BAD_AUTHOR")
    if not (isinstance(m["effects"], dict) and m["effects"]): p.append("BAD_EFFECTS")
    else:
        for e, c in m["effects"].items():
            if c not in COVERAGE: p.append(f"BAD_COVERAGE:{e}")
    if not (isinstance(m["dependencies"], dict) and all(isinstance(k, str) and isinstance(v, str) and re.fullmatch(r"\d+\.\d+\.\d+", v) for k, v in m["dependencies"].items())): p.append("BAD_DEPENDENCIES")
    if not (isinstance(m["supported_platforms"], list) and m["supported_platforms"] and all(isinstance(x, str) for x in m["supported_platforms"])): p.append("BAD_PLATFORMS")
    sg = m["signer"]
    if not (isinstance(sg, dict) and set(sg) == {"kid", "issuer"} and sg["kid"] and sg["issuer"]): p.append("BAD_SIGNER")
    tm = m["threat_model"]
    if not (isinstance(tm, dict) and set(tm) == {"path", "sha256"} and isinstance(tm["path"], str) and isinstance(tm["sha256"], str) and SHA.fullmatch(tm["sha256"])): p.append("BAD_THREAT_MODEL")
    if not (isinstance(m["evidence_digest"], str) and SHA.fullmatch(m["evidence_digest"])): p.append("BAD_EVIDENCE_DIGEST")
    ff = m["feature_flags"]
    if not (isinstance(ff, dict) and all(isinstance(k, str) and isinstance(v, bool) for k, v in ff.items())): p.append("BAD_FEATURE_FLAGS")
    return p


class Admission:
    """Operator-owned.  `trust` holds public keys only; `allow_elevation` maps module name -> set of allowed elevated flags."""
    def __init__(self, trust: TrustStore, *, root: str, evidence_root: str, allow_elevation: dict | None = None, platform_id: str | None = None):
        self.trust, self.root, self.evidence_root = trust, root, evidence_root
        self.allow = {k: set(v) for k, v in (allow_elevation or {}).items()}
        self.platform = platform_id or f"{platform.system().lower()}-{platform.machine()}"
        self.admitted: dict[str, dict] = {}

    def _deny(self, why) -> dict: return {"decision": "DENY", "reasons": sorted(set(why))}

    def admit(self, m, *, at: float | None = None) -> dict:
        try: return self._admit(m, at)
        except Exception as e: return self._deny([f"INTERNAL_ERROR_FAIL_CLOSED:{type(e).__name__}"])

    def _admit(self, m, at) -> dict:
        why = shape_problems(m)
        if why: return self._deny(why)
        if m["name"] in self.admitted: return self._deny(["ALREADY_ADMITTED"])
        if "signature" not in m: return self._deny(["UNSIGNED"])
        sg = m["signer"]
        if sg["issuer"] != REVIEW_ISSUER: why.append("SIGNER_NOT_A_REVIEW_ISSUER")
        if sg["kid"] == m["authored_by"]: why.append("AUTHOR_CANNOT_APPROVE_OWN_MODULE")
        try:
            pub = self.trust.resolve(sg["kid"], sg["issuer"], at)
            try: pub.verify(bytes.fromhex(m["signature"]), canon(m))
            except Exception: why.append("BAD_SIGNATURE")
        except TrustError as e: why.append("SIGNER_" + e.code)
        if self.platform not in m["supported_platforms"]: why.append("UNSUPPORTED_PLATFORM")
        for rel, dig, tag in ((m["threat_model"]["path"], m["threat_model"]["sha256"], "THREAT_MODEL"),):
            full = os.path.realpath(os.path.join(self.root, rel))
            if not full.startswith(os.path.realpath(self.root) + os.sep) or not os.path.isfile(full): why.append(tag + "_MISSING_OR_OUTSIDE_ROOT")
            elif file_sha(full) != dig: why.append(tag + "_DIGEST_MISMATCH")
        ev = os.path.join(self.evidence_root, m["evidence_digest"])
        if not os.path.isfile(ev) or file_sha(ev) != m["evidence_digest"]: why.append("EVIDENCE_NOT_FOUND_OR_DIGEST_MISMATCH")
        for dep, ver in m["dependencies"].items():
            if dep not in self.admitted: why.append(f"DEPENDENCY_NOT_ADMITTED:{dep}")
            elif self.admitted[dep]["version"] != ver: why.append(f"DEPENDENCY_VERSION_MISMATCH:{dep}")
            elif m["track"] != "research" and self.admitted[dep]["track"] == "research": why.append(f"NONRESEARCH_DEPENDS_ON_RESEARCH:{dep}")
        wanted = {k for k, v in m["feature_flags"].items() if v and k in ELEVATED}
        if wanted - self.allow.get(m["name"], set()): why.append("ELEVATION_NOT_ALLOWED:" + ",".join(sorted(wanted - self.allow.get(m["name"], set()))))
        if m["track"] == "research" and "mandatory_enforcement" in wanted: why.append("RESEARCH_MODULE_CANNOT_JOIN_ENFORCEMENT_PATH")
        if any(v == "protected" for v in m["effects"].values()) and m["track"] == "research": why.append("RESEARCH_MODULE_CANNOT_CLAIM_PROTECTED")
        if why: return self._deny(why)
        self.admitted[m["name"]] = m; return {"decision": "ADMIT", "reasons": []}

    def revoke(self, name: str) -> list:
        """Withdraw a module and, transitively, everything that depends on it (claim-closure suspension)."""
        gone, todo = [], [name]
        while todo:
            n = todo.pop()
            if n in self.admitted:
                del self.admitted[n]; gone.append(n)
                todo += [k for k, v in self.admitted.items() if n in v["dependencies"]]
        return sorted(gone)

    def coverage_map(self) -> dict:
        """Per-effect-class coverage by admitted modules.  No aggregate score by design."""
        out = {}
        for m in self.admitted.values():
            for e, c in m["effects"].items(): out.setdefault(e, {k: [] for k in COVERAGE})[c].append(m["name"])
        return {"effects": {e: {k: sorted(v) for k, v in d.items()} for e, d in sorted(out.items())}, "note": "No effect is 'safe' because a module lists it; 'protected' means the module's own manifest claims mandatory mediation, pending independent attestation."}
