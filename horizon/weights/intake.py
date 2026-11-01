"""HorizonWeights intake (P31). Verifies that a model's files, source, signer and runtime binding match an approved manifest BEFORE a protected runner may load it.
Two outputs are kept separate on purpose: `metadata_authenticity` (are these the bytes a trusted signer approved?) and `behavioral_trust` (always UNASSESSED here: digest checks say nothing about dormant behaviour).
Fails closed: any verification error or unavailable trust root yields DENY. No network access; no model is loaded or executed."""
from __future__ import annotations
import hashlib, json, os, re, time
from horizon.authz.keys import TrustStore, TrustError, Signer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "horizon.model.v1"
ROLES = ("weight", "tokenizer", "adapter", "config")
SAFE_FORMATS = {".safetensors", ".json", ".txt", ".model", ".tiktoken"}          # data-only formats
UNSAFE_FORMATS = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".npy", ".joblib", ".py", ".so", ".sh", ".exe", ".dll"}
MUTABLE_REFS = {"latest", "main", "master", "head", "stable", "dev", "nightly", "release"}
PICKLE_MAGIC = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05", b"PK\x03\x04")     # pickle protocols 2-5, zip container (torch.save)

def sha(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
def canon(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def body(m: dict) -> dict: return {k: v for k, v in m.items() if k != "signature"}
def digest(m: dict) -> str: return sha(canon(body(m)))

class IntakeError(Exception):
    def __init__(self, code, detail=""): super().__init__(f"{code}: {detail}"); self.code, self.detail = code, detail

# ------------------------------------------------------------------ schema (P31-02)
def validate_schema(m: dict) -> list:
    """Return a list of problems (empty = valid). Typed, closed-world: unknown top-level keys are problems."""
    p = []; allowed = {"schema", "model_id", "kind", "source", "files", "base", "license", "dependencies", "runtime", "signer", "signature", "created"}
    if not isinstance(m, dict): return ["NOT_AN_OBJECT"]
    p += [f"UNKNOWN_KEY:{k}" for k in m if k not in allowed]
    if m.get("schema") != SCHEMA: p.append("BAD_SCHEMA")
    if m.get("kind") not in ("base", "adapter"): p.append("BAD_KIND")
    if not isinstance(m.get("model_id"), str) or not m.get("model_id"): p.append("MISSING_MODEL_ID")
    s = m.get("source")
    if not (isinstance(s, dict) and all(isinstance(s.get(k), str) and s.get(k) for k in ("repo", "revision", "registry_uri"))): p.append("BAD_SOURCE")
    fs = m.get("files")
    if not (isinstance(fs, list) and fs): p.append("NO_FILES")
    else:
        seen = set()
        for f in fs:
            if not (isinstance(f, dict) and isinstance(f.get("path"), str) and f.get("role") in ROLES and isinstance(f.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", f["sha256"]) and isinstance(f.get("size"), int) and f["size"] >= 0): p.append(f"BAD_FILE:{f.get('path') if isinstance(f, dict) else f}")
            elif f["path"] in seen or f["path"].startswith("/") or ".." in f["path"].split("/"): p.append(f"BAD_PATH:{f['path']}")
            else: seen.add(f["path"])
    if m.get("kind") == "adapter" and not (isinstance(m.get("base"), dict) and re.fullmatch(r"[0-9a-f]{64}", str(m["base"].get("manifest_digest", "")))): p.append("ADAPTER_WITHOUT_BASE_DIGEST")
    if not (isinstance(m.get("license"), dict) and "spdx" in m["license"] and "redistribution" in m["license"]): p.append("BAD_LICENSE")
    if not (isinstance(m.get("dependencies"), dict)): p.append("BAD_DEPENDENCIES")
    sg = m.get("signer")
    if not (isinstance(sg, dict) and sg.get("kid") and sg.get("issuer")): p.append("BAD_SIGNER")
    return p

# ------------------------------------------------------------------ signing (P31-04)
def sign(m: dict, signer: Signer) -> dict:
    m = {**body(m), "signer": {"kid": signer.kid, "issuer": signer.iss}}; m["signature"] = signer.sign(canon(m)).hex(); return m
def verify_signature(m: dict, trust: TrustStore, *, at: float | None = None) -> None:
    """Signer identity comes from a TrustStore owned by the platform, not from the manifest or the agent runtime. Raises IntakeError on unknown, revoked, out-of-window or invalid."""
    sg = m.get("signer") or {}
    try: pub = trust.resolve(sg.get("kid", ""), sg.get("issuer", ""), at)
    except TrustError as e: raise IntakeError("SIGNER_" + e.code, str(e))
    try: sig = bytes.fromhex(m.get("signature", ""))
    except ValueError: raise IntakeError("BAD_SIGNATURE_ENCODING")
    try: pub.verify(sig, canon(body(m)))
    except Exception: raise IntakeError("BAD_SIGNATURE", "manifest body does not match signature")

# ------------------------------------------------------------------ pinning (P31-05)
def check_pins(m: dict, *, protected: bool = True) -> list:
    s, p = m.get("source", {}), []
    rev = str(s.get("revision", ""))
    if protected:
        if rev.lower() in MUTABLE_REFS or not re.fullmatch(r"[0-9a-f]{40}", rev): p.append("MUTABLE_OR_INEXACT_REVISION")
        uri = str(s.get("registry_uri", ""))
        if not re.search(r"@sha256:[0-9a-f]{64}$", uri) or re.search(r":(latest|main|master)$", uri): p.append("REGISTRY_URI_NOT_DIGEST_PINNED")
        if not str(s.get("repo", "")).startswith(("registry.internal/", "hz-registry/", "local/")): p.append("SOURCE_NOT_APPROVED_REGISTRY")
    return p

# ------------------------------------------------------------------ files, formats (P31-03, P31-08)
def check_files(m: dict, root: str) -> dict:
    """Digest every declared file; flag altered, missing, extra files, unsafe formats and pickle/zip content hiding behind a safe extension."""
    bad = {"altered": [], "missing": [], "extra": [], "unsafe_format": [], "disguised_executable": [], "size_mismatch": []}; declared = {f["path"]: f for f in m["files"]}
    for path, f in declared.items():
        ext = os.path.splitext(path)[1].lower(); a = os.path.join(root, path)
        if ext in UNSAFE_FORMATS or ext not in SAFE_FORMATS: bad["unsafe_format"].append(path)
        if not os.path.isfile(a): bad["missing"].append(path); continue
        data = open(a, "rb").read()
        if len(data) != f["size"]: bad["size_mismatch"].append(path)
        if sha(data) != f["sha256"]: bad["altered"].append(path)
        if ext in SAFE_FORMATS and data.startswith(PICKLE_MAGIC): bad["disguised_executable"].append(path)
    for dp, _, fn in os.walk(root):
        for n in fn:
            rel = os.path.relpath(os.path.join(dp, n), root)
            if rel not in declared: bad["extra"].append(rel)
    bad["ok"] = not any(v for k, v in bad.items() if k != "ok"); return bad

# ------------------------------------------------------------------ adapters, drift, upgrades (P31-11, P31-12)
def check_adapter_binding(adapter: dict, approved_base: dict) -> list:
    if adapter.get("kind") != "adapter": return []
    return [] if adapter["base"]["manifest_digest"] == digest(approved_base) else ["ADAPTER_BASE_MISMATCH"]
def role_digests(m: dict) -> dict:
    out = {}
    for f in m["files"]: out.setdefault(f["role"], {})[f["path"]] = f["sha256"]
    return out
def drift(approved: dict, candidate: dict) -> dict:
    a, c = role_digests(approved), role_digests(candidate)
    return {r: sorted(p for p in set(a.get(r, {})) | set(c.get(r, {})) if a.get(r, {}).get(p) != c.get(r, {}).get(p)) for r in ROLES if a.get(r) != c.get(r)}
def issue_upgrade(signer: Signer, *, old_digest: str, new_digest: str, reason: str, ttl_s: int = 3600, now=None) -> dict:
    """An approved model upgrade is a SEPARATE signed record naming both manifest digests; it never lets an unsigned drift through."""
    now = time.time() if now is None else now; b = {"kind": "model-upgrade", "old": old_digest, "new": new_digest, "reason": reason, "exp": now + ttl_s, "signer": {"kid": signer.kid, "issuer": signer.iss}}
    return {**b, "signature": signer.sign(canon(b)).hex()}
def check_upgrade(u: dict, trust: TrustStore, *, old_digest: str, new_digest: str, now=None) -> None:
    now = time.time() if now is None else now; sg = u.get("signer", {})
    try: pub = trust.resolve(sg.get("kid", ""), sg.get("issuer", ""), now)
    except TrustError as e: raise IntakeError("UPGRADE_SIGNER_" + e.code)
    b = {k: v for k, v in u.items() if k != "signature"}
    try: pub.verify(bytes.fromhex(u["signature"]), canon(b))
    except Exception: raise IntakeError("UPGRADE_BAD_SIGNATURE")
    if u["exp"] < now: raise IntakeError("UPGRADE_EXPIRED")
    if (u["old"], u["new"]) != (old_digest, new_digest): raise IntakeError("UPGRADE_NOT_FOR_THESE_DIGESTS")

# ------------------------------------------------------------------ runtime binding (P31-09)
def check_runtime(m: dict, *, image_digest: str, launch_config: dict) -> list:
    r = m.get("runtime", {}); p = []
    if r.get("image_digest") != image_digest: p.append("RUNTIME_IMAGE_NOT_APPROVED")
    if r.get("launch_config_sha256") != sha(canon(launch_config)): p.append("LAUNCH_CONFIG_NOT_APPROVED")
    return p

# ------------------------------------------------------------------ quarantine, revocation, incident evidence (P31-13)
class Quarantine:
    """Revoked sources and quarantined manifest digests. Incident evidence is an append-only hash chain: entries cannot be edited or removed without breaking verification."""
    def __init__(self): self.revoked_sources, self.quarantined, self.chain = set(), {}, []
    def revoke_source(self, repo: str, why: str): self.revoked_sources.add(repo); self._log("revoke_source", {"repo": repo, "why": why})
    def quarantine(self, mdigest: str, why: str, evidence: dict): self.quarantined[mdigest] = why; self._log("quarantine", {"manifest": mdigest, "why": why, "evidence_sha256": sha(canon(evidence))})
    def _log(self, kind, data):
        prev = self.chain[-1]["hash"] if self.chain else "0" * 64; e = {"seq": len(self.chain), "kind": kind, "data": data, "prev": prev}; e["hash"] = sha(canon({k: e[k] for k in ("seq", "kind", "data", "prev")})); self.chain.append(e)
    def verify_chain(self) -> bool:
        prev = "0" * 64
        for i, e in enumerate(self.chain):
            if e["seq"] != i or e["prev"] != prev or e["hash"] != sha(canon({k: e[k] for k in ("seq", "kind", "data", "prev")})): return False
            prev = e["hash"]
        return True

# ------------------------------------------------------------------ admission + report + receipt (P31-07, P31-14, P31-15)
def admit(m: dict, root: str, *, trust: TrustStore | None, quarantine: Quarantine, image_digest: str, launch_config: dict, protected: bool = True, approved_base: dict | None = None,
          approved: dict | None = None, upgrade: dict | None = None, at: float | None = None) -> dict:
    """The protected-runner admission decision. Every check must pass; ANY exception or missing trust root is DENY (fail closed). `approved` = the currently approved manifest for this model_id (for drift)."""
    reasons, checks = [], {}
    def step(name, fn):
        try: r = fn()
        except IntakeError as e: reasons.append(e.code); checks[name] = e.code; return None
        except Exception as e: reasons.append(f"VERIFICATION_UNAVAILABLE:{name}:{type(e).__name__}"); checks[name] = "UNAVAILABLE"; return None
        if r: reasons.extend(r if isinstance(r, list) else []); checks[name] = r
        else: checks[name] = "ok"
        return r
    if trust is None: reasons.append("TRUST_ROOT_UNAVAILABLE")
    sp = validate_schema(m); checks["schema"] = sp or "ok"; reasons += sp
    if not sp:
        if trust is not None: step("signature", lambda: verify_signature(m, trust, at=at))
        step("pins", lambda: check_pins(m, protected=protected))
        fr = check_files(m, root); checks["files"] = {k: v for k, v in fr.items() if v and k != "ok"} or "ok"
        if not fr["ok"]: reasons += [f"FILE_{k.upper()}:{','.join(v)}" for k, v in fr.items() if k != "ok" and v]
        step("runtime", lambda: check_runtime(m, image_digest=image_digest, launch_config=launch_config))
        if approved_base is not None: step("adapter", lambda: check_adapter_binding(m, approved_base))
        elif m.get("kind") == "adapter": reasons.append("ADAPTER_WITHOUT_APPROVED_BASE")
        if m["source"]["repo"] in quarantine.revoked_sources: reasons.append("SOURCE_REVOKED")
        if digest(m) in quarantine.quarantined: reasons.append("MANIFEST_QUARANTINED")
        if approved is not None and digest(approved) != digest(m):
            d = drift(approved, m)
            if upgrade is None: reasons.append("DRIFT_WITHOUT_UPGRADE:" + ",".join(sorted(d)) if d else "MANIFEST_DIFFERS_WITHOUT_UPGRADE")
            elif trust is not None: step("upgrade", lambda: check_upgrade(upgrade, trust, old_digest=digest(approved), new_digest=digest(m), now=at))
    decision = "ADMIT" if not reasons else "DENY"
    return {"decision": decision, "reasons": reasons, "checks": checks, "manifest_digest": digest(m) if not sp else None, "model_id": m.get("model_id") if isinstance(m, dict) else None,
            "report": {"metadata_authenticity": "AUTHENTIC" if decision == "ADMIT" else "NOT_AUTHENTIC" if reasons else "UNKNOWN",
                       "behavioral_trust": "UNASSESSED",
                       "note": "metadata authenticity says these are the bytes a trusted signer approved; it says NOTHING about dormant or conditional behaviour (see docs/evidence/p31/DORMANT_TRIGGER_LIMITS.md)"}}
def receipt(result: dict, signer: Signer, *, run_id: str, source: dict, now=None) -> dict:
    """Source-bound signed intake receipt; attach to the run trace so a verifier can tie a run to exactly the manifest that was admitted."""
    b = {"kind": "model-intake-receipt", "run_id": run_id, "decision": result["decision"], "manifest_digest": result["manifest_digest"], "reasons": result["reasons"], "source": {k: source.get(k) for k in ("repo", "revision", "registry_uri")},
         "report": result["report"], "ts": time.time() if now is None else now, "signer": {"kid": signer.kid, "issuer": signer.iss}}
    return {**b, "signature": signer.sign(canon(b)).hex()}
def verify_receipt(r: dict, pub_raw: bytes) -> bool:
    try: Ed25519PublicKey.from_public_bytes(pub_raw).verify(bytes.fromhex(r["signature"]), canon({k: v for k, v in r.items() if k != "signature"})); return True
    except Exception: return False
def attach_to_trace(trace: dict, rcpt: dict) -> dict:
    t = dict(trace); t["model_intake_receipt"] = rcpt; t["model_manifest_digest"] = rcpt["manifest_digest"]; return t

# ------------------------------------------------------------------ inventory (P31-01)
LOAD_PATTERNS = {"hf_from_pretrained": r"\.from_pretrained\(", "torch_load": r"\btorch\.load\(", "pickle_load": r"\bpickle\.loads?\(|\bcPickle\.", "joblib_load": r"\bjoblib\.load\(", "safetensors_load": r"safetensors", "gguf_or_onnx_load": r"\.gguf|onnxruntime|InferenceSession\(",
                 "adapter_load": r"PeftModel|load_adapter|\.load_lora", "tokenizer_load": r"AutoTokenizer|sentencepiece|tiktoken", "remote_model_ref": r"huggingface\.co|hf_hub_download|snapshot_download|:latest\b|revision=['\"]main['\"]", "yaml_unsafe_load": r"yaml\.load\((?!.*SafeLoader)", "eval_exec_loading": r"\bexec\(|\beval\("}
def inventory(root: str, dirs=("horizon", "bench", "scripts")) -> dict:
    out = {k: [] for k in LOAD_PATTERNS}
    for d in dirs:
        for dp, dn, fn in os.walk(os.path.join(root, d)):
            dn[:] = [x for x in dn if x != "__pycache__"]
            for n in fn:
                if not n.endswith(".py") or n in ("intake.py",): continue
                rel = os.path.relpath(os.path.join(dp, n), root)
                for i, line in enumerate(open(os.path.join(dp, n), errors="replace"), 1):
                    if line.lstrip().startswith("#"): continue
                    for k, rx in LOAD_PATTERNS.items():
                        if re.search(rx, line): out[k].append(f"{rel}:{i}")
    return out
