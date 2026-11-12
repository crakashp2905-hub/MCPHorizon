"""PR-05 (masterplan M4): installer-signed CONTROL ATTESTATION and the commit-time gate that binds assurance claims to what is actually installed.
Problem it addresses: durable claims depended on 'node digests' that anyone able to write the registry could set, so a claim could stay VALID while the control it names had changed on disk.
Flow: the installer role measures the controls (file bytes + config digest) and signs a control attestation; a registry opened with `attested_nodes_only=True` accepts node digests only from such signatures; the gate re-measures at
commit time and DENIES on any drift, expired/forged attestation, stale epoch, or non-VALID claim. The gate can only deny (it returns (False, reason) or (True, "") and the kernel still needs a valid permit).
HONEST LIMITS: measurement is a hash of files and config as seen NOW by this process: it does not prove the running process loaded those bytes (TOCTOU), is not remote/TPM attestation, and the installer key is only as trustworthy
as its custody, which is an owner decision (masterplan section 12) and is not made here. In-process, same-uid CANDIDATE."""
from __future__ import annotations
import hashlib, json, os, time
from dataclasses import dataclass
from horizon.assurance.durable import INSTALLER_ROLE, DurableError

UNMEASURABLE = "UNMEASURABLE"


class AttestError(Exception):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


def _canon(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Control:
    control_id: str; kind: str                  # kind: broker | sandbox | gate | witness | policy
    files: tuple = (); config: object = None    # files: repo-relative paths measured byte-for-byte; config: JSON-serialisable (e.g. a Policy digest)


def measure_one(c: Control, root: str) -> str:
    """sha256 over (kind, [(path, file sha256)...], config). A missing/unreadable file or a path escaping root => UNMEASURABLE (never a digest an installer would attest)."""
    parts = []
    for rel in c.files:
        p = os.path.realpath(os.path.join(root, rel)); r = os.path.realpath(root)
        if not (p == r or p.startswith(r + os.sep)) or not os.path.isfile(p): return UNMEASURABLE
        try: parts.append([rel, hashlib.sha256(open(p, "rb").read()).hexdigest()])
        except OSError: return UNMEASURABLE
    try: return "sha256:" + hashlib.sha256(_canon([c.kind, parts, c.config])).hexdigest()
    except (TypeError, ValueError): return UNMEASURABLE


def measure(controls, root: str) -> dict: return {c.control_id: measure_one(c, root) for c in controls}


def sign_control_attestation(controls, root: str, *, host_id: str, epoch: int, issued_at: float, expires_at: float, signer) -> dict:
    """Installer role only. Refuses to attest an unmeasurable control, an empty set, or an expiry in the past."""
    if getattr(signer, "iss", None) != INSTALLER_ROLE: raise AttestError("WRONG_ISSUER_ROLE")
    controls = list(controls)
    if not controls or len({c.control_id for c in controls}) != len(controls) or not all(c.control_id.startswith("control:") and len(c.control_id) > 8 for c in controls): raise AttestError("BAD_CONTROL_SET")      # ids are registry dependency ids: "control:<name>"
    m = measure(controls, root)
    bad = sorted(k for k, v in m.items() if v == UNMEASURABLE)
    if bad: raise AttestError("UNMEASURABLE_CONTROL", ",".join(bad))
    if not (isinstance(host_id, str) and host_id) or expires_at <= issued_at: raise AttestError("BAD_BODY")
    body = {"kind": "control-attestation", "host_id": host_id, "epoch": epoch, "issued_at": issued_at, "expires_at": expires_at, "controls": m}
    return {"body": body, "kid": signer.kid, "sig": signer.sign(_canon(body)).hex()}


def verify_control_attestation(att: dict, trust, now: float, *, epoch_now: int | None = None, host_id: str | None = None) -> dict:
    try:
        b = att["body"]; trust.resolve(att["kid"], INSTALLER_ROLE, at=now).verify(bytes.fromhex(att["sig"]), _canon(b))
    except Exception: raise AttestError("BAD_ATTESTATION")
    if b.get("kind") != "control-attestation" or not isinstance(b.get("controls"), dict) or not b["controls"]: raise AttestError("BAD_ATTESTATION")
    if UNMEASURABLE in b["controls"].values(): raise AttestError("BAD_ATTESTATION")
    if not (b["issued_at"] <= now < b["expires_at"]): raise AttestError("ATTESTATION_EXPIRED")
    if epoch_now is not None and b["epoch"] != epoch_now: raise AttestError("STALE_EPOCH")
    if host_id is not None and b["host_id"] != host_id: raise AttestError("WRONG_HOST")
    return b


def drift(body: dict, controls, root: str) -> list:
    """Control ids whose live measurement differs from the attested digest, plus attested controls that are no longer supplied for measurement."""
    live = measure(controls, root); return sorted(k for k, v in body["controls"].items() if live.get(k) != v)


def make_gate(registry, claim_id: str, att: dict, trust, controls, root: str, *, epoch_now, host_id: str | None = None, clock=time.time):
    """Zero-arg deny-only gate for EffectKernel / ProtectedFileWriter. On drift it records INVALIDATE events (adapter_changed) for the drifted controls so the claim stops being VALID for everyone, then denies."""
    controls = list(controls)
    def gate():
        try:
            ep = epoch_now(); body = verify_control_attestation(att, trust, clock(), epoch_now=ep, host_id=host_id)
            bad = drift(body, controls, root)
            if bad:
                for k in bad:
                    try: registry.invalidate(k, "adapter_changed")
                    except Exception: pass
                return False, "CONTROL_DRIFT:" + ",".join(bad)
            ok, why = registry.permit(claim_id, ep)
            return (True, "") if ok else (False, why or "CLAIM_NOT_VALID")
        except AttestError as e: return False, e.code
        except Exception as e: return False, "GATE_ERROR:" + type(e).__name__
    return gate
