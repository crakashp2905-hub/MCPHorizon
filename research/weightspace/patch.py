"""Weight-space patch API, model-free slice (HP-008, HP-009, HP-020, HP-022, HP-026). RESEARCH, CANDIDATE, never imported by the trusted kernel.
A checkpoint here is {tensor_name: numpy array}. A patch is a sparse list of (tensor, flat_index, new_value) proposals. validate() enforces the budget (count AND L2 norm of the delta), finite values, known
tensor/index/dtype; apply() is copy-on-write (the base is never mutated); the manifest is content-addressed and binds base digest, indices digest and delta digest; inverse() restores the base exactly.
No model was loaded or edited to produce this code: it is plumbing for HP experiments that are BLOCKED until model hosts are reachable."""
from __future__ import annotations
import hashlib, json
import numpy as np


class PatchError(ValueError):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


def checkpoint_digest(ckpt: dict) -> str:
    h = hashlib.sha256(b"horizonpatch.ckpt.v0\x00")
    for name in sorted(ckpt):
        a = np.ascontiguousarray(ckpt[name]); h.update(name.encode() + b"\x00" + str(a.dtype).encode() + b"\x00" + json.dumps(a.shape).encode() + b"\x00" + a.tobytes())
    return h.hexdigest()


def _edits(proposal): return sorted(((e["tensor"], int(e["index"]), float(e["value"])) for e in proposal["edits"]), key=lambda x: (x[0], x[1]))


def validate(base: dict, proposal: dict, *, max_entries: int, max_l2: float, allowed_tensors: set) -> dict:
    if not isinstance(proposal, dict) or set(proposal) != {"base_digest", "hypothesis", "edits"}: raise PatchError("MALFORMED")
    if proposal["base_digest"] != checkpoint_digest(base): raise PatchError("BASE_MISMATCH")
    if not isinstance(proposal["hypothesis"], str) or not proposal["hypothesis"].strip(): raise PatchError("NO_HYPOTHESIS")
    eds = proposal["edits"]
    if not isinstance(eds, list) or not eds: raise PatchError("EMPTY")
    if len(eds) > max_entries: raise PatchError("BUDGET_ENTRIES")
    seen, sq = set(), 0.0
    for e in eds:
        if not isinstance(e, dict) or set(e) != {"tensor", "index", "value"}: raise PatchError("MALFORMED")
        t, i, v = e["tensor"], e["index"], e["value"]
        if t not in base or t not in allowed_tensors: raise PatchError("TENSOR_NOT_ALLOWED", str(t))
        if not isinstance(i, int) or isinstance(i, bool) or not (0 <= i < base[t].size): raise PatchError("INDEX_OUT_OF_RANGE")
        if not isinstance(v, (int, float)) or isinstance(v, bool) or not np.isfinite(v): raise PatchError("NONFINITE")
        if not np.issubdtype(base[t].dtype, np.floating): raise PatchError("DTYPE")
        if (t, i) in seen: raise PatchError("DUPLICATE_INDEX")
        seen.add((t, i)); sq += (float(v) - float(base[t].flat[i])) ** 2
    l2 = sq ** 0.5
    if l2 > max_l2: raise PatchError("BUDGET_NORM")
    return {"entries": len(eds), "delta_l2": l2}


def manifest(base: dict, proposal: dict, stats: dict) -> dict:
    eds = _edits(proposal); idx = hashlib.sha256(json.dumps([(t, i) for t, i, _ in eds]).encode()).hexdigest(); dl = hashlib.sha256(json.dumps([(t, i, repr(v)) for t, i, v in eds]).encode()).hexdigest()
    body = {"schema_version": "horizonpatch.v0", "base_checkpoint_sha256": checkpoint_digest(base), "hypothesis": proposal["hypothesis"], "edit_method": "gradient_free_sparse_weight_edit",
            "indices_digest": idx, "delta_digest": dl, "num_entries": stats["entries"], "delta_l2": stats["delta_l2"], "status": "CANDIDATE", "authorized_by": None, "limitations": ["not independently verified", "no production authorization"]}
    body["patch_id"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest(); return body


def apply(base: dict, proposal: dict, **budget) -> tuple:
    """Copy-on-write. Returns (candidate, manifest, inverse_proposal). The base dict and its arrays are untouched."""
    stats = validate(base, proposal, **budget); cand = {k: v.copy() for k, v in base.items()}; inv = []
    for t, i, v in _edits(proposal):
        inv.append({"tensor": t, "index": i, "value": float(base[t].flat[i])}); cand[t].flat[i] = v
    for a in cand.values():
        if np.issubdtype(a.dtype, np.floating) and not np.all(np.isfinite(a)): raise PatchError("NONFINITE_AFTER_APPLY")
    m = manifest(base, proposal, stats); return cand, m, {"base_digest": checkpoint_digest(cand), "hypothesis": "inverse of " + m["patch_id"], "edits": inv}


def verify_manifest(base: dict, cand: dict, proposal: dict, m: dict) -> bool:
    """Independent re-derivation: same base, same digests, and the candidate differs from base EXACTLY at the declared indices."""
    try: stats = validate(base, proposal, max_entries=10**9, max_l2=float("inf"), allowed_tensors=set(base))
    except PatchError: return False
    if manifest(base, proposal, stats) != m: return False
    declared = {(t, i) for t, i, _ in _edits(proposal)}
    for t in base:
        if base[t].shape != cand.get(t, np.empty(0)).shape: return False
        for i in np.flatnonzero(base[t].ravel() != cand[t].ravel()):
            if (t, int(i)) not in declared: return False
    return set(cand) == set(base)
