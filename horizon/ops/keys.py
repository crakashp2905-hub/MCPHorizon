"""Key lifecycle and audit integrity stamps (P10-13). States: ACTIVE -> RETIRED (verify only) -> REVOKED (nothing verifies). Stamps anchor the audit head so truncation/rewrite is detectable."""
from __future__ import annotations
import hashlib, hmac, json, os, time


class KeyError_(Exception):
    def __init__(self, code, msg): super().__init__(msg); self.code = code


class KeyRing:
    def __init__(self, clock=time.time): self.k: dict[str, dict] = {}; self.clock = clock; self.n = 0

    def rotate(self) -> str:
        for v in self.k.values():
            if v["state"] == "ACTIVE": v["state"], v["retired_at"] = "RETIRED", self.clock()
        self.n += 1; kid = f"k{self.n}"; self.k[kid] = {"key": os.urandom(32), "state": "ACTIVE", "created": self.clock()}; return kid

    def active(self) -> str:
        for kid, v in self.k.items():
            if v["state"] == "ACTIVE": return kid
        raise KeyError_("NO_ACTIVE_KEY", "no active key; rotate first")

    def revoke(self, kid: str): self.k[kid]["state"] = "REVOKED"; self.k[kid]["key"] = b""            # zeroise on revoke

    def sign(self, data: bytes) -> dict:
        kid = self.active(); return {"kid": kid, "mac": hmac.new(self.k[kid]["key"], data, hashlib.sha256).hexdigest()}

    def verify(self, data: bytes, sig: dict) -> bool:
        v = self.k.get(sig.get("kid"))
        if not v or v["state"] not in ("ACTIVE", "RETIRED"): return False
        return hmac.compare_digest(sig.get("mac", ""), hmac.new(v["key"], data, hashlib.sha256).hexdigest())

    def due_for_rotation(self, max_age_s: float) -> bool:
        try: return self.clock() - self.k[self.active()]["created"] > max_age_s
        except KeyError_: return True


def audit_stamp(ring: KeyRing, audit_path: str) -> dict:
    """Signed checkpoint of (record count, head hash, file size). Store it outside the audit file's trust domain."""
    n, head, size = 0, "0" * 64, os.path.getsize(audit_path)
    with open(audit_path, "rb") as f:
        for line in f: n += 1; head = json.loads(line)["hash"]
    body = {"count": n, "head": head, "size": size, "t": ring.clock()}; return {**body, "sig": ring.sign(json.dumps(body, sort_keys=True).encode())}


def verify_stamp(ring: KeyRing, stamp: dict, audit_path: str) -> tuple[bool, str]:
    body = {k: stamp[k] for k in ("count", "head", "size", "t")}
    if not ring.verify(json.dumps(body, sort_keys=True).encode(), stamp.get("sig", {})): return False, "stamp signature invalid or key revoked"
    lines = []
    with open(audit_path, "rb") as f:
        for line in f: lines.append(json.loads(line)["hash"])
    if len(lines) < stamp["count"]: return False, "audit log truncated since stamp"
    if stamp["count"] and lines[stamp["count"] - 1] != stamp["head"]: return False, "audit history rewritten since stamp"
    return True, "ok"
