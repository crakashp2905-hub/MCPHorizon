"""Append-only hash-chained audit log and verifier (P3-17). Records contain digests and codes, never raw arguments."""
from __future__ import annotations
import hashlib, json, os, threading

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str, fsync: bool = False):
        self.path, self.fsync, self.lock = path, fsync, threading.Lock()
        self.fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        self.prev = self._last_hash()

    def _last_hash(self) -> str:
        try:
            last = None
            with open(self.path, "rb") as f:
                for last in f: pass
            return json.loads(last)["hash"] if last else GENESIS
        except (OSError, ValueError, KeyError): return GENESIS

    def write(self, rec: dict) -> str:
        with self.lock:
            body = {**rec, "prev": self.prev}
            h = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            os.write(self.fd, (json.dumps({**body, "hash": h}, sort_keys=True) + "\n").encode())
            if self.fsync: os.fsync(self.fd)
            self.prev = h
            return h

    def writable(self) -> bool:
        try: os.fstat(self.fd); return True
        except OSError: return False


def verify_audit(path: str) -> tuple[bool, str]:
    prev, n = GENESIS, 0
    with open(path, "rb") as f:
        for i, line in enumerate(f, 1):
            try: rec = json.loads(line)
            except ValueError: return False, f"line {i}: not JSON (truncated or corrupted)"
            h = rec.pop("hash", None)
            if rec.get("prev") != prev: return False, f"line {i}: broken chain (deleted/reordered/inserted record)"
            if hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != h:
                return False, f"line {i}: record modified"
            prev, n = h, n + 1
    return True, f"{n} records, head {prev[:12]}"
