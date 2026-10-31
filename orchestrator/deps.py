"""Dependency lock policy (candidate for P86-07). A lock line must pin an exact version AND at least one sha256 hash; installed/downloaded
artifacts are accepted only if their digest is listed. Missing checksums are an error, not a warning."""
from __future__ import annotations
import hashlib, re

LINE = re.compile(r"^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.!+\-]+)\s*((?:\\?\s*--hash=sha256:[0-9a-f]{64}\s*)*)$")


class DepError(Exception):
    pass


def parse_lock(text: str) -> dict[str, dict]:
    out, cur = {}, ""
    for raw in text.splitlines():
        line = (cur + raw.strip()).strip()
        if not line or line.startswith("#"): continue
        if line.endswith("\\"): cur = line[:-1] + " "; continue
        cur = ""
        m = LINE.match(line)
        if not m: raise DepError(f"unparseable or unpinned lock line: {line[:80]!r}")
        name, ver, hs = m.group(1).lower().replace("_", "-"), m.group(2), re.findall(r"sha256:([0-9a-f]{64})", m.group(3))
        out[name] = {"version": ver, "hashes": set(hs)}
    return out


def require_hashes(lock: dict[str, dict]) -> list[str]:
    """Return packages with NO checksum; callers must treat a non-empty list as a failure."""
    return sorted(n for n, e in lock.items() if not e["hashes"])


def check_artifact(lock: dict[str, dict], name: str, version: str, data: bytes) -> None:
    n = name.lower().replace("_", "-")
    if n not in lock: raise DepError(f"{name} is not in the lock (unlisted dependency)")
    e = lock[n]
    if e["version"] != version: raise DepError(f"{name}=={version} does not match locked {e['version']} (version substitution)")
    if not e["hashes"]: raise DepError(f"{name} has no checksum in the lock; refusing to trust any artifact")
    if hashlib.sha256(data).hexdigest() not in e["hashes"]: raise DepError(f"{name} artifact digest is not in the locked set (compromised mirror or tampering)")
