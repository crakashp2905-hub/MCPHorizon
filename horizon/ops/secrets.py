"""Secret provider and honeytokens (P10-02, P10-12). Secrets never appear in repr/str/logs; providers are allowlisted; file secrets must be private."""
from __future__ import annotations
import hashlib, os, secrets as _s, stat
from pathlib import Path


class SecretError(Exception): pass


class Secret:
    __slots__ = ("_v", "name")
    def __init__(self, name: str, value: str): self.name, self._v = name, value
    def reveal(self) -> str: return self._v
    def __repr__(self): return f"Secret({self.name!r}, <redacted>)"
    __str__ = __repr__
    def __reduce__(self): raise TypeError("Secret objects are not serialisable")
    def __format__(self, spec): return repr(self)
    def __eq__(self, other): return isinstance(other, Secret) and hashlib.sha256(self._v.encode()).digest() == hashlib.sha256(other._v.encode()).digest()
    __hash__ = None


class SecretProvider:
    def __init__(self, *, env_allow: set[str] = frozenset(), file_root: str | None = None, environ=None):
        self.env_allow, self.root, self.environ = set(env_allow), (Path(file_root).resolve() if file_root else None), environ if environ is not None else os.environ

    def get(self, ref: str) -> Secret:
        kind, _, name = ref.partition(":")
        if kind == "env":
            if name not in self.env_allow: raise SecretError(f"environment variable {name!r} is not allowlisted")
            if name not in self.environ: raise SecretError(f"environment variable {name!r} is not set")
            return Secret(ref, self.environ[name])
        if kind == "file":
            if self.root is None: raise SecretError("file secrets are not configured")
            raw = self.root / name; p = raw.parent.resolve() / raw.name                  # resolve the directory part only: the final component must not be a symlink
            if self.root not in p.parents: raise SecretError("secret path escapes the secret root")
            st = p.lstat() if os.path.lexists(p) else None
            if st is None: raise SecretError("secret file not found")
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode): raise SecretError("secret must be a regular file")
            if st.st_mode & 0o077: raise SecretError("secret file must not be group/world accessible (mode 0600)")
            if st.st_uid != os.getuid(): raise SecretError("secret file must be owned by the service user")
            return Secret(ref, p.read_text().rstrip("\n"))
        raise SecretError(f"unknown secret provider {kind!r}")


def make_honeytokens(n: int = 3, prefix: str = "HNY") -> list[str]:
    """Canary values that must NEVER appear in logs, audit, traces, metrics or error bodies."""
    return [f"{prefix}-{_s.token_hex(12)}" for _ in range(n)]


def assert_absent(tokens: list[str], paths: list[str], extra_texts: list[str] = ()) -> list[str]:
    """Return the list of places (file path or 'text[i]') where any honeytoken, or its common encodings, appears."""
    import base64, binascii
    pats = []
    for t in tokens: b = t.encode(); pats += [b, base64.b64encode(b), base64.urlsafe_b64encode(b), binascii.hexlify(b), b[::-1]]
    hits = []
    for p in paths:
        pp = Path(p)
        for f in ([pp] if pp.is_file() else [x for x in pp.rglob("*") if x.is_file()] if pp.exists() else []):
            data = f.read_bytes()
            if any(x in data for x in pats): hits.append(str(f))
    for i, t in enumerate(extra_texts):
        d = t.encode() if isinstance(t, str) else bytes(t)
        if any(x in d for x in pats): hits.append(f"text[{i}]")
    return hits
