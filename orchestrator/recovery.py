"""Backup/restore, audit of VERIFIED claims, checkpoints, manifests and shutdown handling (P76-08..P76-18). Stdlib only."""
from __future__ import annotations
import hashlib, hmac, json, os, re, shutil, signal, sqlite3, tempfile, time
from pathlib import Path
from .ledger import Ledger, LedgerError, sign

SECRET_RE = re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|authorization|private[_-]?key)\s*[=:]\s*\S+|"
                       r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|"
                       r"\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,})\b")


def scrub(text: str) -> str:
    return SECRET_RE.sub("[REDACTED]", text)


def backup(ledger: Ledger, dest: str | Path) -> str:
    """Consistent online backup via the SQLite backup API; returns sha256 of the copy. Refuses to back up a broken journal."""
    if not ledger.verify_journal(): raise LedgerError("refusing to back up: journal hash chain is broken")
    dest = Path(dest); tmp = dest.with_suffix(".tmp")
    if tmp.exists(): tmp.unlink()
    out = sqlite3.connect(str(tmp)); ledger.db.backup(out); out.close()
    os.replace(tmp, dest)
    return hashlib.sha256(dest.read_bytes()).hexdigest()


def audit_verified(ledger: Ledger) -> list[str]:
    """Return problems; [] means every VERIFIED task is justified by a journaled verifier transition for the same sha and plan.
    Used after restore to prove no false VERIFIED state (P76-18)."""
    probs = []
    if not ledger.verify_journal(): probs.append("journal hash chain broken")
    plan = ledger.plan_digest()
    for tid, vsha in ledger.db.execute("SELECT id, verified_sha FROM tasks WHERE status='VERIFIED'").fetchall():
        rows = ledger.db.execute("SELECT actor, detail FROM journal WHERE task=? AND to_='VERIFIED' ORDER BY seq DESC LIMIT 1", (tid,)).fetchone()
        if not rows: probs.append(f"{tid}: VERIFIED with no journaled transition"); continue
        actor, d = rows; d = json.loads(d)
        if ledger.principals.get(actor, ("",))[0] != "verifier": probs.append(f"{tid}: VERIFIED by non-verifier {actor!r}")
        if d.get("git_sha") != vsha: probs.append(f"{tid}: verified_sha does not match journaled receipt")
        if d.get("plan") != plan or d.get("_plan") != plan: probs.append(f"{tid}: receipt/journal bound to a different plan digest")
        if d.get("exit_code") != 0: probs.append(f"{tid}: receipt exit_code is not 0")
    return probs


def restore(backup_path: str | Path, dest: str | Path, principals, expect_sha256: str | None = None) -> Ledger:
    """Restore into `dest` (must not exist), then audit. On any problem the restored file is removed and an error is raised."""
    backup_path, dest = Path(backup_path), Path(dest)
    if dest.exists(): raise LedgerError("restore target exists; refusing to overwrite")
    if expect_sha256 and hashlib.sha256(backup_path.read_bytes()).hexdigest() != expect_sha256:
        raise LedgerError("backup hash mismatch")
    shutil.copyfile(backup_path, dest)
    try:
        led = Ledger(dest, principals); probs = audit_verified(led)
    except Exception:
        dest.unlink(missing_ok=True); raise
    if probs:
        led.db.close(); dest.unlink(missing_ok=True)
        raise LedgerError("restored ledger failed audit: " + "; ".join(probs[:5]))
    return led


def manifest(root: str | Path, files: list[str], test_rev: str) -> dict:
    """Atomic artifact hash manifest (P76-09). Paths must stay inside root; symlinks are rejected."""
    root = Path(root).resolve(); ent = {}
    for rel in sorted(files):
        p = (root / rel)
        if p.is_symlink() or not str(p.resolve()).startswith(str(root) + os.sep): raise LedgerError(f"path escapes root or is a symlink: {rel}")
        ent[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    body = {"files": ent, "test_revision": test_rev}
    return {**body, "manifest_sha256": hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()}


def write_atomic(path: str | Path, data: str) -> None:
    path = Path(path); fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w") as f: f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True); raise


def checkpoint(root: str | Path, task: str, epoch: int, files: dict[str, str]) -> Path:
    """Versioned, isolated, credential-scrubbed checkpoint of uncommitted worker progress (P76-08)."""
    if not re.fullmatch(r"P[0-9]{1,3}-[0-9]{2}", task): raise LedgerError("bad task id")
    for rel in files:                                                  # validate everything BEFORE touching the filesystem
        if rel.startswith("/") or ".." in Path(rel).parts: raise LedgerError(f"unsafe checkpoint path {rel}")
    d = Path(root) / task / f"epoch-{epoch}-{time.time_ns()}"; d.mkdir(parents=True, exist_ok=False, mode=0o700)
    for rel, text in files.items():
        t = d / rel; t.parent.mkdir(parents=True, exist_ok=True); t.write_text(scrub(text))
    return d


class Shutdown:
    """SIGTERM/SIGINT handler: sets a flag so the supervisor loop stops leasing and exits at a safe point. State already lives in
    transactional storage, so nothing queued or active is lost (P76-10). Install explicitly; never at import time."""
    def __init__(self): self.requested = False
    def install(self):
        for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, lambda *_: setattr(self, "requested", True))
        return self


def rotate_log(path: str | Path, max_bytes: int, keep: int) -> None:
    path = Path(path)
    if not path.exists() or path.stat().st_size < max_bytes: return
    for i in range(keep - 1, 0, -1):
        a = path.with_name(f"{path.name}.{i}")
        if a.exists(): os.replace(a, path.with_name(f"{path.name}.{i+1}"))
    os.replace(path, path.with_name(path.name + ".1"))
    old = path.with_name(f"{path.name}.{keep + 1}"); old.unlink(missing_ok=True)
