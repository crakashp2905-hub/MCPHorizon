"""ENG-PR05 (E05, HARD-D subset): ONE protected effect path — file write — with a SINK-SIDE journal owned by the sink, not by the gateway or the agent.
FileSink is the only code that touches the filesystem; ProtectedFileWriter is the only way to reach it: commit-time permit verification -> ledger authorize/begin (at-most-once) -> sink write -> ledger outcome.
Outcome truth comes from the sink journal (sha256 of what actually landed), so a gateway claim of COMMITTED can be checked against it. Localhost/tempdir only. CANDIDATE: in-process, trusting the OS user separation is NOT claimed
(an agent running as the same OS user could bypass; real enforcement needs the sandbox/broker boundary — see limits)."""
from __future__ import annotations
import hashlib, json, os, time
from horizon.authz.gateway import ProofError
from horizon.effects.canonical import CanonicalEffect, commit_verify
from horizon.effects.ledger import EffectLedger, LedgerError


class SinkError(Exception):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


class FileSink:
    def __init__(self, root: str, journal_path: str):
        self.root = os.path.realpath(root); self.journal = journal_path; os.makedirs(self.root, exist_ok=True)

    def _resolve(self, path: str) -> str:
        real = os.path.realpath(path)                                    # resolves symlinks BEFORE the containment check
        if not (real == self.root or real.startswith(self.root + os.sep)): raise SinkError("OUTSIDE_ROOT", "path escapes sink root")
        if real == self.root or os.path.isdir(real): raise SinkError("IS_DIRECTORY")
        return real

    def write(self, path: str, data: bytes, effect_id: str) -> dict:
        real = self._resolve(path); tmp = real + ".tmp." + effect_id[:16]
        with open(tmp, "wb") as f: f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, real)
        rec = {"effect_id": effect_id, "path": real, "sha256": hashlib.sha256(open(real, "rb").read()).hexdigest(), "bytes": len(data), "ts": time.time()}
        with open(self.journal, "a") as j: j.write(json.dumps(rec, sort_keys=True) + "\n"); j.flush(); os.fsync(j.fileno())
        return rec

    def observed(self, effect_id: str) -> dict | None:
        """Independent observation: the sink journal AND the file's current digest; None if the sink never recorded it."""
        if not os.path.exists(self.journal): return None
        for line in open(self.journal):
            r = json.loads(line)
            if r["effect_id"] == effect_id:
                r["present_now"] = os.path.exists(r["path"]) and hashlib.sha256(open(r["path"], "rb").read()).hexdigest() == r["sha256"]; return r
        return None


class ProtectedFileWriter:
    def __init__(self, verifier, ledger: EffectLedger, sink: FileSink):
        self.v, self.ledger, self.sink = verifier, ledger, sink

    def write(self, token, ce: CanonicalEffect, data: bytes, effect_id: str, *, fault=None) -> dict:
        """Returns {"status": ALLOW_COMMITTED|BLOCKED|UNKNOWN|DUPLICATE, ...}. `fault` is a test hook simulating an upstream failure AFTER the write started."""
        if ce.effect != "write" or ce.target_kind != "file": return {"status": "BLOCKED", "code": "UNSUPPORTED_EFFECT"}
        import hashlib as _h
        if ce.args != {"sha256": _h.sha256(data).hexdigest()}: return {"status": "BLOCKED", "code": "DATA_NOT_BOUND_TO_PERMIT"}      # bytes written must be exactly what the permit's args committed to
        if not self.ledger.request(effect_id, {"target": ce.target_raw}): return {"status": "DUPLICATE"}      # a repeated effect_id never re-verifies, re-authorizes or re-writes
        try: claim = commit_verify(self.v, token, ce)
        except ProofError as e:
            if self.ledger.state(effect_id) == "REQUESTED": self.ledger.block(effect_id, {"code": e.code})
            return {"status": "BLOCKED", "code": e.code}
        if not self.ledger.authorize(effect_id, claim["nonce"]): self.ledger.block(effect_id, {"code": "NONCE_REUSE"}); return {"status": "BLOCKED", "code": "NONCE_REUSE"}
        if not self.ledger.begin(effect_id): return {"status": "DUPLICATE"}
        try:
            if fault: fault()
            rec = self.sink.write(ce.target_raw, data, effect_id)
        except SinkError as e: self.ledger.finish(effect_id, "BLOCKED", {"code": e.code}); return {"status": "BLOCKED", "code": e.code}
        except BaseException as e: self.ledger.finish(effect_id, "UNKNOWN", {"error": type(e).__name__}); return {"status": "UNKNOWN", "code": "UPSTREAM_FAILED"}
        self.ledger.finish(effect_id, "COMMITTED", {"sha256": rec["sha256"]}); return {"status": "ALLOW_COMMITTED", "sink_receipt": rec}

    def reconcile(self, effect_id: str) -> str:
        """Resolve UNKNOWN only from the sink's own journal."""
        obs = self.sink.observed(effect_id); self.ledger.reconcile(effect_id, bool(obs and obs["present_now"]), {"sink_observed": bool(obs)}); return self.ledger.state(effect_id)
