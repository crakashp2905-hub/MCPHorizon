"""ENG-PR05 (E05, HARD-D subset): ONE protected effect path — file write — with a SINK-SIDE journal owned by the sink, not by the gateway or the agent.
FileSink is the only code that touches the filesystem; ProtectedFileWriter is the only way to reach it: commit-time permit verification -> ledger authorize/begin (at-most-once) -> sink write -> ledger outcome.
Outcome truth comes from the sink journal (sha256 of what actually landed), so a gateway claim of COMMITTED can be checked against it. Localhost/tempdir only. CANDIDATE: in-process, trusting the OS user separation is NOT claimed
(an agent running as the same OS user could bypass; real enforcement needs the sandbox/broker boundary — see limits)."""
from __future__ import annotations
import fcntl, hashlib, json, os, time
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

    def _locked(self):
        """Cross-process mutual exclusion for journal + fence (flock on a sibling lock file owned by the sink)."""
        class _L:
            def __enter__(s_): s_.f = open(self.journal + ".lock", "a"); fcntl.flock(s_.f, fcntl.LOCK_EX); return s_
            def __exit__(s_, *a): fcntl.flock(s_.f, fcntl.LOCK_UN); s_.f.close()
        return _L()

    def _records(self):
        if not os.path.exists(self.journal): return []
        return [json.loads(l) for l in open(self.journal) if l.strip()]

    def write(self, path: str, data: bytes, effect_id: str) -> dict:
        real = self._resolve(path); tmp = real + ".tmp." + effect_id[:16]
        with self._locked():
            recs = self._records()
            if any(r.get("fence") == effect_id for r in recs): raise SinkError("FENCED", "effect was fenced by reconciliation; write refused")
            if any(r.get("effect_id") == effect_id and "fence" not in r for r in recs): raise SinkError("ALREADY_WRITTEN", "sink already recorded this effect_id")
            with open(tmp, "wb") as f: f.write(data); f.flush(); os.fsync(f.fileno())
            os.replace(tmp, real)
            rec = {"effect_id": effect_id, "path": real, "sha256": hashlib.sha256(open(real, "rb").read()).hexdigest(), "bytes": len(data), "ts": time.time()}
            with open(self.journal, "a") as j: j.write(json.dumps(rec, sort_keys=True) + "\n"); j.flush(); os.fsync(j.fileno())
        return rec

    def fence_and_observe(self, effect_id: str) -> dict | None:
        """ATOMIC (under the sink lock): record a tombstone so no LATER write for effect_id can land, and return what the sink had recorded up to that instant.
        Reconciling an UNKNOWN effect with a plain read is unsafe against a slow worker that writes afterwards (model: `no_fence_timeout_recovery`)."""
        with self._locked():
            obs = self._observed_unlocked(effect_id)
            if not any(r.get("fence") == effect_id for r in self._records()):
                with open(self.journal, "a") as j: j.write(json.dumps({"fence": effect_id, "ts": time.time()}, sort_keys=True) + "\n"); j.flush(); os.fsync(j.fileno())
            return obs

    def _observed_unlocked(self, effect_id: str) -> dict | None:
        for r in self._records():
            if r.get("effect_id") == effect_id and "fence" not in r:
                r = dict(r); r["present_now"] = os.path.exists(r["path"]) and hashlib.sha256(open(r["path"], "rb").read()).hexdigest() == r["sha256"]; return r
        return None

    def observed(self, effect_id: str) -> dict | None:
        """Independent observation: the sink journal AND the file's current digest; None if the sink never recorded it. Plain read: NOT safe for reconciliation (use fence_and_observe)."""
        with self._locked(): return self._observed_unlocked(effect_id)


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
        except SinkError as e:
            try: self.ledger.finish(effect_id, "BLOCKED", {"code": e.code}); return {"status": "BLOCKED", "code": e.code}
            except LedgerError: return {"status": "UNKNOWN" if e.code != "FENCED" else "BLOCKED", "code": e.code}     # ledger already moved on (recovery/reconcile won the race): do not overwrite it
        except BaseException as e:
            try: self.ledger.finish(effect_id, "UNKNOWN", {"error": type(e).__name__})
            except LedgerError: pass
            return {"status": "UNKNOWN", "code": "UPSTREAM_FAILED"}
        try: self.ledger.finish(effect_id, "COMMITTED", {"sha256": rec["sha256"]})
        except LedgerError: return {"status": "UNKNOWN", "code": "LEDGER_MOVED_ON", "sink_receipt": rec}          # sink effect happened; ledger was already UNKNOWN -> reconcile will find it
        return {"status": "ALLOW_COMMITTED", "sink_receipt": rec}

    def reconcile(self, effect_id: str) -> str:
        """Resolve UNKNOWN only from the sink's own journal."""
        obs = self.sink.fence_and_observe(effect_id); self.ledger.reconcile(effect_id, bool(obs and obs["present_now"]), {"sink_observed": bool(obs), "fenced": True}); return self.ledger.state(effect_id)
