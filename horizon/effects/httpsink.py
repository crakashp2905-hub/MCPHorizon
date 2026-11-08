"""A second protected effect path (HTTP POST to ONE configured loopback receiver), so the commit-time deny-only gate is exercised on more than the file sink.
The sink does its own target validation (it does not trust the permit's canonicalisation): scheme http, host exactly 127.0.0.1, the configured port, no userinfo, no redirects followed.
Journal: flock + hash chain (prev, h) like FileSink. Phases: `sent` is written BEFORE the request leaves, `done` after a response arrives. A `sent` with no `done` is genuinely ambiguous (the request
may have landed), so reconcile() leaves it UNKNOWN instead of guessing; only 'fenced before sent' resolves to not-committed. The receiver is assumed to honour `Idempotency-Key`; that is NOT verified here.
CANDIDATE: loopback only, single host, no TLS, no real remote service. The arbitrary-process effect is deliberately NOT implemented (which commands may run is an owner decision)."""
from __future__ import annotations
import fcntl, hashlib, http.client, json, os, time
from urllib.parse import urlsplit
from horizon.authz.gateway import ProofError
from horizon.effects.canonical import CanonicalEffect, commit_verify
from horizon.effects.ledger import EffectLedger, LedgerError


class HttpSinkError(Exception):
    def __init__(self, code, msg=""): super().__init__(f"{code}: {msg}"); self.code = code


class HttpSink:
    def __init__(self, port: int, journal_path: str, *, host: str = "127.0.0.1", timeout: float = 5.0):
        if host != "127.0.0.1": raise ValueError("only the IPv4 loopback address is supported")
        self.host, self.port, self.journal, self.timeout = host, int(port), journal_path, timeout

    def _target(self, url: str) -> str:
        if not isinstance(url, str) or "\x00" in url or "\\" in url or any(c in url for c in "\r\n "): raise HttpSinkError("BAD_URL", "illegal characters")
        s = urlsplit(url)
        if s.scheme != "http" or s.username is not None or s.password is not None or s.hostname != self.host or s.port != self.port or not s.path.startswith("/"): raise HttpSinkError("OUTSIDE_ALLOWED_TARGET", "only the configured loopback receiver is reachable")
        return s.path + ("?" + s.query if s.query else "")

    def _locked(self):
        class _L:
            def __enter__(s_): s_.f = open(self.journal + ".lock", "a"); fcntl.flock(s_.f, fcntl.LOCK_EX); return s_
            def __exit__(s_, *a): fcntl.flock(s_.f, fcntl.LOCK_UN); s_.f.close()
        return _L()

    def _records(self): return [json.loads(l) for l in open(self.journal) if l.strip()] if os.path.exists(self.journal) else []
    @staticmethod
    def _rh(prev, rec): return hashlib.sha256(prev.encode() + json.dumps({k: v for k, v in rec.items() if k not in ("prev", "h")}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _append(self, rec):
        last = self._records()[-1:]; prev = last[0]["h"] if last else "0" * 64; rec = dict(rec, prev=prev); rec["h"] = self._rh(prev, rec)
        with open(self.journal, "a") as f: f.write(json.dumps(rec, sort_keys=True) + "\n"); f.flush(); os.fsync(f.fileno())
        return rec

    def verify_chain(self) -> tuple:
        """-> (ok, n, head). Tail truncation is not detectable without an external anchor."""
        prev, n = "0" * 64, 0
        try: recs = self._records()
        except ValueError: return False, 0, prev
        for r in recs:
            if r.get("prev") != prev or r.get("h") != self._rh(prev, r): return False, n, prev
            prev, n = r["h"], n + 1
        return True, n, prev

    def post(self, url: str, body: bytes, effect_id: str) -> dict:
        path = self._target(url)
        with self._locked():
            recs = self._records()
            if any(r.get("fence") == effect_id for r in recs): raise HttpSinkError("FENCED", "effect was fenced; request refused")
            if any(r.get("effect_id") == effect_id and r.get("phase") for r in recs): raise HttpSinkError("ALREADY_SENT", "sink already recorded this effect_id")
            self._append({"effect_id": effect_id, "phase": "sent", "path": path, "sha256": hashlib.sha256(body).hexdigest(), "ts": time.time()})
        c = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)       # http.client never follows redirects
        try:
            c.request("POST", path, body=body, headers={"Idempotency-Key": effect_id, "Content-Type": "application/octet-stream"}); resp = c.getresponse(); resp.read()
        except ConnectionRefusedError as e:
            with self._locked(): self._append({"effect_id": effect_id, "phase": "refused", "ts": time.time()})
            raise HttpSinkError("CONNECTION_REFUSED", "nothing was sent") from e                  # refused => the request provably did not land
        finally: c.close()
        with self._locked(): return self._append({"effect_id": effect_id, "phase": "done", "status": resp.status, "sha256": hashlib.sha256(body).hexdigest(), "ts": time.time()})

    def fence_and_observe(self, effect_id: str) -> dict:
        """ATOMIC tombstone, then what the journal says: 'none' (never sent), 'refused', 'done' or 'ambiguous' (sent, no response recorded)."""
        with self._locked():
            recs = [r for r in self._records() if r.get("effect_id") == effect_id]
            if not any(r.get("fence") == effect_id for r in self._records()): self._append({"fence": effect_id, "ts": time.time()})
        phases = {r.get("phase") for r in recs}
        done = next((r for r in recs if r.get("phase") == "done"), None)
        return {"http_status": done["status"] if done else None, "state": "done" if "done" in phases else "refused" if "refused" in phases else "ambiguous" if "sent" in phases else "none", "records": recs}


class ProtectedHttpWriter:
    def __init__(self, verifier, ledger: EffectLedger, sink: HttpSink, gate=None):
        """gate: zero-arg callable -> (allowed: bool, reason), evaluated at COMMIT time after the permit verifies and before the nonce is spent. It can only DENY; any exception or non-True verdict blocks."""
        self.v, self.ledger, self.sink, self.gate = verifier, ledger, sink, gate

    def send(self, token, ce: CanonicalEffect, body: bytes, effect_id: str) -> dict:
        if ce.effect != "send" or ce.target_kind != "url": return {"status": "BLOCKED", "code": "UNSUPPORTED_EFFECT"}
        if ce.args != {"sha256": hashlib.sha256(body).hexdigest()}: return {"status": "BLOCKED", "code": "DATA_NOT_BOUND_TO_PERMIT"}
        try: self.sink._target(ce.target_raw)                                    # refuse an out-of-bounds target before a permit is spent on it
        except HttpSinkError as e: return {"status": "BLOCKED", "code": e.code}
        if not self.ledger.request(effect_id, {"target": ce.target_raw}): return {"status": "DUPLICATE"}
        try: claim = commit_verify(self.v, token, ce)
        except ProofError as e:
            if self.ledger.state(effect_id) == "REQUESTED": self.ledger.block(effect_id, {"code": e.code})
            return {"status": "BLOCKED", "code": e.code}
        if self.gate is not None:
            try: g = self.gate(); ok = bool(g[0]) and g[0] is True; why = str(g[1]) if len(g) > 1 else ""
            except Exception: ok, why = False, "GATE_ERROR"
            if not ok:
                if self.ledger.state(effect_id) == "REQUESTED": self.ledger.block(effect_id, {"code": "ASSURANCE_DENIED", "why": why})
                return {"status": "BLOCKED", "code": "ASSURANCE_DENIED", "why": why}
        if not self.ledger.authorize(effect_id, claim["nonce"]): self.ledger.block(effect_id, {"code": "NONCE_REUSE"}); return {"status": "BLOCKED", "code": "NONCE_REUSE"}
        if not self.ledger.begin(effect_id): return {"status": "DUPLICATE"}
        try: rec = self.sink.post(ce.target_raw, body, effect_id)
        except HttpSinkError as e:
            try: self.ledger.finish(effect_id, "BLOCKED", {"code": e.code}); return {"status": "BLOCKED", "code": e.code}
            except LedgerError: return {"status": "UNKNOWN", "code": e.code}
        except BaseException as e:                                               # timeout / reset after the request left: it may have landed
            try: self.ledger.finish(effect_id, "UNKNOWN", {"error": type(e).__name__})
            except LedgerError: pass
            return {"status": "UNKNOWN", "code": "UPSTREAM_FAILED"}
        st = rec["status"]                                                       # 2xx = done; 4xx = the receiver refused; anything else (3xx/5xx) is ambiguous, never reported as committed
        out, code = ("COMMITTED", None) if 200 <= st < 300 else ("BLOCKED", "HTTP_REJECTED") if 400 <= st < 500 else ("UNKNOWN", "HTTP_AMBIGUOUS")
        try: self.ledger.finish(effect_id, out, {"http_status": st})
        except LedgerError: return {"status": "UNKNOWN", "code": "LEDGER_MOVED_ON", "sink_receipt": rec}
        return {"status": "ALLOW_COMMITTED", "sink_receipt": rec} if out == "COMMITTED" else {"status": out, "code": code, "sink_receipt": rec}

    def reconcile(self, effect_id: str) -> str:
        """Resolve UNKNOWN from the sink journal only. 'ambiguous' (request sent, no response) stays UNKNOWN: the sink cannot tell whether the receiver acted."""
        obs = self.sink.fence_and_observe(effect_id)
        if obs["state"] == "ambiguous": return self.ledger.state(effect_id)
        self.ledger.reconcile(effect_id, obs["state"] == "done" and 200 <= obs["http_status"] < 300, {"sink_state": obs["state"], "fenced": True}); return self.ledger.state(effect_id)
