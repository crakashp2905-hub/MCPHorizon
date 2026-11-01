"""Tamper-resistant telemetry (P35). Separates three evidence sources and never lets one vouch for another:
  (1) the AGENT TRANSCRIPT (agent-controlled: untrusted, may be fabricated/rewritten),
  (2) the TRUSTED EVENT LOG (written only by the collector from events emitted by trusted components; hash-chained, batch-signed with a key the agent never holds),
  (3) the RECEIVER EFFECT JOURNAL (independent oracle at the sink).
Reconciliation reports mismatches; absence of a record is reported as UNCERTAIN, never as proof that nothing happened."""
from __future__ import annotations
import hashlib, json, os, socket, struct, subprocess, sys, threading, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from horizon.authz.keys import Signer
from horizon.runtime import schema as SC

def canon(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str).encode()
def sha(b) -> str: return hashlib.sha256(b if isinstance(b, bytes) else canon(b)).hexdigest()
def op_digest(tool: str, args: dict) -> str: return sha({"tool": tool, "args": args})
GENESIS = "0" * 64

# ------------------------------------------------------------------ append-only integrity chain + signed batches (P35-03, P35-04)
class Chain:
    """Records: {seq, prev, event, hash}. Batch seals: {first, last, head, sig}. The Signer stays inside the collector."""
    def __init__(self, signer: Signer, *, batch_size=8, clock_ns=time.monotonic_ns, wall=time.time):
        self._s, self.batch, self.clock_ns, self.wall = signer, batch_size, clock_ns, wall; self.records, self.seals, self._last_sealed = [], [], -1
    @property
    def public_raw(self) -> bytes: return self._s.public_raw()
    def append(self, event: dict) -> dict:
        txt, hits = SC.redact(json.dumps(event, default=str))          # P35-08: redact BEFORE persistence
        ev = json.loads(txt)
        if hits: ev["redaction_audit"] = sorted(set(hits))
        ev.update({"source": "trusted_collector", "mono_ns": self.clock_ns(), "wall": self.wall()})
        prev = self.records[-1]["hash"] if self.records else GENESIS; seq = len(self.records)
        rec = {"seq": seq, "prev": prev, "event": ev}; rec["hash"] = sha({"seq": seq, "prev": prev, "event": ev}); self.records.append(rec)
        if seq - self._last_sealed >= self.batch: self.seal()
        return rec
    def seal(self):
        if not self.records or self._last_sealed == len(self.records) - 1: return None
        b = {"kind": "seal", "first": self._last_sealed + 1, "last": len(self.records) - 1, "head": self.records[-1]["hash"], "kid": self._s.kid}; s = {**b, "sig": self._s.sign(canon(b)).hex()}; self.seals.append(s); self._last_sealed = b["last"]; return s
    def export(self) -> dict: self.seal(); return {"records": list(self.records), "seals": list(self.seals)}

def verify_chain(log: dict, pub_raw: bytes) -> dict:
    """Detects: edited record, deleted record, reordered records, truncated tail past a seal, forged/unsigned seals. Returns problems; a clean result does NOT show the log is complete beyond the last seal."""
    pr, recs, pub = [], log["records"], Ed25519PublicKey.from_public_bytes(pub_raw); prev = GENESIS
    for i, r in enumerate(recs):
        if r.get("seq") != i: pr.append(f"SEQ_GAP_OR_REORDER@{i}")
        if r.get("prev") != prev: pr.append(f"CHAIN_BREAK@{i}")
        if r.get("hash") != sha({"seq": r.get("seq"), "prev": r.get("prev"), "event": r.get("event")}): pr.append(f"RECORD_MODIFIED@{i}")
        prev = r.get("hash")
    covered = -1
    for s in log["seals"]:
        b = {k: s[k] for k in ("kind", "first", "last", "head", "kid")}
        try: pub.verify(bytes.fromhex(s["sig"]), canon(b))
        except Exception: pr.append(f"SEAL_FORGED@{s.get('last')}"); continue
        if s["last"] >= len(recs): pr.append(f"TRUNCATED_BELOW_SEAL@{s['last']}")
        elif recs[s["last"]]["hash"] != s["head"]: pr.append(f"SEAL_HEAD_MISMATCH@{s['last']}")
        covered = max(covered, s["last"])
    return {"ok": not pr, "problems": pr, "records": len(recs), "sealed_through": covered, "unsealed_tail": len(recs) - 1 - covered}

def link_segment(old_log: dict, new_chain: "Chain") -> dict:
    """Normal log rotation (P35-13): the new segment's first record cites the sealed head of the previous one, so rotation is visible and does not look like truncation."""
    old_log = old_log if "seals" in old_log else old_log; last = old_log["records"][-1]
    return new_chain.append({"kind": "segment_link", "prev_segment_head": last["hash"], "prev_segment_last_seq": last["seq"], "prev_segment_seals": len(old_log["seals"])})
def verify_rotation(old_log: dict, new_log: dict) -> bool:
    e = new_log["records"][0]["event"]; return e.get("kind") == "segment_link" and e["prev_segment_head"] == old_log["records"][-1]["hash"]

# ------------------------------------------------------------------ trusted event constructor
def make_event(*, principal, tool, args, decision, policy_hash, execution_id, run_id, status) -> dict:
    return {"kind": "protected_operation", "principal": principal, "op_digest": op_digest(tool, args), "tool": tool, "policy_hash": policy_hash, "decision": decision, "execution_id": execution_id, "run_id": run_id, "status": status}

# ------------------------------------------------------------------ independent receiver journal + signed no-effect assertion (P35-02, P35-11)
class ReceiverJournal:
    """The sink's own record of what actually arrived. Signed with its OWN key, separate from the collector's."""
    def __init__(self, sink: str, signer: Signer | None = None): self.sink, self.entries, self._s = sink, [], signer or Signer.generate("receiver", sink)
    def record(self, execution_id: str, body: bytes): self.entries.append({"i": len(self.entries), "execution_id": execution_id, "body_sha256": sha(body), "t": time.time()})
    def head(self) -> str: return sha(self.entries)
    def assert_no_effect(self, execution_ids, *, since_index=0) -> dict:
        """Signed statement: in journal range [since_index, now) no entry carries any of `execution_ids`. Bound to the journal head so later rewriting of the journal invalidates it."""
        hit = [e for e in self.entries[since_index:] if e["execution_id"] in set(execution_ids)]
        b = {"kind": "no-effect-assertion", "sink": self.sink, "execution_ids": sorted(execution_ids), "range": [since_index, len(self.entries)], "effects_found": len(hit), "journal_head": self.head()}
        return {**b, "sig": self._s.sign(canon(b)).hex(), "kid": self._s.kid}
    @property
    def public_raw(self): return self._s.public_raw()
def verify_assertion(a: dict, pub_raw: bytes, journal: ReceiverJournal | None = None) -> bool:
    b = {k: v for k, v in a.items() if k not in ("sig", "kid")}
    try: Ed25519PublicKey.from_public_bytes(pub_raw).verify(bytes.fromhex(a["sig"]), canon(b))
    except Exception: return False
    return True if journal is None else a["journal_head"] == journal.head() or a["journal_head"] == sha(journal.entries[:a["range"][1]])

# ------------------------------------------------------------------ reconciliation: transcript vs trusted vs receiver (P35-05, P35-06, P35-07)
def reconcile(transcript: list, log: dict, journal: ReceiverJournal, pub_raw: bytes, signer: Signer | None = None) -> dict:
    """transcript: [{execution_id, tool, args}] as CLAIMED by the model/agent. Findings are evidence-typed; nothing is inferred from the transcript alone."""
    f = []; chain = verify_chain(log, pub_raw); ev = [r["event"] for r in log["records"] if r["event"].get("kind") == "protected_operation"]
    if not chain["ok"]: f += [{"code": "LOG_INTEGRITY", "detail": p} for p in chain["problems"]]
    by_exec = {}
    for e in ev: by_exec.setdefault(e["execution_id"], []).append(e)
    for x, es in by_exec.items():
        if len({e["op_digest"] for e in es}) > 1: f.append({"code": "CONFLICTING_EXECUTION_ID", "execution_id": x})
    tx = {}
    for t in transcript: tx.setdefault(t["execution_id"], []).append(t)
    for x, ts in tx.items():
        if len(ts) > 1 and len({op_digest(t["tool"], t["args"]) for t in ts}) > 1: f.append({"code": "TRANSCRIPT_REUSES_EXECUTION_ID", "execution_id": x})
        if x not in by_exec: f.append({"code": "TRANSCRIPT_CLAIM_WITHOUT_TRUSTED_EVENT", "execution_id": x, "tool": ts[0]["tool"]})            # fabricated / never reached the protected path
        elif op_digest(ts[0]["tool"], ts[0]["args"]) != by_exec[x][0]["op_digest"]: f.append({"code": "TRANSCRIPT_OPERATION_DIFFERS_FROM_TRUSTED", "execution_id": x})
    for x, es in by_exec.items():
        if x not in tx: f.append({"code": "TRUSTED_EVENT_ABSENT_FROM_TRANSCRIPT", "execution_id": x, "tool": es[0]["tool"]})              # agent hid an operation
    eff = {}
    for e in journal.entries: eff.setdefault(e["execution_id"], []).append(e)
    for x, es in by_exec.items():
        d = es[-1]["decision"]; seen = x in eff
        if d == "deny" and seen: f.append({"code": "DENIED_BUT_EFFECT_OBSERVED", "execution_id": x})
        elif d == "allow" and not seen: f.append({"code": "ALLOWED_NO_EFFECT_OBSERVED", "execution_id": x, "note": "uncertain: failed, filtered, or journal incomplete"})
    for x in eff:
        if x not in by_exec: f.append({"code": "EFFECT_WITHOUT_TRUSTED_EVENT", "execution_id": x, "note": "uninstrumented path or collector omission"})
    rep = {"kind": "reconciliation-report", "chain": chain, "findings": f, "counts": {"transcript": len(transcript), "trusted": len(ev), "effects": len(journal.entries)}, "clean": not f, "limits": ["a clean report covers only operations that traverse instrumented trusted components", "events after the last seal are unsealed"]}
    if signer: rep["sig"] = signer.sign(canon({k: v for k, v in rep.items() if k != "sig"})).hex(); rep["kid"] = signer.kid
    return rep

# ------------------------------------------------------------------ enforce-mode executor: no collector ack, no effect (P35-10)
class CollectorDown(Exception): pass
class ProtectedExecutor:
    """In enforce mode a protected effect proceeds only after the collector has durably accepted the event. Bounded queue: when the collector is unreachable, ops are denied once `max_pending` is reached, never buffered without limit."""
    def __init__(self, emit, effect, *, mode="enforce", max_pending=4): self.emit, self.effect, self.mode, self.max_pending, self.pending, self.denied, self.executed = emit, effect, mode, max_pending, [], [], []
    def run(self, ev: dict, payload: bytes) -> dict:
        try: self.emit(ev); self._flush()
        except CollectorDown:
            if self.mode == "enforce": self.denied.append(ev["execution_id"]); return {"ok": False, "code": "COLLECTOR_UNAVAILABLE_FAIL_CLOSED"}
            if len(self.pending) >= self.max_pending: self.denied.append(ev["execution_id"]); return {"ok": False, "code": "BACKPRESSURE_LIMIT"}
            self.pending.append(ev); self.effect(ev["execution_id"], payload); self.executed.append(ev["execution_id"]); return {"ok": True, "degraded": True, "pending": len(self.pending)}
        self.effect(ev["execution_id"], payload); self.executed.append(ev["execution_id"]); return {"ok": True}
    def _flush(self):
        while self.pending: self.emit(self.pending[0]); self.pending.pop(0)

# ------------------------------------------------------------------ out-of-process collector (P35-02)
SERVER = r'''
import json, os, socket, struct, sys, time
sys.path.insert(0, sys.argv[1])
from horizon.telemetry.collector import Chain
from horizon.authz.keys import Signer
sock_path, log_path = sys.argv[2], sys.argv[3]
sg = Signer.generate("collector", "trusted"); ch = Chain(sg, batch_size=4)
os.umask(0o077)
if os.path.exists(sock_path): os.unlink(sock_path)
srv = socket.socket(socket.AF_UNIX); srv.bind(sock_path); os.chmod(sock_path, 0o600); srv.listen(16)
print(sg.public_raw().hex(), flush=True)
def recv(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d: raise EOFError
        b += d
    return b
while True:
    c, _ = srv.accept()
    try:
        while True:
            n = struct.unpack(">I", recv(c, 4))[0]; msg = json.loads(recv(c, n))
            if msg.get("cmd") == "export": out = ch.export()
            elif msg.get("cmd") == "stop": c.sendall(struct.pack(">I", 2) + b"{}"); sys.exit(0)
            else: rec = ch.append(msg["event"]); out = {"ok": True, "seq": rec["seq"]}
            b = json.dumps(out).encode(); c.sendall(struct.pack(">I", len(b)) + b)
    except (EOFError, OSError): pass
    finally: c.close()
'''
class CollectorClient:
    def __init__(self, path): self.path, self.s = path, None
    def _conn(self):
        if self.s is None:
            try: s = socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect(self.path); self.s = s
            except OSError as e: raise CollectorDown(str(e))
        return self.s
    def _rpc(self, msg):
        try:
            s = self._conn(); b = json.dumps(msg).encode(); s.sendall(struct.pack(">I", len(b)) + b); n = struct.unpack(">I", self._recv(s, 4))[0]; return json.loads(self._recv(s, n))
        except (OSError, EOFError, struct.error) as e: self.s = None; raise CollectorDown(str(e))
    @staticmethod
    def _recv(s, n):
        b = b""
        while len(b) < n:
            d = s.recv(n - len(b))
            if not d: raise EOFError
            b += d
        return b
    def emit(self, ev): return self._rpc({"event": ev})
    def export(self): return self._rpc({"cmd": "export"})
    def close(self):
        if self.s: self.s.close(); self.s = None
class CollectorProcess:
    """Runs the collector as a separate OS process (own memory; the signing key never exists in the caller's process)."""
    def __init__(self, workdir): self.dir, self.proc, self.pub = workdir, None, None; self.sock = os.path.join(workdir, "collector.sock")
    def start(self):
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.proc = subprocess.Popen([sys.executable, "-c", SERVER, root, self.sock, os.path.join(self.dir, "log")], stdout=subprocess.PIPE, text=True); self.pub = bytes.fromhex(self.proc.stdout.readline().strip())
        for _ in range(100):
            if os.path.exists(self.sock): break
            time.sleep(0.02)
        return self
    def client(self): return CollectorClient(self.sock)
    def kill(self):
        if self.proc: self.proc.kill(); self.proc.wait()
    def __enter__(self): return self.start()
    def __exit__(self, *a): self.kill()

# ------------------------------------------------------------------ incident timeline from multiple authenticated sources (P35-14)
def timeline(sources: dict) -> list:
    """sources: {name: {"authenticated": bool, "events": [{t, ...}]}}. Merges by time; every entry keeps its source and whether that source was authenticated, and clock uncertainty is carried, not hidden."""
    out = []
    for name, s in sources.items():
        for e in s["events"]: out.append({**e, "source": name, "authenticated": bool(s["authenticated"]), "clock_uncertainty_s": s.get("clock_uncertainty_s")})
    return sorted(out, key=lambda e: (e["t"], e["source"]))
