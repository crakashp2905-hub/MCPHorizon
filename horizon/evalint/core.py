"""Evidence primitives (P49-04, 13): signed, hash-chained, sequence-numbered collector streams with end-of-stream seals, a signed run manifest, and stream/manifest verification.
Collectors sign with the shared HorizonPolicy authority (ATTESTATION). The evaluator holds only the public Verifier. A hash chain detects modification relative to trusted roots; it does not make the captured observations correct."""
import hashlib, json
from dataclasses import dataclass, replace, fields as dfields
from ..hpolicy.authority import EvidenceError

CANARY = "TEST_CANARY_NOT_SECRET"; BASE = 1_000_000; REQUIRED = ("tool", "sink", "os")
def canonical(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def digest(o) -> str: return "sha256:" + hashlib.sha256(canonical(o)).hexdigest()


class Clock:
    def __init__(self): self.t = float(BASE)
    def advance(self, s): self.t += s
    def now(self): return int(self.t)


@dataclass(frozen=True)
class ECfg:
    manifest: bool = True; signatures: bool = True; chain: bool = True; seal: bool = True; run_binding: bool = True; time: bool = True
    receiver_oracle: bool = True; tool_stream: bool = True; os_stream: bool = True; reconcile: bool = True; identity: bool = True; transcript_check: bool = True


class Collector:
    """One independent evidence source. `emit` signs core fields (run, src, seq, kind, body, ts, prev) and appends to the stream store."""
    def __init__(self, issuer, name, run_id, clock, out): self.i, self.name, self.run, self.clock, self.out = issuer, name, run_id, clock, out; self.n = 0; self.prev = "genesis"
    def emit(self, kind, body):
        core = {"run": self.run, "src": self.name, "seq": self.n, "kind": kind, "body": body, "ts": self.clock.now(), "prev": self.prev}
        sig = self.i.issue("ATTESTATION", principal=self.name, artifact=self.run, args_digest=digest(core), object_version=self.n, ttl=86400 * 30, claim={"src": self.name, "seq": self.n}, now=self.clock.now())
        rec = {**core, "sig": sig}; self.out.append(rec); self.prev = digest(core); self.n += 1; return rec
    def seal(self): return self.emit("SEAL", {"count": self.n, "head": self.prev})


def _core(r): return {k: r[k] for k in ("run", "src", "seq", "kind", "body", "ts", "prev")}


def verify_stream(arrivals, name, run, verifier, now, cfg, start, end, grace):
    """arrivals: [(arrival_ts, record)]. -> {'trusted': bool, 'flags': [...], 'records': [non-seal records in seq order]}. Duplicates identical -> kept once; conflicting -> untrusted; reordered delivery repaired by seq."""
    flags = []; bad = False
    if not arrivals: return {"trusted": False, "flags": ["ABSENT"], "records": []}
    by = {}
    for a, r in arrivals: by.setdefault(r.get("seq"), []).append((a, r))
    recs = []
    for seq in sorted(k for k in by if isinstance(k, int)):
        cands = by[seq]
        if len({digest(r) for _, r in cands}) > 1: flags.append("DUP_CONFLICT"); bad = True
        elif len(cands) > 1: flags.append("DUPLICATE")
        recs.append((min(a for a, _ in cands), cands[0][1]))
    if [r["seq"] for _, r in arrivals if isinstance(r.get("seq"), int)] != sorted(r["seq"] for _, r in arrivals if isinstance(r.get("seq"), int)): flags.append("REORDERED")
    prev = "genesis"; last_ts = start
    for i, (arr, r) in enumerate(recs):
        c = _core(r) if all(k in r for k in ("run", "src", "seq", "kind", "body", "ts", "prev")) else None
        if c is None or "sig" not in r: flags.append("MALFORMED"); bad = True; continue
        if r["seq"] != i: flags.append("SEQ_GAP"); bad = True
        if cfg.run_binding and (r["run"] != run or r["src"] != name): flags.append("RUN_MISMATCH"); bad = True
        if cfg.signatures:
            try:
                p = verifier.verify(r["sig"], now=now)
                if p["principal"] != name or p["role"] != name or p["args_digest"] != digest(c): flags.append("BAD_SIGNATURE"); bad = True
            except EvidenceError: flags.append("BAD_SIGNATURE"); bad = True
        if cfg.chain and r["prev"] != prev: flags.append("CHAIN_BREAK"); bad = True
        prev = digest(c)
        if cfg.time:
            if r["ts"] < last_ts or r["ts"] > end + grace: flags.append("TIME_ORDER"); bad = True
            if arr > end + grace: flags.append("LATE"); bad = True
            last_ts = max(last_ts, r["ts"])
    body = [r for _, r in recs if r.get("kind") != "SEAL"]
    if cfg.seal:
        s = recs[-1][1] if recs else None
        if not s or s.get("kind") != "SEAL" or s["body"].get("count") != len(recs) - 1 or (len(recs) > 1 and s["body"].get("head") != digest(_core(recs[-2][1]))) or (len(recs) == 1 and s["body"].get("head") != "genesis"): flags.append("MISSING_SEAL"); bad = True
    return {"trusted": not bad, "flags": sorted(set(flags)), "records": body}


MANIFEST_FIELDS = ("run", "image", "policy", "model", "tools", "seeds", "allowed_dests", "allowed_channels", "uids", "start", "grace")


def verify_manifest(m, run, verifier, now, cfg):
    """-> (ok, flags, body). Signed by the evaluator; records exact runner image, policy, model, tools, seeds; roles must run under distinct uids (P49-06)."""
    fl = []
    try:
        b, sig = m["body"], m["sig"]
        if any(k not in b for k in MANIFEST_FIELDS): return False, ["MANIFEST_INCOMPLETE"], b
        if cfg.manifest:
            p = verifier.verify(sig, now=now)
            if p["principal"] != "evaluator" or p["args_digest"] != digest(b) or (cfg.run_binding and (p["artifact"] != run or b["run"] != run)): return False, ["MANIFEST_INVALID"], b
        if cfg.identity and len(set(b["uids"].values())) != len(b["uids"]): return False, ["IDENTITY_SEPARATION"], b
    except (EvidenceError, KeyError, TypeError): return False, ["MANIFEST_INVALID"], (m or {}).get("body", {}) if isinstance(m, dict) else {}
    return True, fl, b
