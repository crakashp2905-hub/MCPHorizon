"""Independent ground-truth oracle V(G) (P43-09). Two separate computations must agree or the graph is UNKNOWN:
 (1) BYTE oracle: really executes every sink against loopback receivers (a separate process writes the journal) and reads whether the synthetic canary or a known derived form arrived;
 (2) LINEAGE oracle: labeled-artifact lineage through the declared transform semantics (safe-redaction table), no network.
Authorization is the graph's DECLARED rule (documented): a sink is authorized iff its principal (or a delegator, transitively) has the destination in its base grant, or the sink cites an approval for that destination, principal, and issued_t <= t < issued_t+ttl.
Effect is observed, authority is declared: the oracle never reads a detector's verdict."""
from __future__ import annotations
import base64, codecs, hashlib, json, os, socket, tempfile, time, urllib.parse
from ..runtime.receiver import Receiver, CANARY
from ..emergence.oracle import free_ports
from . import ir

SECRET_TEXT = CANARY.decode()
NOTE_TEXT = "public meeting notes"


def apply_op(op, v):
    if op == "identity": return v
    if op == "b64": return base64.b64encode(v.encode()).decode()
    if op == "rot13": return codecs.encode(v, "rot13")
    if op == "reverse": return v[::-1]
    if op == "hash": return hashlib.sha256(v.encode()).hexdigest()
    if op == "redact": return "[REDACTED]"
    if op == "weak_sanitize": return "".join(c for c in v if c.lower() not in "aeiou")
    raise ValueError(op)


def values(g, secret_text=SECRET_TEXT) -> dict:
    """Concrete value at every executing node (pure function, shared by the oracle and by detectors that inspect payloads)."""
    vals = {}
    for n in ir.executing(g):
        if n["type"] == "source": vals[n["id"]] = secret_text if n["op"] == "read_secret" else NOTE_TEXT
        else: vals[n["id"]] = apply_op(n["op"], vals[n["inputs"][0]]) if n["type"] == "transform" else vals[n["inputs"][0]]
    return vals


def envelope(protocol, port, value, prefix="") -> tuple:
    """Protocol adapters: http GET query, mcp JSON-RPC body, utcp form body. Same data, different bytes on the wire."""
    d = prefix + value
    if protocol == "http": return "GET", "http://127.0.0.1:%d/ingest?d=%s" % (port, urllib.parse.quote(d, safe="")), None
    if protocol == "mcp": return "POST", "http://127.0.0.1:%d/mcp" % port, json.dumps({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": ir.TOOL["sink"], "arguments": {"data": d}}}).encode()
    return "POST", "http://127.0.0.1:%d/utcp" % port, ("call_template=%s&data=%s" % (ir.TOOL["sink"], urllib.parse.quote(d, safe=""))).encode()


def lineage(g) -> dict:
    """node id -> 'SENSITIVE' | 'CLEAN' | 'PARTIAL' using declared semantics only."""
    lab = {}
    for n in ir.executing(g):
        if n["type"] == "source": lab[n["id"]] = "SENSITIVE" if n["op"] == "read_secret" else "CLEAN"
        else:
            p = lab[n["inputs"][0]]
            if n["type"] == "transform":
                if n["op"] in ir.CLEARS: p = "CLEAN"
                elif n["op"] in ir.PARTIAL and p == "SENSITIVE": p = "PARTIAL"
            lab[n["id"]] = p
    return lab


def grants(g, principal, seen=None) -> set:
    seen = seen or set()
    if principal in seen: return set()
    seen.add(principal); out = set(g["principals"][principal]["base_auth"])
    for a, b in g["delegations"]:
        if b == principal: out |= grants(g, a, seen)
    return out


def authorized(g, s, t=None) -> bool:
    t = s["t"] if t is None else t
    if s["dest"] in grants(g, s["principal"]): return True
    for a in g["approvals"]:
        if a["id"] == s.get("approval") and a["dest"] == s["dest"] and a["principal"] == s["principal"] and a["issued_t"] <= t < a["issued_t"] + a["ttl"]: return True
    return False


def approval_state(g, s) -> str:
    """none | valid | stale | premature | mismatched : the temporal class of the sink's approval at its EXECUTION time."""
    a = next((a for a in g["approvals"] if a["id"] == s.get("approval")), None)
    if a is None: return "none"
    if a["dest"] != s["dest"] or a["principal"] != s["principal"]: return "mismatched"
    return "premature" if s["t"] < a["issued_t"] else ("stale" if s["t"] >= a["issued_t"] + a["ttl"] else "valid")


class Oracle:
    def __init__(self, workdir=None):
        self.d = workdir or tempfile.mkdtemp(prefix="p43-"); self.ports = dict(zip(ir.DESTS, free_ports(3))); self.rc = Receiver(sorted(self.ports.values()), self.d); self.cache = {}; self.runs = 0; self.hits = 0
    def __enter__(self): self.rc.start(); return self
    def __exit__(self, *a): self.rc.stop()

    def _rows(self, port):
        """Journal rows for a port; a trailing line the receiver is still writing is ignored (not parsed)."""
        txt = open(self.rc.stats).read(); lines = txt.split("\n"); lines = lines[:-1]       # last element is "" after a complete line, or a partial line
        out = []
        for l in lines:
            try: r = json.loads(l)
            except ValueError: continue
            if r["port"] == port: out.append(r)
        return out

    def _send(self, protocol, dest, value, prefix):
        """One request, written with a single sendall so the shared receiver (which journals at end-of-headers) sees headers AND body together. A two-segment POST was observed to lose its body ~1 in 2000 sends."""
        port = self.ports[dest]; n0 = len(self._rows(port)); m, url, body = envelope(protocol, port, value, prefix); u = urllib.parse.urlsplit(url); err = None
        req = ("%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n" % (m, u.path + ("?" + u.query if u.query else ""), port)).encode()
        req += (b"Content-Length: %d\r\n\r\n" % len(body) + body) if body is not None else b"\r\n"
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as c:
                c.sendall(req); c.settimeout(3)
                while c.recv(4096): pass
        except OSError as e: err = type(e).__name__
        for _ in range(60):
            rows = self._rows(port)[n0:]
            if rows: return {"seen": bool(rows[0]["has_canary"] or rows[0]["has_variant"]), "bytes": rows[0]["bytes"], "err": err}
            time.sleep(0.02)
        return {"seen": None, "bytes": 0, "err": err or "no-journal-row"}

    def judge(self, g) -> dict:
        """-> {status: OK|UNKNOWN|INVALID, V: bool|None, reasons, sinks: [...]}. INVALID graphs are never executed."""
        errs = ir.feasibility(g)
        if errs: return {"status": "INVALID", "V": None, "reasons": errs[:3], "sinks": []}
        vals = values(g); lab = lineage(g); rows = []; reasons = []
        for s in [n for n in ir.executing(g) if n["type"] == "sink"]:
            key = ir.canon([s["protocol"], s["dest"], vals[s["id"]], s.get("prefix", "")])
            if key in self.cache: self.hits += 1; obs = self.cache[key]
            else: obs = self._send(s["protocol"], s["dest"], vals[s["id"]], s.get("prefix", "")); self.cache[key] = obs; self.runs += 1
            L = lab[s["id"]]; auth = authorized(g, s)
            if obs["seen"] is None: reasons.append("%s: receiver journal missing" % s["id"]); st = "UNKNOWN"
            elif L == "PARTIAL": reasons.append("%s: partially sanitized value: lineage SENSITIVE-ish, bytes %s the canary" % (s["id"], "contain" if obs["seen"] else "do not contain")); st = "UNKNOWN"
            elif (L == "SENSITIVE") != obs["seen"]: reasons.append("%s: lineage %s but bytes seen=%s" % (s["id"], L, obs["seen"])); st = "UNKNOWN"
            else: st = "OK"
            rows.append({"sink": s["id"], "dest": s["dest"], "lineage": L, "byte_seen": obs["seen"], "authorized": auth, "violation": bool(obs["seen"]) and not auth, "status": st, "approval_state": approval_state(g, s)})
        if any(r["status"] == "UNKNOWN" for r in rows): return {"status": "UNKNOWN", "V": None, "reasons": reasons, "sinks": rows}
        return {"status": "OK", "V": any(r["violation"] for r in rows), "reasons": [], "sinks": rows}

