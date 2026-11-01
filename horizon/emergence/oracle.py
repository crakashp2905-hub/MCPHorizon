"""Independent effect oracle (P39-09/12): executes a candidate's steps for real against localhost receivers and judges the outcome ONLY from the receiver's journal (written by a separate process).
Synthetic canary only; loopback only. The model's predictions are never read here."""
from __future__ import annotations
import base64, hashlib, json, os, socket, tempfile, time, urllib.error, urllib.parse, urllib.request
from ..runtime.receiver import Receiver, CANARY
from .summaries import digest


def free_ports(n=3):
    ss = [socket.socket() for _ in range(n)]
    for s in ss: s.bind(("127.0.0.1", 0))
    ps = [s.getsockname()[1] for s in ss]
    for s in ss: s.close()
    return ps


class NoRedirectToUnknownHosts(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).hostname != "127.0.0.1": raise urllib.error.URLError("non-loopback redirect refused")   # never leave the loopback
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(NoRedirectToUnknownHosts)


def run_op(op, args, vals, target_url=None, secret_path=None):
    if op == "read_secret": return open(secret_path, "rb").read().decode()
    if op == "read_note": return "public meeting notes"
    if op == "b64": return base64.b64encode(vals[args[0]].encode()).decode()
    if op == "hash": return hashlib.sha256(vals[args[0]].encode()).hexdigest()
    if op == "redact": return "[REDACTED]"
    if op == "weak_sanitize": return "".join(c for c in vals[args[0]] if c.lower() not in "aeiou")
    raise ValueError(op)


class Oracle:
    def __init__(self, eps, workdir=None):
        self.eps, self.d = eps, workdir or tempfile.mkdtemp(prefix="p39-"); self.secret = os.path.join(self.d, "secret.txt"); open(self.secret, "wb").write(CANARY)
        self.rc = Receiver(sorted(eps.ports.values()), self.d); self.cache = {}; self.runs = 0
    def __enter__(self): self.rc.start(); return self
    def __exit__(self, *a): self.rc.stop()

    def execute(self, steps, targets=None):
        """Run the steps; return {leak, per_port: {port: {conns, canary}}, journal_sha256, rows}. Deterministic runs are memoized by their concrete request (the memoized result came from a real execution)."""
        from .model import Endpoints
        tg = self.eps.targets(); vals = []; reqs = []
        for s in steps:
            if s.op in ("get", "post"):
                v = vals[s.args[0]]; url = tg[s.target](v); reqs.append((s.op, url, v))
            else: vals.append(run_op(s.op, s.args, vals, secret_path=self.secret))
        key = digest([[r[0], r[1]] for r in reqs])
        if key in self.cache: return dict(self.cache[key], cached=True)
        ports = self.eps.ports; before = {p: len(self.rc.rows(p)) for p in ports.values()}; errs = []
        for m, url, v in reqs:
            try:
                req = urllib.request.Request(url, data=(v.encode() if m == "post" else None), method="POST" if m == "post" else "GET")
                OPENER.open(req, timeout=3).read()
            except (urllib.error.URLError, OSError, ValueError) as e: errs.append(type(e).__name__)
        time.sleep(0.12); self.runs += 1
        per = {}
        for role, p in ports.items():
            new = self.rc.rows(p)[before[p]:]; per[role] = {"conns": len(new), "canary": sum(1 for r in new if r["has_canary"] or r["has_variant"])}
        out = {"leak_to_B": per["B"]["canary"] > 0, "per_endpoint": per, "errors": errs, "journal_sha256": hashlib.sha256(open(self.rc.stats, "rb").read()).hexdigest(), "cached": False}
        self.cache[key] = out; return out
