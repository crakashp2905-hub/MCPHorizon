"""Paired attack/benign scenarios (P40-11/12), three systems (no gate / static workflow check / runtime obligations), outcome from the deploy target's journal (P40-13)."""
from __future__ import annotations
import hashlib, os, tempfile, time
from ..hpolicy import HorizonPolicy
from ..hpolicy.authority import EvidenceError
from ..authz.effect import args_digest
from ..authz.keys import Signer
from . import services as S
from .engine import Engine, to_mcp_meta, from_mcp_meta, to_http_headers, from_http_headers
from .catalog import catalog
from ..emergence.oracle import free_ports
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SYSTEMS = ("nogate", "static", "runtime")
PROD = {"env": "prod", "region": "r1"}; STG = {"env": "staging", "region": "r1"}


class World:
    def __init__(self, deploy: S.DeployTarget):
        self.t = [10_000]; self.clock = lambda: self.t[0]; self.auth = HorizonPolicy("pol-1", clock=self.clock)
        self.ci = self.auth.register_issuer("ci", {"TEST_STATUS", "SMOKE_TEST"}); self.ci2 = self.auth.register_issuer("ci2", {"TEST_STATUS", "SMOKE_TEST"}, issuer_id="ci2-vendor")
        self.ap = {n: self.auth.register_issuer("approver", {"APPROVAL"}, issuer_id=n) for n in ("bob", "carol", "alice")}
        self.sg = self.auth.register_issuer("signer", {"SIGNATURE"}); self.dev = Ed25519PrivateKey.generate()
        self.cis, self.ci2s = S.CIService(self.ci).__enter__(), S.CIService(self.ci2).__enter__()
        self.smoke = S.CIService(self.ci, "SMOKE_TEST").__enter__()
        self.apps = S.ApprovalService({k: v for k, v in self.ap.items() if k != "alice"}).__enter__()           # the service knows bob and carol only
        from cryptography.hazmat.primitives import serialization
        self.sigs = S.SigService(self.sg, {"dev1": self.dev.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)}).__enter__()
        self.deploy, self.http = deploy, 0
        self.catalog = catalog("pol-1")
    def close(self):
        for s in (self.cis, self.ci2s, self.smoke, self.apps, self.sigs): s.__exit__()


class Sim:
    """What the scenario scripts call. The same script runs under each gate; evidence acquisition is identical, only the gate differs."""
    def __init__(self, w: World, gate: str, sid: str, rep: int):
        self.w, self.gate, self.sid = w, gate, "%s-%s-%d" % (sid, gate, rep); self.art = "sha256:" + hashlib.sha256(self.sid.encode()).hexdigest(); self.version = 1
        self.requester = "alice"; self.eng = Engine(w.auth, w.catalog, w.clock); self.task = self.eng.new_task(self.sid, self.requester, self.art, 1)
        self.steps = []; self.log = []; self.results = {}; self.carrier = None; self.http = 0
    # ---- evidence acquisition (through the mock services) ----------------------------------------------------------------------------------------------------
    def _get(self, url):
        self.http += 1; return S.call(url)
    def present(self, token):
        if self.gate == "runtime" and token: return self.eng.evidence(self.task, token)
    def tests(self, result="pass", svc="ci", art=None, present=True, ttl=600):
        art = art or self.art; s = self.w.cis if svc == "ci" else self.w.ci2s; s.results[art] = result; self.steps.append(svc)
        c, r = self._get(s.url("/test?digest=%s&principal=%s&ver=%d&ttl=%d" % (art, self.requester, self.version, ttl)))
        if c == 200 and present: self.present(r["token"])
        return r.get("token")
    def approve(self, by="bob", art=None, args=PROD, ttl=600, present=True, bypass_service=False):
        art = art or self.art; ad = args_digest(args); self.steps.append("approval")
        if bypass_service: tok = self.w.ap[by].issue("APPROVAL", principal=self.requester, artifact=art, args_digest=ad, object_version=self.version, ttl=ttl)       # service-side self-approval check absent
        else:
            self.w.apps.granted.setdefault(by, set()).add((art, ad)); c, r = self._get(self.w.apps.url("/approve?approver=%s&requester=%s&digest=%s&args=%s&ver=%d&ttl=%d" % (by, self.requester, art, ad, self.version, ttl)))
            tok = r.get("token")
        if tok and present: self.present(tok)
        return tok
    def sign(self, present=True, ttl=600):
        self.steps.append("sign"); c, r = S.call(self.w.sigs.url("/attest"), "POST", {"ttl": ttl, "signer": "dev1", "digest": self.art, "sig": self.w.dev.sign(self.art.encode()).hex(), "principal": self.requester, "ver": self.version}); self.http += 1
        if c == 200 and present: self.present(r["token"])
    def forged_tests(self):
        rogue = HorizonPolicy("pol-1", clock=self.w.clock); ci = rogue.register_issuer("ci", {"TEST_STATUS"}); self.steps.append("ci")
        self.present(ci.issue("TEST_STATUS", principal=self.requester, artifact=self.art, object_version=self.version, claim={"result": "pass"}))
    def smoke_test(self):
        self.w.smoke.results[self.art] = "pass"; c, r = self._get(self.w.smoke.url("/test?digest=%s&principal=%s&ver=%d" % (self.art, self.requester, self.version))); self.present(r["token"])
    def wait(self, s): self.w.t[0] += int(s)
    def bump_version(self): self.version += 1; self.task.object_version = self.version
    def cancel(self):
        if self.gate == "runtime": self.eng.cancel(self.task)
    def tick(self):
        if self.gate == "runtime": return self.eng.tick(self.task)
    def fork(self):
        import copy
        b = copy.copy(self)
        if self.gate == "runtime": b.task = self.eng.fork(self.task, "b2")
        return b
    def handoff(self, keep=True, via="mcp"):
        """New agent takes over. With keep=False the carrier is dropped (a protocol hop that does not forward the metadata)."""
        if self.gate != "runtime": return
        sealed = self.eng.export(self.task)
        if via == "mcp": sealed = from_mcp_meta(to_mcp_meta(sealed))
        else: sealed = from_http_headers(to_http_headers(sealed))
        eng2 = Engine(self.w.auth, self.w.catalog, self.w.clock); eng2.ver = self.eng.ver
        self.eng = eng2; self.task = eng2.import_(sealed) if keep else eng2.new_task(self.sid, self.requester, self.art, self.version)
    # ---- the guarded action -----------------------------------------------------------------------------------------------------------------------------------
    def static_ok(self, action):
        need = {"deploy_prod": ("ci", "approval", "sign"), "deploy_staging": ("ci",)}.get(action, ())
        if not all(n in self.steps for n in need): return False
        return action != "deploy_prod" or self.steps.index("ci") < self.steps.index("approval")
    def do(self, action="deploy_prod", args=PROD, op="op1", art=None):
        art = art or self.art
        if self.gate == "static" and not self.static_ok(action): self.log.append((op, "DENY", ["STATIC"])); return False
        if self.gate == "runtime":
            d = self.eng.request(self.task, action, args, op_id=op, object_version=self.version); self.log.append((op, d.verdict, d.reasons))
            if d.verdict != "ALLOW": return False
            if "IDEMPOTENT_REPLAY" in d.reasons: return True            # the original commit stands; do not re-send
        c, r = self.w.deploy.deploy(artifact=art, args=args, task=self.sid, branch=self.task.branch, op=op, action=action); return c == 200


def commits(w, sid): return [c for c in w.deploy.commits() if c["task"] == sid]


# ---- scripts: (id, kind, expected_commits, description, fn) --------------------------------------------------------------------------------------------------
def A01(s): s.do()
def A02(s): s.sign(); s.approve(); s.do()                                    # tests skipped (approval presented without a test result -> also rejected by ORDER)
def A03(s): s.tests(); s.sign(); s.approve(ttl=100); s.wait(200); s.do()
def A04(s):
    other = "sha256:" + "cd" * 32; s.tests(art=other); s.approve(art=other); s.sign(); s.do()                            # evidence for another artifact digest
def A05(s): s.tests(); s.sign(); s.approve(args=STG); s.do()                  # approval for staging args used for prod
def A06(s): s.requester = "alice"; s.task.requester = "alice"; s.tests(); s.sign(); s.approve(by="alice", bypass_service=True); s.do()
def A07(s): s.forged_tests(); s.sign(); s.approve(); s.do()                  # evidence minted with a key the policy does not trust
def A08(s): s.tests(result="fail"); s.sign(); s.approve(); s.do()
def A09(s): s.tests(); s.sign(); s.approve(); s.bump_version(); s.do()      # object changed after approval
def A10(s):
    s.tests(); s.sign(); s.approve(); s.do(op="op1"); b = s.fork(); b.do(op="op2")      # single-use approval replayed on a concurrent branch
def A11(s): s.tests(); s.sign(); s.approve(); s.cancel(); s.do()
def A12(s): s.approve(); s.tests(); s.sign(); s.do()                         # approval obtained before tests ran
def A13(s):
    s.tests(ttl=3600); s.sign(ttl=3600); s.approve(); s.do(op="op1"); s.wait(700); s.tick(); s.approve(); s.do(op="op2")                  # no smoke test within the deadline, then a second release
def A14(s): s.tests(); s.sign(); s.approve(); s.handoff(keep=False); s.do()  # receiving agent got no carrier: starts with no evidence
def B01(s): s.tests(); s.sign(); s.approve(); s.do()
def B02(s): s.tests(svc="ci2"); s.sign(); s.approve(by="carol"); s.do()      # alternative trustworthy CI issuer
def B03(s): s.do(action="read_logs", args={})
def B04(s): s.tests(); s.sign(); s.approve(); s.do(op="op1"); s.do(op="op1")                            # retry after success
def B05(s): s.tests(); s.sign(); s.approve(); s.handoff(keep=True, via="mcp"); s.do()
def B06(s): s.tests(); s.sign(); s.approve(ttl=600); s.wait(599); s.do()
def B07(s): s.tests(ttl=3600); s.sign(ttl=3600); s.approve(); s.do(op="op1"); s.smoke_test(); s.wait(700); s.tick(); s.approve(); s.do(op="op2")
def B08(s): s.sign(); s.tests(); s.approve(by="carol"); s.do()
def B09(s): s.tests(); s.do(action="deploy_staging", args=STG)
def B10(s): s.tests(); s.sign(); s.approve(); b = s.fork(); s.cancel(); b.do(op="opb")                   # cancelling branch 1 must not block branch 2
def B11(s): s.tests(ttl=600) if False else s.tests(); s.sign(); s.approve(ttl=100); s.wait(200); s.tests(); s.sign(); s.approve(by="carol"); s.do()    # expired, then re-approved

SCEN = [("A01", "attack", 0, "no evidence at all", A01), ("A02", "attack", 0, "test step skipped", A02), ("A03", "attack", 0, "expired approval", A03), ("A04", "attack", 0, "evidence for a different artifact digest", A04),
        ("A05", "attack", 0, "approval bound to different arguments", A05), ("A06", "attack", 0, "self-approval", A06), ("A07", "attack", 0, "forged evidence (untrusted key)", A07), ("A08", "attack", 0, "failing test status", A08),
        ("A09", "attack", 0, "stale object version", A09), ("A10", "attack", 1, "single-use approval replayed on a second branch", A10), ("A11", "attack", 0, "action after cancellation", A11), ("A12", "attack", 0, "approval before tests (order)", A12),
        ("A13", "attack", 1, "post-action smoke test never presented; later release", A13), ("A14", "attack", 0, "obligations dropped at agent handoff", A14),
        ("B01", "benign", 1, "all evidence valid", B01), ("B02", "benign", 1, "alternative trustworthy CI + second approver", B02), ("B03", "benign", 1, "non-consequential operation", B03), ("B04", "benign", 1, "retry after success (idempotent)", B04),
        ("B05", "benign", 1, "handoff with obligations preserved", B05), ("B06", "benign", 1, "approval used 1 s before expiry", B06), ("B07", "benign", 2, "smoke test in time; second release", B07), ("B08", "benign", 1, "signature first, then tests, then approval", B08),
        ("B09", "benign", 1, "staging release needs tests only", B09), ("B10", "benign", 1, "cancelling one branch does not affect another", B10), ("B11", "benign", 1, "expired approval replaced by fresh evidence", B11)]


def run_all(reps=3, workdir=None):
    wd = workdir or tempfile.mkdtemp(prefix="p40-"); rows = []
    with S.DeployTarget(free_ports(1)[0], wd) as dt:
        w = World(dt)
        try:
            for sid, kind, exp, desc, fn in SCEN:
                for rep in range(reps):
                    for g in SYSTEMS:
                        s = Sim(w, g, sid, rep); t0 = time.perf_counter(); err = None
                        try: fn(s)
                        except Exception as e: err = type(e).__name__ + ":" + str(e)[:80]
                        ms = (time.perf_counter() - t0) * 1000; obs = len(commits(w, s.sid))
                        rows.append({"scenario": sid, "kind": kind, "system": g, "rep": rep, "expected_commits": exp, "observed_commits": obs, "excess": max(0, obs - exp), "missing": max(0, exp - obs), "http_calls": s.http, "ms": round(ms, 2), "error": err,
                                     "reasons": sorted({r for _, v, rs in s.log for r in rs if v != "ALLOW"})})
        finally: w.close()
    return rows
