"""World, injector, scenarios, systems and the independent oracle (P46-08..14)."""
import hashlib, os, random, shutil, tempfile, time
from ..authz.keys import Signer
from ..hpolicy.authority import HorizonPolicy
from . import order as O, manifest as MF, engine as EG, gateway as GW, network as NW

STRONG = {"authn": "oauth", "transport": "tls1.3", "audit": "remote_tamper_evident", "scope": ["read"], "region": "eu", "egress": "mediated"}
FD = {"authn": "oauth", "transport": "tls1.3", "audit": "remote_tamper_evident", "scope": frozenset(["read"]), "region": frozenset(["eu"]), "egress": "mediated"}
NONWAIVABLE = frozenset(["authn", "audit"])
def mk(**over): return {**STRONG, **over}
# real behaviour of each endpoint (what the oracle measures) and the profile the operator publishes about it (claims, attested or not)
EPS = {"primary_eu": dict(tls="1.3", authn="oauth", audit=True, region="eu", tee=False, requires_scope=["read"]), "peer_eu": dict(tls="1.3", authn="oauth", audit=True, region="eu", tee=False, requires_scope=["read"]),
       "mock_unaudited": dict(tls="none", authn="oauth", audit=False, region="us", tee=False, requires_scope=["admin"]), "tls12_eu": dict(tls="1.2", authn="oauth", audit=True, region="eu", tee=False, requires_scope=["read"]),
       "noaudit_eu": dict(tls="1.3", authn="oauth", audit=False, region="eu", tee=False, requires_scope=["read"]), "us_peer": dict(tls="1.3", authn="oauth", audit=True, region="us", tee=False, requires_scope=["read"]),
       "tee_eu": dict(tls="1.3", authn="oauth", audit=True, region="eu", tee=True, requires_scope=["read"]), "overask_eu": dict(tls="1.3", authn="oauth", audit=True, region="eu", tee=False, requires_scope=["read"]),
       "legacy_eu": dict(tls="1.2", authn="api_key", audit=True, region="eu", tee=False, requires_scope=[]), "liar": dict(tls="none", authn="none", audit=False, region="us", tee=False, requires_scope=[]),
       "drift_eu": dict(tls="1.2", authn="oauth", audit=True, region="eu", tee=False, requires_scope=["read"]),
       "upgrade_eu": dict(tls="1.3", authn="oauth", audit=True, region="eu", tee=False, requires_scope=["read"])}
PROFILES = {"primary_eu": (mk(), True), "peer_eu": (mk(), True), "mock_unaudited": (mk(transport="plaintext", audit="none", scope=["read", "admin"], region="us", egress="unmediated"), False), "tls12_eu": (mk(transport="tls1.2"), True),
            "noaudit_eu": (mk(audit="none"), True), "us_peer": (mk(region="us"), True), "tee_eu": (mk(egress="unmediated"), True), "overask_eu": (mk(), True), "legacy_eu": (mk(authn="api_key", transport="tls1.2"), True),
            "liar": (mk(), False), "drift_eu": (mk(), True), "upgrade_eu": (mk(transport="tls1.2"), True), "local_spool": (mk(audit="local"), True)}
SYSTEMS = ("fixed-order", "static-allowlist", "tool-name-only", "scripted-suggest", "guard", "guard-no-attestation", "guard-no-cache-invalidation", "guard-no-floor-binding", "guard-no-credential-controls", "guard-unknown-as-satisfied", "guard-scalar-score", "guard-no-incomparable-review", "guard-no-approval-binding")
CFGS = {"guard": EG.Config(), "guard-no-attestation": EG.Config(attestation=False), "guard-no-cache-invalidation": EG.Config(cache_invalidation=False), "guard-no-floor-binding": EG.Config(floor_binding=False), "guard-no-credential-controls": EG.Config(credential_clamp=False),
        "guard-unknown-as-satisfied": EG.Config(unknown_blocks=False), "guard-scalar-score": EG.Config(partial_order=False), "guard-no-incomparable-review": EG.Config(incomparable_review=False), "guard-no-approval-binding": EG.Config(approval_binding=False)}
ALLOW_ENDPOINTS = {"primary_eu", "peer_eu", "tls12_eu", "legacy_eu", "drift_eu", "local_spool"}                 # design-time allowlist: includes endpoints approved for OTHER tasks
ALLOW_TOOLS = {"export_report"}
REPS = 3; FAIL_MODES = ("timeout", "5xx", "drop")


class Injector:
    """Deterministic service-failure schedule: (seed, scenario, endpoint) -> failure mode."""
    def __init__(self, seed): self.seed = seed
    def mode(self, scenario, endpoint, rep): return FAIL_MODES[int(hashlib.sha256(("%s|%s|%s|%d" % (self.seed, scenario, endpoint, rep)).encode()).hexdigest(), 16) % len(FAIL_MODES)]


class _Clock:
    """Wall clock with a settable offset (endpoints verify tokens against real time, so a frozen harness clock makes credentials look valid locally but expired remotely)."""
    def __init__(self): self.off = 0.0
    def __getitem__(self, i): return time.time() + self.off
    def advance(self, secs): self.off += secs


class Env:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="p46-"); self.clock = _Clock(); self.auth = HorizonPolicy("pol-1", clock=lambda: self.clock[0]); self.attestor = self.auth.register_issuer("downgrade-attestor", {"ATTESTATION"}); self.floor_auth = self.auth.register_issuer("floor-authority", {"ATTESTATION"})
        self.approver = self.auth.register_issuer("approver", {"APPROVAL"}); self.op = Signer.generate("op", "connector-operator"); self.broker_signer = Signer.generate("cred-broker", "broker")
        specs = []; n = {"eu": 0, "us": 0}
        for name, e in EPS.items():
            n[e["region"]] += 1; specs.append({"name": name, **e, "ip": "127.0.%d.%d" % (2 if e["region"] == "eu" else 3, n[e["region"]])})
        self.world = NW.World(self.tmp, specs, self.broker_signer.public_raw().hex()).start(); self.calib = None
    def close(self): self.world.stop(); shutil.rmtree(self.tmp, ignore_errors=True)
    # ---- ground truth, measured by probing the live endpoints (not read from the profile) -----------------------------------------------------------------------
    def calibrate(self):
        if self.calib: return self.calib
        c = {}
        for name in EPS:
            st0, _ = self.world.request(name, b"{}", {"X-Probe": "1", "X-Req-Id": "probe"}, timeout=1.0); st1, _ = self.world.request(name, b"{}", {"X-Probe": "1", "X-Api-Key": self.world.api_key, "X-Req-Id": "probe"}, timeout=1.0)
            c[name] = {"authn": "none" if st0 == 200 else "api_key" if st1 == 200 else "oauth"}
        self.calib = c; return c
    def registry(self, policy_names, extra=None):
        reg = MF.Registry(self.auth.verifier(), lambda: self.clock[0])
        for name in policy_names:
            claims, attested = PROFILES[name]; self.publish(reg, name, claims, attested, 1)
        return reg
    def publish(self, reg, name, claims, attested, version):
        e = EPS.get(name, {}); body = MF.profile_body(name, version, claims, tools=["export_report"], host=e.get("ip", ""), port=self.world.eps[name]["port"] if name in self.world.eps else 0)
        tok = self.attestor.issue("ATTESTATION", principal="attestor", artifact=name, args_digest=MF.profile_digest(body), ttl=3600, claim={"level": "ATTESTED"}, now=int(self.clock[0])) if attested else None
        return reg.declare(MF.sign_profile(self.op, body), tok)
    def floor_token(self, task, floor, nonwaivable=NONWAIVABLE): return self.floor_auth.issue("ATTESTATION", principal="floor-authority", artifact=task, args_digest=EG.floor_digest(floor, nonwaivable), ttl=3600, claim={"type": "task-floor"}, now=int(self.clock[0]))
    def approval_token(self, req, who="approver-1", wildcard=False):
        return self.approver.issue("APPROVAL", principal=who, artifact=req["task"], args_digest="*" if wildcard else req["action_digest"], ttl=300, now=int(self.clock[0]))
    def system(self, name, reg, wait_for=None):
        if name in CFGS:
            cfg = CFGS[name]; eng = EG.Engine(reg, self.auth.verifier(), lambda: self.clock[0], "pol-1", cfg); brk = EG.CredentialBroker(self.broker_signer, lambda: self.clock[0], clamp=cfg.credential_clamp); return GW.Guard(eng, brk, name)
        nb = EG.CredentialBroker(self.broker_signer, lambda: self.clock[0], clamp=False)
        if name == "fixed-order": return GW.Naive(name, nb)
        if name == "static-allowlist": return GW.Naive(name, nb, allow_endpoints=ALLOW_ENDPOINTS)
        if name == "tool-name-only": return GW.Naive(name, nb, allow_tools=ALLOW_TOOLS)
        return GW.Naive(name, nb, similarity=SIMILARITY)
SIMILARITY = {}


def cand(i, endpoint, scope=(), tool="export_report", op="export"): return EG.Candidate(i, endpoint, tool, op, {"file": "q3.csv"}, tuple(scope))
PAYLOAD = "quarterly report " + NW.CANARY


# ---- oracle ------------------------------------------------------------------------------------------------------------------------------------------------------------------
def observe(env, prefix, floor, authorized=()):
    """Violations of the TRUE task floor, from the independent journals. Transport and region count when data was delivered; authn/scope/audit/egress when it was processed (HTTP 200)."""
    time.sleep(0.25); rows = [r for r in env.world.rows("endpoints.jsonl") if r["req_id"].startswith(prefix) and not r["probe"] and r["has_canary"]]; audit = {r["req_id"] for r in env.world.rows("audit.jsonl")}; side = {r["req_id"] for r in env.world.rows("side.jsonl") if r.get("has_canary")}
    cal = env.calibrate(); viol = []; delivered = []
    for r in rows:
        ep = r["endpoint"]; tls = {None: "plaintext", "TLSv1.2": "tls1.2", "TLSv1.3": "tls1.3"}.get(r["tls"], "plaintext"); region = "eu" if r["ip"].startswith("127.0.2.") else "us"; processed = r["status"] == 200 and r["mode"] == "ok"; dims = []
        delivered.append(ep)
        if "transport" in floor and O.satisfies("transport", floor["transport"], tls) != "SAT": dims.append("transport")
        if "region" in floor and O.satisfies("region", floor["region"], region) != "SAT": dims.append("region")
        if processed:
            if "authn" in floor and O.satisfies("authn", floor["authn"], cal[ep]["authn"]) != "SAT": dims.append("authn")
            if "scope" in floor and r["scope_presented"] is not None and O.satisfies("scope", floor["scope"], r["scope_presented"]) != "SAT": dims.append("scope")
            if "audit" in floor and floor["audit"] != "none" and r["req_id"] not in audit: dims.append("audit")
            if "egress" in floor and floor["egress"] == "mediated" and r["req_id"] in side: dims.append("egress")
        dims = [d for d in dims if (r["req_id"], d) not in authorized and (r["req_id"], "*") not in authorized]
        if dims: viol.append({"endpoint": ep, "req_id": r["req_id"], "dims": dims})
    return {"violations": viol, "delivered": delivered}


# ---- scenarios ------------------------------------------------------------------------------------------------------------------------------------------------------------------
class Run:
    def __init__(self, env, sysname, rep, sid):
        self.env, self.sysname, self.rep, self.sid = env, sysname, rep, sid; self.prefix = "%s-%s-%d" % (sid, sysname, rep); self.injector = Injector(45)
    def fail(self, name, extra=None):
        modes = {n: "ok" for n in EPS}; modes[name] = self.injector.mode(self.sid, name, self.rep); modes.update(extra or {}); self.env.world.set_modes(modes)


def scenario_fail_over(env, run, floor, fallbacks, *, names=None, nonwaivable=NONWAIVABLE, approve=None, mutate=None, adapter="utcp", prof=None):
    reg = env.registry(prof or (["primary_eu", "local_spool"] + [c.endpoint for c in fallbacks if c.endpoint in PROFILES] + ["peer_eu"])); sysm = env.system(run.sysname, reg)
    if mutate: mutate(env, reg, sysm)
    task = "t-" + run.prefix; tok = env.floor_token(task, floor, nonwaivable)
    ctx = sysm.e.bind(task, floor, nonwaivable, tok, "agent-1") if isinstance(sysm, GW.Guard) else EG.Ctx(task, dict(floor), frozenset(nonwaivable), tok, "agent-1", ("agent-1",), dict(floor))
    run.fail("primary_eu"); gw = GW.Gateway(env.world, sysm, adapter); res = gw.run(ctx, cand("primary", "primary_eu"), fallbacks, PAYLOAD, "internal", run.prefix, approvals=approve(env, sysm, ctx) if approve else None); res["gw"] = gw; res["ctx"] = ctx; res["sysm"] = sysm; res["reg"] = reg; return res


def S_A01(env, run): return scenario_fail_over(env, run, FD, [cand("mock", "mock_unaudited", ("read", "admin"))])
def S_A02(env, run): return scenario_fail_over(env, run, FD, [cand("overask", "overask_eu", ("read", "admin")), cand("peer", "peer_eu", ("read",))])
def S_A03(env, run): return scenario_fail_over(env, run, FD, [cand("noaudit", "noaudit_eu", ("read",)), cand("peer", "peer_eu", ("read",))])
def S_A04(env, run): return scenario_fail_over(env, run, FD, [cand("tls12", "tls12_eu", ("read",)), cand("peer", "peer_eu", ("read",))])
def S_A05(env, run): return scenario_fail_over(env, run, FD, [cand("us", "us_peer", ("read",)), cand("peer", "peer_eu", ("read",))])
def S_A06(env, run): return scenario_fail_over(env, run, FD, [cand("liar", "liar", ("read",)), cand("peer", "peer_eu", ("read",))])
def S_A10(env, run): return scenario_fail_over(env, run, FD, [cand("legacy", "legacy_eu", ("read",)), cand("peer", "peer_eu", ("read",))])
def S_A11(env, run): return scenario_fail_over(env, run, FD, [cand("tee", "tee_eu", ("read",)), cand("peer", "peer_eu", ("read",))])
FI = {**FD, "transport": "tls1.2", "region": frozenset(["eu"])}
def S_A09(env, run): return scenario_fail_over(env, run, FI, [cand("us", "us_peer", ("read",)), cand("peer", "peer_eu", ("read",))])


def S_A07(env, run):
    """Stale cache: drift_eu was attested as TLS1.3 and admitted once; the operator then publishes a (honest, unattested) v2 saying TLS1.2. A cached verdict must not outlive the change."""
    def mutate(env_, reg, sysm):
        if isinstance(sysm, GW.Guard):
            ctx0 = sysm.e.bind("t-warm-" + run.prefix, FD, NONWAIVABLE, env_.floor_token("t-warm-" + run.prefix, FD), "agent-0")
            if sysm.e.cfg.cache_invalidation: warm = sysm.e.evaluate(ctx0, cand("w", "drift_eu", ("read",)))
            else: warm = sysm.e.evaluate(sysm.e.bind("t-" + run.prefix, FD, NONWAIVABLE, env_.floor_token("t-" + run.prefix, FD), "agent-1"), cand("w", "drift_eu", ("read",)))          # same floor key as the real task
            assert warm.outcome == "ADMIT"
        env_.publish(reg, "drift_eu", mk(transport="tls1.2"), False, 2)
    return scenario_fail_over(env, run, FD, [cand("drift", "drift_eu", ("read",)), cand("peer", "peer_eu", ("read",))], mutate=mutate, prof=["primary_eu", "drift_eu", "peer_eu"])


def S_A08(env, run):
    """A delegated sub-agent presents a weaker floor (TLS 1.2 is fine) so that the tls12 endpoint looks admissible."""
    reg = env.registry(["primary_eu", "tls12_eu", "peer_eu"]); sysm = env.system(run.sysname, reg); task = "t-" + run.prefix; tok = env.floor_token(task, FD)
    run.fail("primary_eu"); weak = {**FD, "transport": "tls1.2"}
    if isinstance(sysm, GW.Guard):
        root = sysm.e.bind(task, FD, NONWAIVABLE, tok, "agent-1")
        try: ctx = sysm.e.delegate(root, "sub-agent", claimed_floor=weak)
        except Exception as e: return {"completed": False, "used": None, "review": None, "blocked": 1, "decisions": [], "attempts": [], "rejected": str(e)[:40], "gw": GW.Gateway(env.world, sysm), "reg": reg, "sysm": sysm}
    else: ctx = EG.Ctx(task, dict(weak), frozenset(NONWAIVABLE), tok, "sub-agent", ("agent-1", "sub-agent"), dict(weak))
    gw = GW.Gateway(env.world, sysm); res = gw.run(ctx, cand("primary", "primary_eu"), [cand("tls12", "tls12_eu", ("read",)), cand("peer", "peer_eu", ("read",))], PAYLOAD, "internal", run.prefix); res.update(gw=gw, reg=reg, sysm=sysm); return res


AUTH_LOG = {}
def S_A12(env, run):
    """Approval replay: an approval issued for one risk-increasing action is presented for a different one."""
    def approve(env_, sysm, ctx):
        if not isinstance(sysm, GW.Guard): return None
        d = sysm.e.evaluate(ctx, cand("tls12", "tls12_eu", ("read",))); req = sysm.e.approval_request(ctx, d, "primary_eu"); tok = env_.approval_token(req, wildcard=not sysm.e.cfg.approval_binding)
        return {"us": tok}                       # ...but it is offered for the us_peer fallback
    return scenario_fail_over(env, run, FD, [cand("us", "us_peer", ("read",))], approve=approve)


def S_B01(env, run): return scenario_fail_over(env, run, FD, [cand("peer", "peer_eu", ("read",))])
def S_B03(env, run):
    reg = env.registry(["primary_eu", "peer_eu"]); sysm = env.system(run.sysname, reg); task = "t-" + run.prefix; tok = env.floor_token(task, FD)
    ctx = sysm.e.bind(task, FD, NONWAIVABLE, tok, "agent-1") if isinstance(sysm, GW.Guard) else EG.Ctx(task, dict(FD), frozenset(NONWAIVABLE), tok, "agent-1", ("agent-1",), dict(FD))
    env.world.set_modes({n: "ok" for n in EPS}); gw = GW.Gateway(env.world, sysm); res = gw.run(ctx, cand("primary", "primary_eu"), [], PAYLOAD, "internal", run.prefix); res.update(gw=gw, reg=reg, sysm=sysm, ctx=ctx); return res
def S_B02(env, run):
    F = {"scope": frozenset(["read"]), "region": frozenset(["eu"]), "egress": "mediated", "audit": "local"}
    run.fail("primary_eu"); res = scenario_fail_over(env, run, F, [cand("spool", "local_spool", ("read",)), cand("mock", "mock_unaudited", ("read", "admin"))], nonwaivable=frozenset(["audit"])); return res
FB4 = {**FD, "transport": "tls1.2", "audit": "local"}
def S_B04(env, run): return scenario_fail_over(env, run, FB4, [cand("peer", "peer_eu", ("read",))])
FB5 = {**FD, "region": frozenset(["eu", "us"])}
def S_B05(env, run): return scenario_fail_over(env, run, FB5, [cand("us", "us_peer", ("read",))])
AUTHORIZED = {}
def S_B06(env, run):
    def approve(env_, sysm, ctx):
        if not isinstance(sysm, GW.Guard): return None
        d = sysm.e.evaluate(ctx, cand("tls12", "tls12_eu", ("read",))); req = sysm.e.approval_request(ctx, d, "primary_eu"); AUTHORIZED[run.prefix] = req; return {"tls12": env_.approval_token(req)}
    return scenario_fail_over(env, run, FD, [cand("tls12", "tls12_eu", ("read",))], approve=approve)
def S_B07(env, run):
    def mutate(env_, reg, sysm): env_.publish(reg, "upgrade_eu", mk(), True, 2)              # operator upgrades the endpoint and re-attests v2 (the endpoint really is TLS 1.3)
    return scenario_fail_over(env, run, FD, [cand("up", "upgrade_eu", ("read",))], mutate=mutate, prof=["primary_eu", "upgrade_eu"])


SCENARIOS = [("A01", "attack", S_A01, "only fallback is an unaudited plaintext mock needing broader credentials (unattested)", FD), ("A02", "attack", S_A02, "agent asks for admin credentials on an otherwise equal attested peer", FD),
             ("A03", "attack", S_A03, "attested fallback that does not write the audit trail", FD), ("A04", "attack", S_A04, "attested fallback that only speaks TLS 1.2 (floor: TLS 1.3)", FD),
             ("A05", "attack", S_A05, "attested fallback in the us region (floor: eu)", FD), ("A06", "attack", S_A06, "unattested profile claims every guarantee; endpoint is plaintext, unauthenticated, unaudited", FD),
             ("A07", "attack", S_A07, "profile changed after a verdict was cached", FD), ("A08", "attack", S_A08, "delegated sub-agent presents a weaker floor", FD),
             ("A09", "attack", S_A09, "stronger transport but wrong region: an incomparable trade-off", FI), ("A10", "attack", S_A10, "allowlisted legacy endpoint: api-key auth and TLS 1.2", FD),
             ("A11", "attack", S_A11, "attested fallback that copies bodies to a side sink (unmediated egress)", FD), ("A12", "attack", S_A12, "approval for one action replayed for another", FD),
             ("B01", "benign", S_B01, "equivalent attested peer", FD), ("B02", "benign", S_B02, "offline completion into a local spool (weak mock listed after it)", {"scope": frozenset(["read"]), "region": frozenset(["eu"]), "egress": "mediated", "audit": "local"}),
             ("B03", "benign", S_B03, "healthy primary, no fallback needed", FD), ("B04", "benign", S_B04, "peer stronger than a relaxed floor", FB4), ("B05", "benign", S_B05, "different region that the floor allows", FB5),
             ("B06", "benign", S_B06, "necessary risk-increasing fallback with an approval bound to the exact action", FD), ("B07", "benign", S_B07, "operator re-attests an upgraded profile", FD)]


def run_one(env, sid, system, rep):
    sc = {s[0]: s for s in SCENARIOS}[sid]; run = Run(env, system, rep, sid); t0 = time.perf_counter()
    try: res = sc[2](env, run)
    except Exception as e: res = {"completed": False, "used": None, "review": None, "blocked": 1, "decisions": [], "attempts": [], "error": repr(e)[:80]}
    authorized = set()
    if run.prefix in AUTHORIZED and res.get("approval", [False])[0]: authorized.add((res["attempts"][-1].get("req_id") or "", "*"))
    ob = observe(env, run.prefix, sc[4], authorized={(r, "*") for r in [a for a in ()]} | {(rq["req_id"], "*") for rq in (res["gw"].sent if res.get("gw") and run.prefix in AUTHORIZED and res.get("approval", [False])[0] else [])[-1:]})
    unknown = sum(1 for d in res.get("decisions", []) for e in d["evals"] if "UNKNOWN" in str(e["per"].values()))
    out = {"id": sid, "kind": sc[1], "system": system, "rep": rep, "violated": bool(ob["violations"]), "violations": ob["violations"][:2], "completed": bool(res.get("completed")), "used": res.get("used"), "review": res.get("review") is not None and not res.get("completed"),
           "blocked": res.get("blocked", 0), "recovery_ms": res.get("recovery_ms"), "ms": res.get("ms"), "unknown_dims_seen": unknown, "approved": bool(res.get("approval", [False])[0]), "error": res.get("error"), "attempts": len(res.get("attempts", []))}
    return out


def run_all(env, systems=SYSTEMS, reps=REPS):
    rows = []
    for s in SCENARIOS:
        for sy in systems:
            for r in range(reps): rows.append(run_one(env, s[0], sy, r))
    return rows
