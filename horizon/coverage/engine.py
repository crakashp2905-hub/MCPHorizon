"""Coverage evidence bundle, TTL/invalidation, stream health, host-vs-application comparison, ingestion gaps (P42-07..12). States: VERIFIED | UNKNOWN | MISSING. Nothing defaults to safe."""
from __future__ import annotations
import hashlib, json, os, platform, time
from . import harness as H
from ..runtime import sandbox as SB
from ..runtime.receiver import CANARY

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCHEMA = "coverage-bundle/1.0.0"
TTL_S = 3600


def sha(b): return hashlib.sha256(b if isinstance(b, bytes) else json.dumps(b, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
def filehash(rel, root=None): return sha(open(os.path.join(root or ROOT, rel), "rb").read())


def components(policy_revision="pol-1", sandbox_policy=None, root=None) -> dict:
    """Everything whose change invalidates coverage evidence (P42-11): sandbox policy + code, runtime/receiver/collector code, plugins/adapters, policy revision, kernel."""
    root = root or ROOT; plugins = {f: filehash("horizon/adapters/" + f, root) for f in sorted(os.listdir(os.path.join(root, "horizon/adapters"))) if f.endswith(".py")}
    return {"sandbox_policy": (sandbox_policy or SB.Policy()).digest(), "sandbox_code": filehash("horizon/runtime/sandbox.py", root), "observer_code": sha({f: filehash(f, root) for f in ("horizon/runtime/receiver.py", "horizon/coverage/observers.py", "horizon/counterfactual/receipt.py")}),
            "enforcement_code": sha({f: filehash(f, root) for f in ("horizon/counterfactual/commit.py", "horizon/telemetry/collector.py")}), "plugins": sha(plugins), "policy_revision": policy_revision, "kernel": platform.release()}


def environment() -> dict:
    ok, why = H.sandbox_available()
    return {"kernel": platform.release(), "python": platform.python_version(), "machine": platform.machine(), "uid": os.geteuid(), "sandbox": why, "sandbox_usable": ok, "plugin_files": sorted(os.listdir(os.path.join(ROOT, "horizon/adapters")))}


def collect(*, policy_revision="pol-1", now=None, ttl=TTL_S, env=None) -> dict:
    own = env is None; env = env or H.Env(); sinks = []
    try:
        for s in H.INVENTORY:
            res = H.run_sink(env, s); c = H.classify(s, res)
            sinks.append({"id": s["id"], "family": s["family"], "interface": s["interface"], "enforcement_point": s["enforcement_point"], "observation_channel": s["observation_channel"], "enforcement": list(c["enforcement"]), "observation": list(c["observation"]), "overall": c["overall"],
                          "weak_seen": [t.get("seen") for t in res["weak"]], "strong_seen": [t.get("seen") for t in res["strong"]], "note": s["note"]})
    finally:
        if own: env.close()
    b = {"schema": SCHEMA, "issued_at": int(now if now is not None else time.time()), "ttl_s": ttl, "environment": environment(), "components": components(policy_revision), "sinks": sinks}
    b["ratios"] = ratios(sinks); b["bundle_digest"] = sha({k: v for k, v in b.items() if k != "bundle_digest"}); return b


def ratios(sinks) -> dict:
    out = {}
    for fam in H.FAMILIES:
        S = [s for s in sinks if s["family"] == fam]; c = {k: sum(1 for s in S if s["overall"] == k) for k in ("VERIFIED", "UNKNOWN", "MISSING")}
        out[fam] = {"sinks": len(S), **c, "verified_ratio": round(c["VERIFIED"] / len(S), 4) if S else None}
    allS = sinks; out["ALL"] = {"sinks": len(allS), **{k: sum(1 for s in allS if s["overall"] == k) for k in ("VERIFIED", "UNKNOWN", "MISSING")}}; out["ALL"]["verified_ratio"] = round(out["ALL"]["VERIFIED"] / len(allS), 4); return out


def evaluate(bundle, current: dict, now) -> dict:
    """Current state of each sink: stored VERIFIED degrades to UNKNOWN when the bundle is expired or any component changed. Never upgrades."""
    why = []
    if now >= bundle["issued_at"] + bundle["ttl_s"]: why.append("TTL_EXPIRED")
    if bundle["issued_at"] > now + 5: why.append("ISSUED_IN_FUTURE")
    for k, v in bundle["components"].items():
        if current.get(k) != v: why.append("INVALIDATED:" + k)
    out = []
    for s in bundle["sinks"]:
        st = s["overall"]
        if st == "VERIFIED" and why: st = "UNKNOWN"
        out.append({"id": s["id"], "family": s["family"], "state": st, "stored": s["overall"], "reasons": list(why) if s["overall"] == "VERIFIED" else []})
    return {"reasons": why, "sinks": out, "ratios": ratios([{"family": o["family"], "overall": o["state"]} for o in out])}


def claims_status(claims: dict, report: dict) -> dict:
    """A protection claim is SUPPORTED only if every sink it depends on is VERIFIED right now."""
    st = {o["id"]: o["state"] for o in report["sinks"]}; res = {}
    for name, c in claims.items():
        need = c["sinks"]; bad = {i: st.get(i, "MISSING") for i in need if st.get(i) != "VERIFIED"}; res[name] = {"supported": not bad, "blocking": bad}
    return res


# ---- application-event stream health and host-vs-application comparison (P42-07, P42-12) ------------------------------------------------------------------------------
def stream_health(log: dict, pub_raw: bytes) -> dict:
    from ..telemetry.collector import verify_chain
    r = verify_chain(log, pub_raw); return {"state": "VERIFIED" if r["ok"] else "UNKNOWN", "problems": r["problems"][:4]}


def compare_streams(host_effects: list, app_events: list) -> dict:
    """host_effects/app_events: lists of {kind, target}. host_only = effects the application log never reported (blind spot of tool-level logging); app_only = reported but not observed."""
    H_ = {(e["kind"], e["target"]) for e in host_effects}; A = {(e["kind"], e["target"]) for e in app_events}
    return {"matched": sorted(H_ & A), "host_only": sorted(H_ - A), "app_only": sorted(A - H_), "state": "VERIFIED" if H_ == A else "UNKNOWN"}


class Ingest:
    """Bounded collector queue with sequence numbers (P42-08): outages, backpressure and restarts show up as gaps; coverage over a window containing a gap is UNKNOWN, never 'no events = safe'."""
    def __init__(self, cap=4): self.cap, self.q, self.accepted, self.dropped, self.up, self.epoch, self.expected = cap, [], [], [], True, 0, 0
    def emit(self, seq, ev):
        if not self.up: self.dropped.append((seq, "COLLECTOR_DOWN")); return False
        if len(self.q) >= self.cap: self.dropped.append((seq, "BACKPRESSURE")); return False
        self.q.append((self.epoch, seq, ev)); return True
    def drain(self, n=None):
        k = len(self.q) if n is None else n
        for _ in range(min(k, len(self.q))): self.accepted.append(self.q.pop(0))
    def outage(self): self.up = False
    def restart(self): self.up = True; self.epoch += 1; self.q.clear()          # in-memory queue is lost on restart: its contents become gaps
    def gaps(self, last_seq):
        seen = {s for _, s, _ in self.accepted}; return [s for s in range(0, last_seq + 1) if s not in seen]
    def window_state(self, last_seq): return ("VERIFIED", []) if not self.gaps(last_seq) else ("UNKNOWN", self.gaps(last_seq))
