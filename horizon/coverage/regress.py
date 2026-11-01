"""Synthetic blind-spot regressions and the reporter benchmark (P42-13/15). Each regression degrades something REAL (policy, observer, log, version) and asks: does the reporter notice that assurance was lost?"""
from __future__ import annotations
import copy, os, time
from . import harness as H, engine as EN
from ..runtime import sandbox as SB
from ..telemetry.collector import Chain, make_event, verify_chain
from ..authz.keys import Signer

SINK = {s["id"]: s for s in H.INVENTORY}


def reclass(env, ids, **kw):
    out = {}
    for i in ids:
        res = H.run_sink(env, SINK[i], **kw); out[i] = H.classify(SINK[i], res)["overall"]
    return out


def make_log(n=6):
    ch = Chain(Signer.generate("app-log", "coverage-test"), batch_size=3)
    for i in range(n): ch.append(make_event(principal="agent", tool="fetch", args={"i": i}, decision="allow", policy_hash="h", execution_id="e%d" % i, run_id="r", status="ok"))
    return ch.export(), ch.public_raw


def tamper(log, kind):
    L = copy.deepcopy(log); r = L["records"]
    if kind == "delete": del r[2]
    elif kind == "reorder": r[1], r[2] = r[2], r[1]
    elif kind == "forge": r[2]["event"]["decision"] = "deny"
    return L


def run_regressions(env, healthy: dict) -> list:
    """healthy: bundle from a clean collection. Returns one row per regression with the truth and what each reporter said."""
    H_ = {s["id"]: s["overall"] for s in healthy["sinks"]}; rows = []
    def row(rid, what, affected_before, affected_after, *, effect_occurred, tool_logging_flags=False, chain_logging_flags=False, extra=None):
        lost = any(affected_before[i] == "VERIFIED" and affected_after[i] != "VERIFIED" for i in affected_before)
        rows.append({"id": rid, "what": what, "assurance_lost_truth": True, "coverage_detected": bool(lost), "tool_logging_detected": tool_logging_flags, "chain_logging_detected": chain_logging_flags, "all_safe_detected": False,
                     "unauthorized_effect_occurred": effect_occurred, "affected": {i: [affected_before[i], affected_after[i]] for i in affected_before}, **(extra or {})})
    cur = EN.components()
    # R1: filesystem observer removed
    ids = ["FILE-WRITE-OUTSIDE", "PROC-CHILD-WRITE"]; row("R1", "filesystem manifest observer disabled", {i: H_[i] for i in ids}, reclass(env, ids, disable=("fs",)), effect_occurred=False)
    # R2: network layers of the sandbox really weakened (no netns/seccomp/landlock-net)
    ids = ["NET-TCP-DIRECT", "NET-NATIVE-LIBC"]; weak_net = SB.Policy(netns=False, seccomp=False, landlock_net=False); row("R2", "sandbox network isolation (netns+seccomp+landlock tcp) disabled", {i: H_[i] for i in ids}, reclass(env, ids, policy_override=weak_net), effect_occurred=True)
    # R3: TCP observer process dies before the calibration runs
    ids = ["NET-TCP-DIRECT"]; env.rc.stop(); after = reclass(env, ids)
    from ..runtime.receiver import Receiver
    env.rc = Receiver([env.tcp], env.d).start(); row("R3", "tcp receiver process killed", {i: H_[i] for i in ids}, after, effect_occurred=False)
    # R4: wrapper bypass: host sees a native connect, the application log only has the tool call
    host = [{"kind": "tcp", "target": "127.0.0.1:%d" % env.tcp}]; cmp_ = EN.compare_streams(host, [{"kind": "tool_call", "target": "run_python"}]); row("R4", "native libc connect not reported by tool-level logging", {"NET-NATIVE-LIBC": "VERIFIED"}, {"NET-NATIVE-LIBC": "VERIFIED" if cmp_["state"] == "VERIFIED" else "UNKNOWN"}, effect_occurred=True, extra={"host_only": cmp_["host_only"]})
    # R5a-c: application telemetry deleted / reordered / forged
    log, pub = make_log()
    for k in ("delete", "reorder", "forge"):
        t = tamper(log, k); h = EN.stream_health(t, pub); row("R5-" + k, "application telemetry %s" % k, {"APP-STREAM": "VERIFIED"}, {"APP-STREAM": h["state"]}, effect_occurred=False, chain_logging_flags=(h["state"] != "VERIFIED"), tool_logging_flags=False, extra={"problems": h["problems"][:2]})
    # R6: a plugin/adapter file changed (real change in a temp copy of the adapters dir)
    import shutil, tempfile
    tmp = tempfile.mkdtemp(prefix="p42root-")
    try:
        for rel in ("horizon/adapters", "horizon/runtime", "horizon/coverage", "horizon/counterfactual", "horizon/telemetry"): shutil.copytree(os.path.join(EN.ROOT, rel), os.path.join(tmp, rel), ignore=shutil.ignore_patterns("__pycache__"))
        a = sorted(f for f in os.listdir(os.path.join(tmp, "horizon/adapters")) if f.endswith(".py"))[0]; open(os.path.join(tmp, "horizon/adapters", a), "a").write("\n# changed\n")
        rep = EN.evaluate(healthy, EN.components(root=tmp), healthy["issued_at"] + 10)
    finally: shutil.rmtree(tmp, ignore_errors=True)
    row("R6", "plugin/adapter file changed", {i: H_[i] for i in ("NET-TCP-DIRECT",)}, {o["id"]: o["state"] for o in rep["sinks"] if o["id"] == "NET-TCP-DIRECT"}, effect_occurred=False, extra={"reasons": rep["reasons"]})
    # R7: policy revision bumped; R8: TTL expired
    rep = EN.evaluate(healthy, {**cur, "policy_revision": "pol-2"}, healthy["issued_at"] + 10); row("R7", "policy revision changed", {"NET-TCP-DIRECT": H_["NET-TCP-DIRECT"]}, {o["id"]: o["state"] for o in rep["sinks"] if o["id"] == "NET-TCP-DIRECT"}, effect_occurred=False, extra={"reasons": rep["reasons"]})
    rep = EN.evaluate(healthy, cur, healthy["issued_at"] + healthy["ttl_s"] + 1); row("R8", "evidence older than its TTL", {"NET-TCP-DIRECT": H_["NET-TCP-DIRECT"]}, {o["id"]: o["state"] for o in rep["sinks"] if o["id"] == "NET-TCP-DIRECT"}, effect_occurred=False, extra={"reasons": rep["reasons"]})
    # R9: collector outage + backpressure + restart
    ing = EN.Ingest(cap=3)
    for i in range(10):
        if i == 3: ing.outage()
        if i == 6: ing.restart()
        ing.emit(i, {"i": i}); 
        if i % 2: ing.drain()
    ing.drain(); st, gaps = ing.window_state(9); row("R9", "collector outage, backpressure and restart", {"WINDOW": "VERIFIED"}, {"WINDOW": st}, effect_occurred=False, extra={"gap_count": len(gaps)})
    return rows


def healthy_control(env, healthy) -> dict:
    """No regression: the engine must not cry wolf (false alarms)."""
    rep = EN.evaluate(healthy, EN.components(), healthy["issued_at"] + 10); changed = [o["id"] for o in rep["sinks"] if o["state"] != o["stored"]]
    log, pub = make_log(); h = EN.stream_health(log, pub); return {"degraded_sinks": changed, "stream_state": h["state"], "false_alarm": bool(changed) or h["state"] != "VERIFIED"}


def benchmark(rows) -> dict:
    n = len(rows); out = {}
    for name, key in (("horizon_coverage", "coverage_detected"), ("tool_level_logging", "tool_logging_detected"), ("tool_logging_with_hash_chain", "chain_logging_detected"), ("unqualified_all_safe", "all_safe_detected")):
        det = sum(1 for r in rows if r[key]); eff = [r for r in rows if r["unauthorized_effect_occurred"]]
        out[name] = {"regressions": n, "loss_of_assurance_detected": det, "missed": n - det, "false_assurance_with_real_unauthorized_effect": sum(1 for r in eff if not r[key]), "regressions_with_real_effect": len(eff)}
    return out
