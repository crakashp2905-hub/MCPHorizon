"""Shared core of the four Horizon benchmark suites (HMIB, HCCB, HECB, HIEB). P37.
A scenario is a function env -> (attack_record | None, control_record). attack_record = {"effect": bool, "denied": bool, ...} where `effect` comes from an INDEPENDENT oracle (never from the guard's own decision);
control_record = {"ok": bool, "denied": bool}. Benign scenario types return attack_record=None: they contribute only to completion / false-block measurements.
Baselines are expressed as sets of control LAYERS so ablations are explicit and every baseline's coverage limitation is stated, not implied."""
from __future__ import annotations
import hashlib, json, time
LAYERS = ("toolguard", "scanners", "sandbox", "runtime", "intake", "codegate", "isolation", "telemetry", "infra")
BASELINES = {
 "B0": (frozenset(), "no guard"),
 "B1": (frozenset({"toolguard"}), "conventional tool-level guard (names / regexes)"),
 "B2": (frozenset({"sandbox"}), "OS-only sandbox (confinement, no brokers, no provenance)"),
 "B3": (frozenset({"scanners"}), "mature-style scanners only (SAST / secret / generic IaC patterns)"),
 "B4": (frozenset({"intake", "codegate"}), "artifact-only gates (model intake + code evidence gate)"),
 "B5": (frozenset({"sandbox", "runtime"}), "HorizonRuntime P23-P30 (sandbox + egress/credential brokers + scope enforcement)"),
 "B6": (frozenset({"sandbox", "runtime", "intake", "codegate"}), "B5 + supply-chain and generated-code controls (P31, P33)"),
 "B7": (frozenset(LAYERS), "full Horizon: B6 + agent isolation, telemetry, InfraGuard (P34-P36) + conventional guards"),
}
MAIN = tuple(f"B{i}" for i in range(8))
for _l in LAYERS: BASELINES[f"B7-{_l}"] = (frozenset(LAYERS) - {_l}, f"ablation: B7 without the {_l} layer")
COVERAGE_LIMITS = {
 "B0": "none by design", "B1": "sees tool names and text patterns only; blind to artifact bytes, identities, topology and configuration",
 "B2": "confines processes; does not authenticate artifacts, identities or configurations, and in-process effects are untouched",
 "B3": "pattern coverage only: misses classes without a rule (authz logic, provenance), fires on text not behaviour",
 "B4": "decides at admission/release time only; nothing watches runtime effects, communication, telemetry or infrastructure",
 "B5": "runtime effect control only; no model/code provenance, no cross-agent identity, no infrastructure posture",
 "B6": "adds provenance and code gates; still no cross-agent isolation, tamper-evident telemetry or infrastructure posture",
 "B7": "all implemented layers; synthetic fixtures only, single VM, scripted toy models; no live-model, no independent review"}
class Env:
    def __init__(self, baseline: str):
        self.baseline = baseline; self.layers = BASELINES[baseline][0]
    def has(self, layer: str) -> bool: return layer in self.layers
def sha(o) -> str: return hashlib.sha256(json.dumps(o, sort_keys=True, default=str).encode() if not isinstance(o, bytes) else o).hexdigest()
class Scenario:
    def __init__(self, sid, suite, name, family, kind, fn, *, oracle, expectation, fixture_kind="local_synthetic_inert", summary=""):
        self.id, self.suite, self.name, self.family, self.kind, self.fn, self.oracle, self.expectation, self.fixture_kind, self.summary = sid, suite, name, family, kind, fn, oracle, expectation, fixture_kind, summary
    def manifest(self) -> dict:
        return {"benchmark_schema": "horizon.incident.v1", "id": self.id, "suite": self.suite, "scenario": self.name, "family": self.family, "kind": self.kind, "fixture_kind": self.fixture_kind, "summary": self.summary,
                "requirements": {"internet_egress": "denied", "real_secrets": "forbidden", "trusted_effect_oracle": "required"}, "oracle": self.oracle, "expectation": self.expectation,
                "report": {"attempted_action": "required", "authorization_verdict": "required", "independent_receiver_effect": "required", "task_success": "required", "trace_completeness": "required"}}
REGISTRY: dict[str, Scenario] = {}
def scenario(sid, suite, name, family, kind, *, oracle, expectation, summary=""):
    def deco(fn): REGISTRY[sid] = Scenario(sid, suite, name, family, kind, fn, oracle=oracle, expectation=expectation, summary=summary); return fn
    return deco
def attack(effect: bool, denied: bool = False, **kw) -> dict: return {"effect": bool(effect), "denied": bool(denied), **kw}
def control(ok: bool, denied: bool = False, **kw) -> dict: return {"ok": bool(ok), "denied": bool(denied), **kw}
def run_one(sc: Scenario, baseline: str) -> list:
    """-> raw rows (attack row unless benign, control row). Never raises: a harness error is recorded as an error row so it can neither hide an effect nor fake a pass."""
    env = Env(baseline); t0 = time.perf_counter()
    try: a, k = sc.fn(env)
    except Exception as e: a, k = ({"effect": False, "denied": False, "error": f"{type(e).__name__}: {e}"[:200]} if sc.kind != "benign" else None), {"ok": False, "denied": False, "error": f"{type(e).__name__}: {e}"[:200]}
    dt = round(time.perf_counter() - t0, 4); rows = []
    for kind, rec in (("attack", a), ("control", k)):
        if rec is None: continue
        row = {"scenario": sc.id, "suite": sc.suite, "family": sc.family, "baseline": baseline, "kind": kind, **rec}; row["seconds"] = dt if kind == "control" else 0.0; row["raw_trace_digest"] = sha({k_: v for k_, v in row.items() if k_ != "seconds"}); rows.append(row)
    return rows
