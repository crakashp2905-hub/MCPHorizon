"""Managed execution of generated NATIVE code (P27). Wraps the kernel sandbox with: a launch identity (run/parent/exec ids), a pre-launch hook, trusted host observation (process tree + scratch file events),
correlation of the agent's action to kernel-native process events, advisory (never enforcing) claim-vs-behavior mismatch, and an explicit coverage report. The agent's code and words are untrusted inputs."""
from __future__ import annotations
import hashlib, uuid
from dataclasses import dataclass, field
from horizon.runtime import sandbox as S, procs as P, schema as SC

SUPPORTED = ("python",)
INTERFACES = ("mcp_wrapper", "utcp_cli", "code_mode")


@dataclass(frozen=True)
class Identity:
    run_id: str; parent_run_id: str | None; exec_id: str; principal: str; interface: str; language: str; code_sha256: str; policy_digest: str


class Refused(Exception):
    def __init__(self, code, detail=""): super().__init__(f"{code}: {detail}"); self.code = code


COVERAGE = {
    "process_creation": {"status": "intercepted", "how": "host /proc ancestry polling (pid+starttime)", "gap": "processes shorter than the poll interval can be missed; not a syscall trace"},
    "file_scratch_events": {"status": "intercepted", "how": "host inotify on the scratch tree", "gap": "depth-1 + directories present at start; no events outside scratch"},
    "file_outside_scratch": {"status": "enforced_not_observed", "how": "Landlock + mount masking deny access", "gap": "denied attempts are silent (no kernel audit stream collected)"},
    "network_direct": {"status": "enforced_not_observed", "how": "netns + seccomp + Landlock deny", "gap": "attempts are not logged unless the payload itself reports errno (advisory)"},
    "network_brokered": {"status": "intercepted", "how": "broker session + independent receiver", "gap": "HTTP only; other transports denied"},
    "syscalls_general": {"status": "unavailable", "how": "no ptrace/seccomp-notify/eBPF tracing implemented", "gap": "cannot enumerate all syscalls attempted"},
    "kernel_audit": {"status": "unavailable", "how": "no auditd/LSM log correlation", "gap": "P24-18 unmet"},
    "non_python_runtimes": {"status": "unsupported", "how": "refused at launch hook", "gap": "bash/node/perl as the TOP-LEVEL program are refused (children of python are confined by inheritance)"},
}


class ManagedExecutor:
    def __init__(self, session_factory=None, *, policy=None, hook=None, timeout_s=15):
        self.session_factory, self.policy, self.hook, self.timeout_s, self.launches = session_factory, policy, hook, timeout_s, []
    def run(self, code: str, *, principal: str, interface: str = "code_mode", language: str = "python", parent_run_id: str | None = None, action_id: str | None = None, declared: dict | None = None, observe_files=True, prelude: str = "") -> dict:
        if interface not in INTERFACES: raise Refused("UNKNOWN_INTERFACE", interface)
        if language not in SUPPORTED: raise Refused("UNSUPPORTED_RUNTIME", language)                  # no privileged fallback: unsupported means not run at all
        exec_id = "x-" + uuid.uuid4().hex[:12]; run_id = "r-" + exec_id[2:]
        full = prelude + code; pol = self.policy or S.Policy()
        ident = Identity(run_id, parent_run_id, exec_id, principal, interface, language, hashlib.sha256(full.encode()).hexdigest(), pol.digest())
        if self.hook:
            v = self.hook(ident, full)                                                                  # managed execution hook BEFORE the program starts
            if v is not None: raise Refused("HOOK_DENIED", str(v))
        pw, fw = P.ProcWatch(), P.FileWatch(); obs = [pw] + ([fw] if observe_files else [])
        res = S.launch(full, run_id=run_id, policy=pol, broker=self.session_factory(principal) if self.session_factory else None, timeout_s=self.timeout_s, observers=obs, extra_env={"HZ_PARENT_RUN_ID": parent_run_id or ""})
        if res.refused: raise Refused("LAUNCH_REFUSED", res.refused)
        self.launches.append(ident)
        procs = res.observations["procs"]["processes"]; files = res.observations.get("files", {}).get("events", [])
        events = native_events(ident, action_id, res, procs, files)
        mismatch = None
        if declared is not None:
            actual = {"uses_tools": bool(res.broker_requests), "spawns_processes": len(procs) > 1, "writes_files": any(e["op"] in ("create", "modify") for e in files)}
            diff = {k: {"declared": v, "observed": actual.get(k)} for k, v in declared.items() if k in actual and actual[k] != v}
            mismatch = {"advisory": True, "diff": diff} if diff else None                                 # logged; NEVER changes the enforcement result
        return {"identity": ident, "result": res, "processes": procs, "file_events": files, "events": events, "mismatch": mismatch, "action_id": action_id}


def native_events(ident: Identity, action_id, res, procs, files) -> list:
    """Correlates the agent action with kernel-native process rows (source=host). Process facts never come from the agent."""
    evs = []
    for i, p in enumerate(procs):
        prof = p["profile"]; evs.append(SC.make_event(ident.run_id, i, "process", layer="L2", origin="live_attempt", process={"pid": p["pid"], "ppid": p["ppid"], "source": "host"}, principal=ident.principal, decision="allow", policy_digest=ident.policy_digest,
                                                       status="ATTEMPTED", oracle={"receiver_bytes": None}, action_id=action_id, interface=ident.interface, exec_id=ident.exec_id, comm=p["comm"], no_new_privs=prof.get("NoNewPrivs"), seccomp=prof.get("Seccomp"), cap_eff=prof.get("CapEff")))
    return evs


def coverage_report() -> dict:
    by = {}
    for k, v in COVERAGE.items(): by.setdefault(v["status"], []).append(k)
    return {"effects": COVERAGE, "summary": {k: sorted(v) for k, v in by.items()}, "note": "an effect class that is not 'intercepted' must not be read as 'safe'; enforced_not_observed means blocked but unlogged"}


def comparable(out: dict) -> dict:
    """Interface-independent outcome used for cross-interface equality (P27-18)."""
    r = out["result"]
    return {"exit": r.exit, "stdout": r.stdout, "broker": [(x["url"], x["ok"], x.get("code")) for x in r.broker_requests], "proc_comms": sorted(p["comm"] for p in out["processes"]), "profiles": sorted({(p["profile"].get("NoNewPrivs"), p["profile"].get("Seccomp"), p["profile"].get("CapEff")) for p in out["processes"]})}
