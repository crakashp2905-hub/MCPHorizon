"""M0-03: per-module-group inventory for the 47 masterplan module groups (A01..G05). `--write` regenerates the module-inventory JSON under docs/evidence/integration (default mode checks it is current).
Everything here is a STATIC HEURISTIC over source text/AST: it lists files, LOC, public top-level names, side-effect imports/calls, persisted-state markers, tests that import the group, and syntactic fail-open
patterns (a bare `except` that only passes/returns a constant). It is not a security review: a missing marker means 'not detected', and a detected one is a lead, not a finding. `role` and `required_integration`
are TRANSCRIBED from the masterplan table, not derived."""
from __future__ import annotations
import ast, json, os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); OUT = os.path.join(ROOT, "docs", "evidence", "integration", "MODULE_INVENTORY.json")
# (id, name, paths, role, required integration) transcribed from masterplan section 3
M = [
 ("A01", "Schemas, normalization", ["horizon/schemas.py", "horizon/normalize.py", "schemas"], "Foundation", "One protocol-neutral schema and canonicalizer; Python/Rust/TS semantic parity"),
 ("A02", "Core capability policy", ["horizon/core", "core"], "Kernel", "One authoritative evaluate() with deny precedence; no parallel decision routes"),
 ("A03", "Authority and evidence", ["horizon/hpolicy", "horizon/authz"], "High-trust authority", "Unify issuer roles; stop per-module signer creation; separate keys"),
 ("A04", "Canonical effect", ["horizon/effects/canonical.py"], "Kernel", "Extend exact target/args/session/server/delegation binding to all effects"),
 ("A05", "Delegation and A2A", ["horizon/deleg", "horizon/a2a"], "Session/identity", "Capability attenuation, grant lineage, revocation and sub-agent ancestry"),
 ("A06", "Least privilege and fallback", ["horizon/lp", "horizon/downgrade"], "Constraint engine", "Policy floor; fallback cannot widen privileges"),
 ("B01", "Decision API", ["horizon/service", "horizon/sdk", "sdk-ts"], "Policy service", "Make durable, authenticated, role-scoped; no process-local authority claims"),
 ("B02", "Effect ledger", ["horizon/effects/ledger.py"], "Kernel commit", "Atomic nonce, fence, uncertain outcomes, separate broker transactions"),
 ("B03", "Protected file sink", ["horizon/effects/filesink.py", "horizon/effects/sinkproc.py"], "PEP / sink", "OS-separated fs; no direct agent file writes; external anchor"),
 ("B04", "Network and remote effects", ["horizon/effects/netbroker.py", "horizon/effects/httpsink.py", "horizon/reach"], "PEP / sink", "Mandatory brokered egress; TLS/DNS; indirect-effect evidence"),
 ("B05", "Linux sandbox", ["horizon/runtime/sandbox.py", "horizon/runtime/managed.py"], "Isolation", "Block raw sockets and ambient exec; verify kernel profile before agent starts"),
 ("B06", "Code Mode", ["horizon/codemode", "codemode"], "Adapter + isolation", "Treat JS isolate as untrusted; all tool calls re-enter kernel"),
 ("B07", "Transactions/obligations/counterfactual", ["horizon/txn", "horizon/obligation", "horizon/counterfactual"], "Precommit/preview", "Typed prerequisites, true dry-run no live effects"),
 ("B08", "Secrets/credential broker", ["horizon/ops/secrets.py", "horizon/runtime/creds.py", "horizon/adapters/utcp/creds.py"], "Trusted broker", "Never inject long-lived raw credentials into untrusted agents"),
 ("C01", "MCP adapter", ["horizon/adapters/mcp", "horizon/effects/mcp_gateway.py"], "Gateway", "Merge policy-first gate and effect-bound reference gateway"),
 ("C02", "UTCP adapter", ["horizon/adapters/utcp"], "Gateway", "Wrap official SDK and pass all calls through same canonical effect kernel"),
 ("C03", "A2A/frameworks/skills", ["horizon/a2a", "horizon/frameworks", "horizon/skillpolicy"], "Gateway/intake", "Delegation and tool manifests as untrusted until verified"),
 ("C04", "Data lineage", ["horizon/lineage"], "Policy predicate", "Trusted sidecar traces taint; bounded detection with explicit blind spots"),
 ("C05", "Multi-agent isolation", ["horizon/agents", "horizon/deleg"], "Runner", "Tenant/session isolation, no uncontrolled cross-agent sharing"),
 ("C06", "Memory/epistemic evidence", ["horizon/memory", "horizon/epist"], "Data plane + observer", "Memory is data, not authority; uncertainty and evidence lineage"),
 ("C07", "Temporal safety/continuity", ["horizon/temporal", "horizon/continuity"], "Constraint/monitor", "Monotonic policies, scoped handoff, temporal revocation"),
 ("D01", "Privacy/budgets", ["horizon/privacy", "horizon/budget"], "Atomic commit constraint", "Reserve and charge privacy/usage budget with effect IDs"),
 ("D02", "Consent/approvals", ["horizon/consent", "horizon/approvalui"], "Owner authority", "Approval bound to exact effect + content/destination/version"),
 ("D03", "Incentive robustness", ["horizon/incentive"], "Evaluation", "Demonstrate that agent reward does not override reference monitor"),
 ("D04", "Evaluation integrity", ["horizon/evalint"], "Independent evaluation", "Protect hidden labels, oracle independence and collector trust"),
 ("D05", "Browser/vision", ["horizon/vision"], "Effect adapter", "Browser writes/navigation/download must be brokered and receiver observed"),
 ("D06", "Fallback/model policy", ["horizon/downgrade", "horizon/weights"], "Intake/risk", "Model artifacts pinned, behavioral safety unassessed unless tested"),
 ("E01", "HorizonEmergence", ["horizon/emergence"], "Discovery/test", "Multi-step composition attacks; feed counterexamples into Forge"),
 ("E02", "HorizonCoverage", ["horizon/coverage"], "Observer", "Typed coverage, missing sensors, explicit UNKNOWN, independent sources"),
 ("E03", "HorizonMutation", ["horizon/mutation"], "Validation", "Mutation testing with live security oracles; harness rollback"),
 ("E04", "HorizonReach", ["horizon/reach"], "Remote graph/test", "Indirect effects and deceptive remote services; no first-call false assurance"),
 ("E05", "HorizonCounterfactual", ["horizon/counterfactual"], "Predeploy validation", "Prove simulations cannot commit real effects"),
 ("E06", "Telemetry/forensics", ["horizon/telemetry", "horizon/integration/audit.py"], "Witness/evidence", "Receiver/sink and host observations separate from untrusted transcript"),
 ("E07", "Code/infrastructure scanning", ["horizon/codeassur", "horizon/infraguard", "horizon/guard"], "Intake/advisory", "Scan malicious tools/code/config; never greenlight solely from scanner"),
 ("F01", "HorizonZero", ["horizon/assurance"], "Assurance gate", "Claims scoped to actual installed controls and independently observed effects"),
 ("F02", "HorizonForge", ["horizon/forge"], "Untrusted proposal", "Joint control + witness optimization; trusted checker separate"),
 ("F03", "HorizonSpectra", ["research/spectra"], "Safe discovery", "Effect probes on real isolated receivers, honest unidentifiability"),
 ("F04", "HorizonPatch", ["research/weightspace"], "Optional model research", "Repair model behavior only after causal/held-out security validation"),
 ("F05", "HorizonSentinel", [], "Optional model integrity", "Checkpoint/delta integrity and rollback, no silent live model modification"),
 ("F06", "HorizonTransfer", [], "Optional model research", "Patch portability experiments with independent tests; no implicit rollout"),
 ("F07", "HorizonReflex", [], "Optional fast advisor", "Effect/probe proposal model, no permission to authorize"),
 ("F08", "Novelty helper tools", ["research/novel"], "Validation", "Independent risk/witness/model checks; separate research claims"),
 ("G01", "Synthetic benchmarks", ["bench/secbench", "bench/dataset"], "Evaluation", "Retain negative baselines; benchmark not circular"),
 ("G02", "Real data and replay", ["bench/real", "research/live"], "Evaluation", "Offline replay vs live intervention separated; held-out task utility"),
 ("G03", "Supervisor", ["orchestrator", "spec"], "Development governance", "No autonomous self-certification; worker/verifier/owner identities separate"),
 ("G04", "Release/supply chain", ["scripts", "third_party_pins", ".github"], "Deployment governance", "SBOM, signatures, licensing, reproducible artifacts, incident plan"),
 ("G05", "Operations and recovery", ["horizon/ops", "horizon/integration"], "Operations", "SLIs, alerts, backups, live-unknown handling, key rotation, kill switches"),
]
SIDE = {"socket", "subprocess", "sqlite3", "http", "urllib", "ssl", "ctypes", "multiprocessing", "shutil", "tempfile", "fcntl", "resource"}
SIDE_CALLS = {"open", "system", "popen", "remove", "unlink", "rename", "replace", "makedirs", "mkdir", "rmdir", "setrlimit", "unshare", "chmod", "kill", "killpg"}
PERSIST = {"sqlite3", "pickle", "shelve", "json.dump"}


def _files(paths):
    out = []
    for p in paths:
        a = os.path.join(ROOT, p)
        if os.path.isfile(a): out.append(p)
        elif os.path.isdir(a):
            for dp, dn, fs in os.walk(a):
                dn[:] = sorted(d for d in dn if d not in ("__pycache__", "node_modules", "target", ".git"))
                out += [os.path.relpath(os.path.join(dp, f), ROOT) for f in sorted(fs) if f.endswith((".py", ".ts", ".rs", ".js", ".json", ".yml", ".yaml"))]
    return sorted(set(out))


def analyse_py(src):
    tree = ast.parse(src); side = set(); persist = set(); failopen = 0; public = []
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)) and not n.name.startswith("_"): public.append(n.name)
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] in SIDE: side.add(a.name.split(".")[0])
                if a.name.split(".")[0] in PERSIST: persist.add(a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom) and n.module and n.module.split(".")[0] in SIDE: side.add(n.module.split(".")[0])
        elif isinstance(n, ast.Call):
            fn = n.func; nm = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
            if nm in SIDE_CALLS: side.add(nm + "()")
            if nm in ("dump", "dumps") and isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.value.id in ("json", "pickle"): persist.add(fn.value.id + "." + nm)
        elif isinstance(n, ast.ExceptHandler):
            body = n.body
            if len(body) == 1 and (isinstance(body[0], ast.Pass) or (isinstance(body[0], ast.Return) and isinstance(body[0].value, ast.Constant) and body[0].value.value in (True, None))): failopen += 1
    return public, sorted(side), sorted(persist), failopen


def tests_for(paths):
    mods = set()
    for p in paths:
        if p.endswith(".py"): mods.add(p[:-3].replace("/", ".").removesuffix(".__init__"))
        elif os.path.isdir(os.path.join(ROOT, p)): mods.add(p.replace("/", "."))
    found = set()
    for dp, dn, fs in os.walk(os.path.join(ROOT, "tests")):
        dn[:] = sorted(d for d in dn if d != "__pycache__")
        for f in sorted(fs):
            if f.endswith(".py"):
                t = open(os.path.join(dp, f), errors="ignore").read()
                if any(re.search(r"(?:from|import)\s+" + re.escape(m) + r"\b", t) for m in mods): found.add(os.path.relpath(os.path.join(dp, f), ROOT))
    return sorted(found)


def build():
    rows = []
    for mid, name, paths, role, req in M:
        files = _files(paths); loc = 0; public = set(); side = set(); persist = set(); fo = 0; bad = []
        for f in files:
            t = open(os.path.join(ROOT, f), errors="ignore").read(); loc += t.count("\n") + 1
            if f.endswith(".py"):
                try: p, s, ps, n = analyse_py(t)
                except SyntaxError: bad.append(f); continue
                public |= set(p); side |= set(s); persist |= set(ps); fo += n
        tests = tests_for([f for f in files if f.endswith(".py")])
        rows.append({"id": mid, "name": name, "paths": paths, "present": bool(files), "files": len(files), "loc": loc, "public_names": len(public), "public_sample": sorted(public)[:8], "side_effect_markers": sorted(side),
                     "persisted_state_markers": sorted(persist), "tests_importing": len(tests), "test_files_sample": tests[:5], "fail_open_syntactic_patterns": fo, "unparsable": bad, "role": role, "required_integration": req,
                     "status": "UNMAPPED" if not files else "CANDIDATE"})
    return {"modules": rows, "count": len(rows), "limits": "static heuristic; role and required_integration transcribed from the masterplan; 'CANDIDATE' means code exists, nothing about integration or review; groups with no code are UNMAPPED"}


def main(argv):
    g = build()
    if "--write" in argv: os.makedirs(os.path.dirname(OUT), exist_ok=True); open(OUT, "w").write(json.dumps(g, indent=1, sort_keys=True) + "\n"); print("written", g["count"], "groups;", sum(1 for r in g["modules"] if not r["present"]), "unmapped"); return 0
    ok = os.path.exists(OUT) and json.load(open(OUT)) == json.loads(json.dumps(g)); print("OK" if ok else "STALE: run scripts/module_inventory.py --write"); return 0 if ok else 1


if __name__ == "__main__": sys.exit(main(sys.argv[1:]))
