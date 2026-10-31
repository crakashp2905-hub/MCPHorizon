#!/usr/bin/env python3
"""P83 typed task-contract compiler and validator (stdlib only).

Compiles docs/MCPHORIZON_2_0_MASTER_SPEC.md into:
  spec/task_compiled.jsonl   one TaskSpec per task (source span + extraction confidence)
  spec/dependencies.yaml     explicit phase/gate edges (JSON, which is valid YAML) with citations
  spec/plan.lock             pinned digests; `reviewed` is false until a human signs it
It NEVER marks anything VERIFIED, never infers task-level edges, and refuses scheduling
use of unreviewed edges (every edge carries review_status; unsigned = NEEDS_REVIEW).
Commands: compile | validate | diff | explain-dependencies | critical-path | export-plan
"""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from collections import defaultdict, deque
from pathlib import Path

SCHEMA_VERSION = "1.0.0"
EXPECTED_TASKS = 1686
EXPECTED_PHASES = set(range(95))
TASK_LINE = re.compile(r"^- \[( |x)\] \*\*(P(\d{1,2})-(\d{2}))\*\*\s*(.*)$")
ANY_TASK_REF = re.compile(r"^- \[.\] \*\*P\d")
WORK_CLASSES = {"CODE", "EXPERIMENT", "EXTERNAL", "DECISION", "LIVE_EFFECT"}
STATES = {"PENDING", "READY", "LEASED", "RUNNING", "VERIFYING", "VERIFIED", "RETRY_WAIT",
          "WAITING_EXTERNAL", "NEEDS_APPROVAL", "NEEDS_RECONCILIATION", "BLOCKED_SECURITY",
          "REJECTED", "NOT_APPLICABLE_APPROVED", "NEEDS_REVALIDATION"}
ORACLES = {"sandbox_effect_log:v1", "pytest", "schema_validation", "manual_signed_review",
           "external_signature", "none_declared"}

# Explicit edges: (from_phase_or_gate, to_phase_or_gate, spec citation, extraction confidence).
# Edge "A -> B" means B cannot start until A's gate (all tasks verified) passes.
RANGE = lambda a, b: [f"P{i}" for i in range(a, b + 1)]
PHASE_EDGES = [
    ("P0", "P1", "§19 mermaid", "high"), ("P1", "P2", "§19 mermaid", "high"),
    ("P2", "P3", "§19 mermaid", "high"), ("P3", "P4", "§19 mermaid", "high"),
    ("P3", "P5", "§19 mermaid", "high"), ("P3", "P6", "§19 mermaid", "high"),
    ("P4", "P7", "§19 mermaid", "high"), ("P5", "P7", "§19 mermaid", "high"),
    ("P6", "P7", "§19 mermaid", "high"), ("P7", "P8", "§19 mermaid", "high"),
    ("P8", "P9", "§19 mermaid", "high"), ("P9", "P11", "§19 mermaid", "high"),
    ("P7", "P10", "§19 mermaid", "high"), ("P10", "P11", "§19 mermaid", "high"),
    ("P11", "P12", "§19 mermaid", "high"),
    ("P0", "P83", "§132.2(1-2) P83 starts after P0", "high"),
    ("P83", "P75", "§119/§132.2(2) P83 before P75 ledger migration", "high"),
    ("P83", "P76", "§132.2(3) supervisor primitives follow canonical plan", "medium"),
    ("P83", "P77", "§132.2(3) supervisor primitives follow canonical plan", "medium"),
    ("P75", "P84", "§132.2(3) P84/P85 before workers trusted", "medium"),
    ("P77", "P85", "§119 example: P94-04 depends on P77-18/P85-18", "medium"),
    ("P84", "P86", "§132.2(3) P86 tests before full campaign", "medium"),
    ("P85", "P86", "§132.2(3) P86 tests before full campaign", "medium"),
    ("P75", "P78", "§132.2(3) P78-P82 after supervisor primitives", "low"),
    ("P85", "P94", "§119 example P94-04 depends on P85-18", "high"),
    ("P77", "P94", "§119 example P94-04 depends on P77-18", "high"),
    ("P83", "P94", "§119 example P94-04 depends on P83-18", "high"),
]
# Research phases with no documented ordering are only anchored to P0 (AGENTS.md step 1).
ANCHOR_P0 = RANGE(13, 54) + RANGE(87, 93) + [f"P{i}" for i in (1,)]  # P1 already via §19
RCR_INPUTS = RANGE(1, 54) + RANGE(87, 94)
RCR_CITE = "AGENTS.md step 1 / §104 ('DO NOT START P55+ WITHOUT EVIDENCE OF RC-R'); §5380 RC-R definition"
PRODUCT = RANGE(55, 74)

CLASS_RULES = [  # heuristic, low confidence, always NEEDS_REVIEW
    ("EXTERNAL", r"\b(external (audit|reviewer|signator)|pilot customer|customer|design partner|legal|counsel|certif|sign-?off|signed|auditor|SOC ?2|ISO ?27001|penetration test by|third-party audit)\b"),
    ("LIVE_EFFECT", r"\b(live|production|deploy|publish|release to|real (provider|account)|spend|payment|billing)\b"),
    ("EXPERIMENT", r"\b(experiment|benchmark|ablation|hypothes|measure|run .*trials|dataset|statistic|power analysis|replicat|evaluate|evaluation)\b"),
    ("DECISION", r"\b(decide|decision|go/no-go|approve|choose|select|adjudicat|triage)\b"),
]
HIGH_RISK = re.compile(r"\b(credential|secret|token|exfil|sandbox|isolat|enforce|verifier|policy|attest|sign|key|privilege|supervisor)\b", re.I)


def sha(s: str | bytes) -> str:
    return hashlib.sha256(s.encode() if isinstance(s, str) else s).hexdigest()


def classify(desc: str) -> tuple[str, str]:
    for cls, pat in CLASS_RULES:
        if re.search(pat, desc, re.I):
            return cls, "low"
    return "CODE", "low"


def parse_spec(text: str) -> list[dict]:
    lines = text.splitlines()
    tasks, seen = [], set()
    heading = ""
    for n, line in enumerate(lines, 1):
        if line.startswith("#"):
            heading = line.lstrip("# ").strip()
        if ANY_TASK_REF.match(line):
            m = TASK_LINE.match(line)
            if not m or not m.group(5).strip():
                raise ValueError(f"line {n}: malformed or truncated task definition: {line[:80]!r}")
            tid, ph, num, desc = m.group(2), int(m.group(3)), int(m.group(4)), m.group(5).strip()
            if tid in seen:
                raise ValueError(f"duplicate task id {tid} (line {n})")
            seen.add(tid)
            tasks.append({"id": tid, "phase": ph, "ordinal": num, "description": desc,
                          "source_line": n, "source_section": heading, "checked_in_source": m.group(1) == "x"})
    if len(tasks) != EXPECTED_TASKS:
        raise ValueError(f"expected {EXPECTED_TASKS} tasks, found {len(tasks)}")
    if {t["phase"] for t in tasks} != EXPECTED_PHASES:
        raise ValueError("phase set differs from P0..P94")
    for ph in EXPECTED_PHASES:
        nums = sorted(t["ordinal"] for t in tasks if t["phase"] == ph)
        if nums != list(range(1, len(nums) + 1)):
            raise ValueError(f"invalid ordinals in P{ph}")
    return tasks


def build_edges() -> list[dict]:
    edges = [{"from": f"GATE:{a}", "to": f"GATE:{b}" if False else f"PHASE:{b}", "citation": c,
              "confidence": conf, "review_status": "NEEDS_REVIEW", "signed_by": None}
             for a, b, c, conf in PHASE_EDGES]
    for p in ANCHOR_P0:
        if p != "P1":
            edges.append({"from": "GATE:P0", "to": f"PHASE:{p}", "citation": "AGENTS.md step 1 (start with P0 audit)",
                          "confidence": "medium", "review_status": "NEEDS_REVIEW", "signed_by": None})
    for p in RCR_INPUTS:
        edges.append({"from": f"GATE:{p}", "to": "PHASE:RC-R", "citation": RCR_CITE,
                      "confidence": "medium", "review_status": "NEEDS_REVIEW", "signed_by": None})
    for p in PRODUCT:
        edges.append({"from": "GATE:RC-R", "to": f"PHASE:{p}", "citation": RCR_CITE,
                      "confidence": "high", "review_status": "NEEDS_REVIEW", "signed_by": None})
    return edges


def gate_nodes(edges: list[dict]) -> set[str]:
    return {e["from"] for e in edges} | {e["to"] for e in edges}


def compile_plan(spec_path: Path, outdir: Path) -> dict:
    text = spec_path.read_text(encoding="utf-8")
    spec_sha = sha(text)
    tasks = parse_spec(text)
    edges = build_edges()
    preds: dict[str, list[str]] = defaultdict(list)  # phase node -> gate prerequisites
    for e in edges:
        preds[e["to"]].append(e["from"])
    outdir.mkdir(parents=True, exist_ok=True)
    rows = []
    for t in tasks:
        cls, conf = classify(t["description"])
        dh = sha(t["id"] + "\n" + t["description"])
        rows.append({
            "task_id": t["id"], "schema_version": SCHEMA_VERSION, "spec_revision_sha256": spec_sha,
            "description": t["description"], "description_hash": dh, "phase": t["phase"],
            "work_class": cls, "risk_tier": "high" if HIGH_RISK.search(t["description"]) else "medium",
            "priority": None, "depends_on": sorted(set(preds.get(f"PHASE:P{t['phase']}", []))),
            "dependency_review_status": "NEEDS_REVIEW",
            "produces": None, "consumes": None, "changed_path_allowlist": None,
            "secrets_policy": "no-live-credentials", "network_policy": "none-by-default",
            "provider_policy": "approved-local-or-sanitized",
            "expected_compute_budget": None, "expected_monetary_budget": None,
            "owner_role": "unassigned", "acceptance_gates": [], "verifier_profile": None,
            "evidence_schema": None, "negative_controls": None, "timeout": None, "retry_class": None,
            "external_blocker": "external_dependency_possible" if cls == "EXTERNAL" else None,
            "status": "PENDING", "last_verified_revision": None,
            "source": {"line": t["source_line"], "section": t["source_section"]},
            "extraction_confidence": {"description": "exact", "work_class": conf, "depends_on": "phase-level only",
                                      "unspecified_fields": "null = not extractable from prose; needs reviewer"},
        })
    with open(outdir / "task_compiled.jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    deps = {"schema_version": SCHEMA_VERSION, "note": "JSON syntax (valid YAML). Edges are gate-level; "
            "task-level edges are NOT inferred. All edges NEEDS_REVIEW until signed.",
            "gates": {"RC-R": {"requires_external_signature": True,
                               "description": "Research-to-product release candidate; cannot be synthesized by an agent."}},
            "edges": edges}
    (outdir / "dependencies.yaml").write_text(json.dumps(deps, indent=1, sort_keys=True))
    (outdir / "overrides.yaml").write_text(json.dumps({"overrides": []}, indent=1))
    manifest_digest = sha("".join(sha(json.dumps(r, sort_keys=True)) for r in rows) + sha(json.dumps(deps, sort_keys=True)))
    lock = {"schema_version": SCHEMA_VERSION, "spec_path": str(spec_path), "spec_sha256": spec_sha,
            "task_count": len(rows), "edge_count": len(edges), "plan_digest_sha256": manifest_digest,
            "reviewed": False, "reviewer_signature": None,
            "scheduling_enabled": False,
            "reason": "Dependencies are unreviewed; P83-06/P83-16 require an authorized maintainer signature."}
    (outdir / "plan.lock").write_text(json.dumps(lock, indent=2, sort_keys=True))
    (outdir / "task_schema.json").write_text(json.dumps(task_schema(), indent=2))
    return lock


def task_schema() -> dict:
    str_or_null = {"type": ["string", "null"]}
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "MCPHorizon TaskSpec",
            "type": "object", "additionalProperties": True,
            "required": ["task_id", "schema_version", "spec_revision_sha256", "description_hash", "phase",
                         "work_class", "risk_tier", "depends_on", "status", "extraction_confidence", "source"],
            "properties": {"task_id": {"type": "string", "pattern": r"^P\d{1,2}-\d{2}$"},
                           "spec_revision_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                           "description_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                           "phase": {"type": "integer", "minimum": 0, "maximum": 94},
                           "work_class": {"enum": sorted(WORK_CLASSES)},
                           "risk_tier": {"enum": ["low", "medium", "high", "critical"]},
                           "depends_on": {"type": "array", "items": {"type": "string"}},
                           "status": {"enum": sorted(STATES)}, "owner_role": str_or_null,
                           "acceptance_gates": {"type": "array"}, "last_verified_revision": str_or_null}}


def load(specdir: Path):
    rows = [json.loads(l) for l in (specdir / "task_compiled.jsonl").read_text().splitlines() if l.strip()]
    deps = json.loads((specdir / "dependencies.yaml").read_text())
    lock = json.loads((specdir / "plan.lock").read_text())
    return rows, deps, lock


def detect_cycle(nodes: set[str], edges: list[tuple[str, str]]) -> list[str] | None:
    adj, indeg = defaultdict(list), {n: 0 for n in nodes}
    for a, b in edges:
        adj[a].append(b)
        indeg[b] += 1
    q = deque(n for n, d in indeg.items() if d == 0)
    seen = 0
    while q:
        n = q.popleft(); seen += 1
        for m in adj[n]:
            indeg[m] -= 1
            if indeg[m] == 0:
                q.append(m)
    return sorted(n for n, d in indeg.items() if d > 0) or None if seen != len(nodes) else None


def validate(specdir: Path, spec_path: Path | None = None) -> list[str]:
    errs: list[str] = []
    rows, deps, lock = load(specdir)
    ids = [r["task_id"] for r in rows]
    if len(ids) != len(set(ids)):
        errs.append("duplicate task ids in compiled manifest")
    if len(rows) != lock.get("task_count"):
        errs.append(f"task_count mismatch: lock={lock.get('task_count')} actual={len(rows)}")
    if spec_path:
        text = spec_path.read_text(encoding="utf-8")
        if sha(text) != lock["spec_sha256"]:
            errs.append("spec digest differs from plan.lock (spec changed; new plan revision required)")
        try:
            src = {t["id"]: t for t in parse_spec(text)}
        except ValueError as e:
            errs.append(f"spec parse failure: {e}"); src = {}
        for r in rows:
            s = src.get(r["task_id"])
            if s is None:
                errs.append(f"{r['task_id']}: orphan ID not present in spec")
            elif sha(s["id"] + "\n" + s["description"]) != r["description_hash"]:
                errs.append(f"{r['task_id']}: wrong description digest")
        for tid in set(src) - set(ids):
            errs.append(f"{tid}: missing from compiled manifest")
    expected_ph = {f"P{i}" for i in EXPECTED_PHASES}
    gates = {e["from"] for e in deps["edges"]}
    for r in rows:
        if r["work_class"] not in WORK_CLASSES: errs.append(f"{r['task_id']}: bad work_class")
        if r["status"] not in STATES: errs.append(f"{r['task_id']}: bad status")
        if r["status"] == "VERIFIED" and not r.get("last_verified_revision"):
            errs.append(f"{r['task_id']}: VERIFIED without last_verified_revision")
        if r["task_id"] in r["depends_on"]: errs.append(f"{r['task_id']}: self-dependency")
        for d in r["depends_on"]:
            if d not in gates and d not in set(ids):
                errs.append(f"{r['task_id']}: unknown prerequisite {d}")
        if r["phase"] in range(55, 75) and "GATE:RC-R" not in r["depends_on"]:
            errs.append(f"{r['task_id']}: product task missing machine-checkable RC-R gate")
    nodes = gate_nodes(deps["edges"])
    for e in deps["edges"]:
        for end in (e["from"], e["to"]):
            base = end.split(":", 1)[1]
            if base != "RC-R" and base not in expected_ph:
                errs.append(f"edge references unknown phase/gate {end}")
    edge_pairs = [(("GATE:" + e["to"].split(":")[1]) if e["to"].startswith("PHASE:") else e["to"], e["from"]) for e in deps["edges"]]
    # cycle check on gate graph: GATE:X -> GATE:Y when an edge feeds phase Y
    gate_edges = [(e["from"], "GATE:" + e["to"].split(":", 1)[1]) for e in deps["edges"]]
    cyc = detect_cycle({n for ab in gate_edges for n in ab}, gate_edges)
    if cyc: errs.append(f"dependency cycle among: {cyc}")
    for e in gate_edges:
        if e[0] == e[1]: errs.append(f"self-dependency edge {e[0]}")
    if lock.get("scheduling_enabled") and not (lock.get("reviewed") and lock.get("reviewer_signature")):
        errs.append("scheduling enabled without reviewed plan and reviewer signature")
    unreviewed = [e for e in deps["edges"] if e["review_status"] != "SIGNED"]
    if lock.get("reviewed") and unreviewed:
        errs.append(f"plan marked reviewed but {len(unreviewed)} edges are unsigned")
    return errs


def diff(old: Path, new: Path) -> list[str]:
    a = {json.loads(l)["task_id"]: json.loads(l) for l in old.read_text().splitlines() if l.strip()}
    b = {json.loads(l)["task_id"]: json.loads(l) for l in new.read_text().splitlines() if l.strip()}
    out = [f"REMOVED {t}" for t in sorted(set(a) - set(b))] + [f"ADDED {t}" for t in sorted(set(b) - set(a))]
    for t in sorted(set(a) & set(b)):
        if a[t]["description_hash"] != b[t]["description_hash"]:
            out.append(f"CHANGED-DESCRIPTION {t}")
        if a[t]["status"] == "VERIFIED" and b[t]["status"] != "VERIFIED":
            out.append(f"SILENT-STATUS-RESET {t}: VERIFIED -> {b[t]['status']} (needs NEEDS_REVALIDATION + reason)")
    return out


def phase_graph(deps):
    ph = defaultdict(set)
    for e in deps["edges"]:
        ph[e["to"].split(":", 1)[1]].add(e["from"].split(":", 1)[1])
    return ph


def explain(specdir: Path, phase: str) -> list[str]:
    _, deps, _ = load(specdir)
    g = phase_graph(deps)
    out, seen, stack = [], set(), [phase]
    while stack:
        p = stack.pop()
        for q in sorted(g.get(p, [])):
            cite = next(e for e in deps["edges"] if e["from"] == f"GATE:{q}" and e["to"] == f"PHASE:{p}")
            out.append(f"{q} -> {p}  [{cite['confidence']}, {cite['review_status']}] {cite['citation']}")
            if q not in seen: seen.add(q); stack.append(q)
    return out


def critical_path(specdir: Path, target: str) -> list[str]:
    rows, deps, _ = load(specdir)
    size = defaultdict(int)
    for r in rows: size[f"P{r['phase']}"] += 1
    g = phase_graph(deps)
    memo: dict[str, tuple[int, list[str]]] = {}
    def best(p):
        if p in memo: return memo[p]
        cands = [best(q) for q in g.get(p, [])]
        w, path = max(cands, default=(0, []))
        memo[p] = (w + size.get(p, 0), path + [p]); return memo[p]
    w, path = best(target)
    return [f"{p} ({size.get(p,0)} tasks)" for p in path] + [f"total tasks on longest chain: {w}"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("compile", "validate", "export-plan"):
        p = sub.add_parser(name); p.add_argument("--spec", type=Path, default=Path("docs/MCPHORIZON_2_0_MASTER_SPEC.md"))
        p.add_argument("--out", type=Path, default=Path("spec"))
    d = sub.add_parser("diff"); d.add_argument("old", type=Path); d.add_argument("new", type=Path)
    e = sub.add_parser("explain-dependencies"); e.add_argument("phase"); e.add_argument("--out", type=Path, default=Path("spec"))
    ap_ = sub.add_parser("approve", help="record a human maintainer's approval of all gate edges")
    ap_.add_argument("--out", type=Path, default=Path("spec")); ap_.add_argument("--approver", required=True)
    ap_.add_argument("--basis", required=True, help="how approval was given, e.g. 'chat message 2026-10-31, not line-by-line'")
    c = sub.add_parser("critical-path"); c.add_argument("target"); c.add_argument("--out", type=Path, default=Path("spec"))
    a = ap.parse_args(argv)
    try:
        if a.cmd == "compile":
            print(json.dumps(compile_plan(a.spec, a.out), indent=2))
        elif a.cmd == "validate":
            errs = validate(a.out, a.spec)
            print("\n".join(errs) if errs else f"OK: plan valid ({EXPECTED_TASKS} tasks). Edges signed: {sum(1 for e in json.loads((a.out / "dependencies.yaml").read_text())["edges"] if e["review_status"]=="SIGNED")}.")
            return 1 if errs else 0
        elif a.cmd == "approve":
            import datetime
            rows, deps, lock = load(a.out)
            stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            for e in deps["edges"]:
                e["review_status"], e["signed_by"] = "SIGNED", a.approver
            (a.out / "dependencies.yaml").write_text(json.dumps(deps, indent=1, sort_keys=True))
            lock.update(reviewed=True, scheduling_enabled=True, reason="Approved by human maintainer; see reviewer_signature.",
                        reviewer_signature={"approver": a.approver, "basis": a.basis, "time_utc": stamp,
                                            "plan_digest_before_approval": lock["plan_digest_sha256"],
                                            "cryptographic": False})
            (a.out / "plan.lock").write_text(json.dumps(lock, indent=2, sort_keys=True))
            print(json.dumps(lock, indent=2))
        elif a.cmd == "diff":
            r = diff(a.old, a.new); print("\n".join(r) if r else "no differences"); return 1 if any("SILENT" in x or "REMOVED" in x for x in r) else 0
        elif a.cmd == "explain-dependencies":
            print("\n".join(explain(a.out, a.phase)))
        elif a.cmd == "critical-path":
            print("\n".join(critical_path(a.out, a.target)))
        elif a.cmd == "export-plan":
            lock = json.loads((a.out / "plan.lock").read_text())
            rows, deps, _ = load(a.out)
            print(json.dumps({"lock": lock, "phases": sorted({r["phase"] for r in rows}),
                              "edges": len(deps["edges"])}, indent=2))
    except (ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr); return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
