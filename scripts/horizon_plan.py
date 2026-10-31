#!/usr/bin/env python3
"""Deterministic plan CLI (P75-13, P75-16): plan | next | list | why-blocked | status | export-dag | render.
Reads spec/task_compiled.jsonl + spec/plan.lock and a local ledger (default .horizon/ledger.db, created on first use).
Read-only except `render`, which writes generated files atomically under a file lock. Exit codes: 0 ok, 1 not-found/blocked, 2 usage/integrity."""
from __future__ import annotations
import argparse, fcntl, json, os, sys
from collections import Counter
from pathlib import Path
ROOT = Path(os.environ.get("HORIZON_ROOT") or Path(__file__).resolve().parents[1]); sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from orchestrator.ledger import Ledger, LedgerError
from orchestrator.recovery import write_atomic

PRINC = {"sup": ("supervisor", b"cli-readonly")}                 # CLI never holds worker/verifier/external keys


def load(ledger_path: str) -> tuple[Ledger, list[dict], dict]:
    rows = [json.loads(l) for l in (ROOT / "spec/task_compiled.jsonl").read_text().splitlines() if l.strip()]
    lock = json.loads((ROOT / "spec/plan.lock").read_text())
    if len(rows) != lock["task_count"]: raise SystemExit("integrity: task count does not match plan.lock; refusing (no silent drop)")
    ids = [r["task_id"] for r in rows]
    if len(set(ids)) != len(ids): raise SystemExit("integrity: duplicate task ids")
    Path(ledger_path).parent.mkdir(parents=True, exist_ok=True)
    edges = json.loads((ROOT / "spec/dependencies.yaml").read_text())                 # file is JSON-formatted YAML
    edges = edges["edges"] if isinstance(edges, dict) else edges
    inputs = sorted({e["from"] for e in edges if e["to"] == "PHASE:RC-R"}, key=lambda g: int(g.split(":P")[1]))
    if not inputs: raise SystemExit("integrity: no RC-R input gates found in dependencies.yaml")
    with open(str(ledger_path) + ".init.lock", "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)                       # serialise first-time initialisation and the RC-R write across processes
        led = Ledger(ledger_path, PRINC)
        if not led.db.execute("SELECT 1 FROM plan WHERE k='digest'").fetchone():
            led.load_plan(rows, lock)
        elif led.plan_digest() != lock["plan_digest_sha256"]:
            raise SystemExit("integrity: ledger was initialised from a different plan digest; reconcile explicitly")
        led.set_rcr_inputs(inputs)
    return led, rows, lock


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="horizon-plan"); ap.add_argument("--ledger", default=str(ROOT / ".horizon/ledger.db"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("plan"); sub.add_parser("next"); sub.add_parser("status"); sub.add_parser("export-dag").add_argument("--format", choices=["json", "dot"], default="json")
    ls = sub.add_parser("list"); ls.add_argument("--phase", type=int); ls.add_argument("--state")
    sub.add_parser("why-blocked").add_argument("task"); rd = sub.add_parser("render"); rd.add_argument("--out", default=str(ROOT / "docs/implementation/generated"))
    a = ap.parse_args(argv)
    led, rows, lock = load(a.ledger); by = {r["task_id"]: r for r in rows}
    st = dict(led.db.execute("SELECT id,status FROM tasks"))
    if a.cmd == "plan":
        print(json.dumps({"spec_sha256": lock["spec_sha256"], "plan_digest": lock["plan_digest_sha256"], "tasks": len(rows),
                          "phases": len({r["phase"] for r in rows}), "reviewed": lock["reviewed"], "scheduling_enabled": lock["scheduling_enabled"],
                          "edges_signed": lock["edge_count"]}, indent=1)); return 0
    if a.cmd == "next":
        e = led.eligible(); print("\n".join(e) if e else "(none eligible)"); return 0 if e else 1
    if a.cmd == "list":
        for tid in sorted(by):
            if (a.phase is None or by[tid]["phase"] == a.phase) and (a.state is None or st[tid] == a.state):
                print(f"{tid}\t{st[tid]}\t{by[tid]['description'][:90]}")
        return 0
    if a.cmd == "why-blocked":
        if a.task not in by: print(f"unknown task {a.task}", file=sys.stderr); return 1
        w = led.why_blocked(a.task); print("\n".join(w) if w else "not blocked by dependencies"); return 1 if w else 0
    if a.cmd == "status":
        print(json.dumps(dict(sorted(Counter(st.values()).items())), indent=1)); return 0
    if a.cmd == "export-dag":
        edges = sorted({(r["task_id"], g) for r in rows for g in r["depends_on"]})
        gates = sorted({g for _, g in edges}); phases = sorted({r["phase"] for r in rows})
        if a.format == "dot":
            print("digraph plan {"); [print(f'  "{g}" -> "P{ph}";') for ph in phases for g in sorted({x for r in rows if r["phase"] == ph for x in r["depends_on"]})]; print("}")
        else:
            print(json.dumps({"phases": phases, "gates": gates, "phase_edges": sorted({(g, f"P{r['phase']}") for r in rows for g in r["depends_on"]}), "task_edges": len(edges)}))
        return 0
    if a.cmd == "render":
        out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
        with open(out / ".lock", "w") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)                                   # serialise concurrent renderers (no racing writers)
            cnt = Counter(st.values()); blocked = {t: led.why_blocked(t) for t in sorted(by) if st[t] == "PENDING"}
            first = [(t, w) for t, w in blocked.items() if w][:20]
            write_atomic(out / "LEDGER_STATUS.md", "# Ledger status (generated; do not edit)\n\nplan `" + lock["plan_digest_sha256"][:16] + "…`\n\n" +
                         "\n".join(f"- {k}: {v}" for k, v in sorted(cnt.items())) + "\n")
            write_atomic(out / "LEDGER_BLOCKERS.md", "# Blocked tasks (generated; first 20)\n\n" + "\n".join(f"- {t}: {'; '.join(w)}" for t, w in first) + "\n")
        print(f"wrote {out}"); return 0


if __name__ == "__main__":
    try: raise SystemExit(main())
    except LedgerError as e: print(f"ledger error: {e}", file=sys.stderr); raise SystemExit(2)
