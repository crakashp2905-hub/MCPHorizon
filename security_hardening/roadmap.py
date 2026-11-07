"""Blueprint roadmap tracker rules (blueprint S0-04/S0-06). CANDIDATE.
The checker REFUSES any record that claims more than the evidence supports: statuses are only OPEN / CANDIDATE / BLOCKED; GATE tasks can never be CANDIDATE
(a gate is an independent reviewer's act); a CANDIDATE needs existing evidence files whose sha256 matches; BLOCKED names its external dependency.
No status named like an independent or hardened level is accepted. The agent cannot promote anything by editing this file: the rules live here and are mutation-tested."""
from __future__ import annotations
import hashlib, json, os, re

STATUSES = ("OPEN", "CANDIDATE", "BLOCKED")
TASK = re.compile(r"^- \[[ xX]\] (S\d-(?:\d\d|GATE))\s+(.*\S)\s*$")
LEVELS = ("IMPLEMENTED", "INTEGRATED", "ADVERSARIAL_TESTED", "INDEPENDENTLY_VERIFIED", "UNSUPPORTED")   # S0-06 vocabulary; only CANDIDATE evidence exists, so the last-but-one is always 0
SHA = re.compile(r"[0-9a-f]{64}")


def sha(path):
    with open(path, "rb") as f: return hashlib.sha256(f.read()).hexdigest()


def parse_doc(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        m = TASK.match(line)
        if m:
            if m.group(1) in out: raise ValueError("duplicate task " + m.group(1))
            out[m.group(1)] = m.group(2)
    if not out: raise ValueError("no tasks parsed")
    return out


def problems(doc_tasks: dict, status: dict, root: str, doc_sha: str) -> list:
    p = []
    if status.get("doc_sha256") != doc_sha: p.append("DOC_DIGEST_MISMATCH")
    tasks = status.get("tasks")
    if not isinstance(tasks, dict): return p + ["NO_TASKS"]
    for t in sorted(set(doc_tasks) - set(tasks)): p.append(f"UNTRACKED:{t}")
    for t in sorted(set(tasks) - set(doc_tasks)): p.append(f"NOT_IN_DOC:{t}")
    for t, r in tasks.items():
        if t not in doc_tasks: continue
        if not isinstance(r, dict) or set(r) - {"status", "evidence", "blocked_by", "note"}: p.append(f"BAD_RECORD:{t}"); continue
        s = r.get("status")
        if s not in STATUSES: p.append(f"BAD_STATUS:{t}"); continue
        if t.endswith("-GATE") and s == "CANDIDATE": p.append(f"GATE_CANNOT_BE_CANDIDATE:{t}")
        if s == "CANDIDATE":
            ev = r.get("evidence")
            if not (isinstance(ev, dict) and ev): p.append(f"NO_EVIDENCE:{t}"); continue
            for path, d in ev.items():
                full = os.path.realpath(os.path.join(root, path))
                if not full.startswith(os.path.realpath(root) + os.sep) or not os.path.isfile(full): p.append(f"EVIDENCE_MISSING:{t}:{path}")
                elif not (isinstance(d, str) and SHA.fullmatch(d)) or sha(full) != d: p.append(f"EVIDENCE_STALE:{t}:{path}")
            if not (isinstance(r.get("note"), str) and r["note"].strip()): p.append(f"NO_LIMITS_NOTE:{t}")
        if s == "BLOCKED" and not (isinstance(r.get("blocked_by"), str) and r["blocked_by"].strip()): p.append(f"NO_BLOCKER:{t}")
        if s == "OPEN" and (r.get("evidence") or r.get("blocked_by")): p.append(f"OPEN_WITH_CLAIMS:{t}")
    return p


def report(doc_tasks: dict, status: dict) -> str:
    c = {s: 0 for s in STATUSES}
    for t in doc_tasks: c[status["tasks"][t]["status"]] += 1
    lines = [f"# Blueprint roadmap status (generated; do not edit)", "",
             f"Tasks: {len(doc_tasks)} | OPEN {c['OPEN']} | CANDIDATE {c['CANDIDATE']} | BLOCKED {c['BLOCKED']} | INDEPENDENTLY_VERIFIED 0 (no reviewer attestation exists; not claimable by the author)", "",
             "CANDIDATE = author-run implementation/evidence with stated limits. It is NOT integrated, adversarially tested by others, or independently verified.", "",
             "| Task | Status | Basis |", "|---|---|---|"]
    for t, text in doc_tasks.items():
        r = status["tasks"][t]; basis = r.get("note") or r.get("blocked_by") or ""
        lines.append(f"| {t} {text[:70].replace('|', '/')} | {r['status']} | {basis[:160].replace('|', '/')} |")
    return "\n".join(lines) + "\n"
