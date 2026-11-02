"""P83-01/02/09: inventory, pinned source-span map, historical-reference check. Stdlib only."""
import hashlib, json, os, re

H = lambda b: hashlib.sha256(b if isinstance(b, bytes) else b.encode()).hexdigest()
TASK = re.compile(r"^- \[[ x]\] \*\*(P\d{1,2}-\d{2})\*\*")
GATE = re.compile(r"^#{2,4} .*\b(Gate|GATE|RC-R|CG-\d\d|PG-\d\d|ES-G\d+)\b")
PATHREF = re.compile(r"`((?:results|docs|bench|horizon|scripts|tests|spec|paper|replication|schemas)/[A-Za-z0-9_./*-]+)`")


def span_map(spec_text):
    """Return {sha, tasks:{id:{start,end,sha}}, gates:[{line,title,sha}]} with 1-based inclusive lines.
    A task span ends at the line before the next task/heading; spans never overlap."""
    lines = spec_text.split("\n"); tasks = {}; heads = []
    for i, l in enumerate(lines):
        m = TASK.match(l)
        if m:
            if m.group(1) in tasks: raise ValueError("duplicate task id %s" % m.group(1))
            tasks[m.group(1)] = [i, None]
        if m or l.startswith("#"): heads.append(i)
    heads.append(len(lines))
    out = {}
    for tid, (s, _) in tasks.items():
        e = min(h for h in heads if h > s)
        out[tid] = {"start": s + 1, "end": e, "sha256": H("\n".join(lines[s:e]))}
    gates = []
    for i, l in enumerate(lines):
        if GATE.match(l):
            e = min(h for h in heads if h > i); gates.append({"line": i + 1, "title": l.lstrip("# ").strip(), "end": e, "sha256": H("\n".join(lines[i:e]))})
    return {"spec_sha256": H(spec_text), "tasks": out, "gates": gates}


def check_span_map(sm, spec_text):
    """Re-derive and compare; returns list of problems (empty = pinned map matches the spec exactly)."""
    cur = span_map(spec_text); errs = []
    if cur["spec_sha256"] != sm["spec_sha256"]: errs.append("spec digest differs")
    for t in set(sm["tasks"]) | set(cur["tasks"]):
        a, b = sm["tasks"].get(t), cur["tasks"].get(t)
        if a is None: errs.append("%s: not in pinned map" % t)
        elif b is None: errs.append("%s: missing from spec" % t)
        elif a != b: errs.append("%s: span or digest changed" % t)
    if sm["gates"] != cur["gates"]: errs.append("gate spans differ")
    return errs


def history_refs(spec_text, root):
    """P83-09: referenced repo paths per task; classify exists/missing honestly (globs: any match)."""
    import glob
    res = {}
    for tid, sp in span_map(spec_text)["tasks"].items():
        body = "\n".join(spec_text.split("\n")[sp["start"] - 1:sp["end"]])
        refs = sorted(set(PATHREF.findall(body)))
        if refs:
            res[tid] = {r: ("present" if glob.glob(os.path.join(root, r)) else "MISSING") for r in refs}
    return res
