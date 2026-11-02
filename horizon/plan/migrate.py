"""P83-10/11: revisioned task-contract migration (no silent deletion) and safe VERIFIED-receipt invalidation."""
import hashlib, json
from collections import defaultdict

H = lambda o: hashlib.sha256(json.dumps(o, sort_keys=True).encode()).hexdigest()
IMMUTABLE = ("task_id", "phase")
TERMINAL_PROTECTED = {"VERIFIED", "NOT_APPLICABLE_APPROVED", "REJECTED"}


class MigrationError(Exception): pass


def migrate(old, new, *, tombstones=(), revision):
    """old/new: lists of TaskSpec rows. Returns (rows, manifest). Refuses: removal without a tombstone,
    changed phase/ID, silent status reset, and VERIFIED rows whose description changed (-> NEEDS_REVALIDATION)."""
    o = {r["task_id"]: r for r in old}; n = {r["task_id"]: r for r in new}
    if len(n) != len(new): raise MigrationError("duplicate task ids in new plan")
    removed = sorted(set(o) - set(n)); added = sorted(set(n) - set(o))
    bad = [t for t in removed if t not in set(tombstones)]
    if bad: raise MigrationError("silent deletion refused: %s" % bad[:5])
    rows, changed, reval = [], [], []
    for t, r in n.items():
        r = dict(r)
        if t in o:
            for k in IMMUTABLE:
                if o[t][k] != r[k]: raise MigrationError("%s: %s changed (renumber refused)" % (t, k))
            if o[t]["status"] in TERMINAL_PROTECTED and r["status"] != o[t]["status"]:
                if r["status"] == "PENDING": raise MigrationError("%s: silent status reset %s->PENDING" % (t, o[t]["status"]))
            if o[t]["description_hash"] != r["description_hash"]:
                changed.append(t)
                if o[t]["status"] == "VERIFIED": r["status"] = "NEEDS_REVALIDATION"; reval.append(t)
        rows.append(r)
    man = {"revision": revision, "before_digest": H(old), "after_digest": H(rows), "added": added, "removed": removed,
           "tombstones": sorted(tombstones), "description_changed": sorted(changed), "needs_revalidation": sorted(reval),
           "counts": {"before": len(old), "after": len(rows)}}
    return rows, man


def downstream(rows, changed_ids, edges=()):
    """Transitive dependents: task-level depends_on that names a task, plus explicit (a,b) task edges."""
    rev = defaultdict(set)
    for r in rows:
        for d in r.get("depends_on", []): rev[d].add(r["task_id"])
    for a, b in edges: rev[a].add(b)
    seen, q = set(), list(changed_ids)
    while q:
        x = q.pop()
        for y in rev.get(x, ()):
            if y not in seen: seen.add(y); q.append(y)
    return seen


def invalidate(rows, receipts, changed_evidence, edges=()):
    """receipts: {task_id: {"evidence": {name: digest}, ...}}. A VERIFIED task whose own evidence digest changed, or whose
    transitive prerequisite changed, becomes NEEDS_REVALIDATION; nothing is deleted; others untouched.
    Returns (rows, report)."""
    ids = {r["task_id"] for r in rows}
    direct = {t for t, rc in receipts.items() if t in ids and any(rc["evidence"].get(k) != v for k, v in changed_evidence.items() if k in rc["evidence"])}
    hit = direct | downstream(rows, direct, edges)
    out, inval = [], []
    for r in rows:
        r = dict(r)
        if r["task_id"] in hit and r["status"] == "VERIFIED":
            r["status"] = "NEEDS_REVALIDATION"; inval.append(r["task_id"])
        out.append(r)
    return out, {"direct": sorted(direct), "invalidated": sorted(inval), "unaffected_verified": sorted(r["task_id"] for r in out if r["status"] == "VERIFIED")}
