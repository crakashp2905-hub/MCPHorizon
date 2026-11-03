"""Idea 6: revocation-vs-commit race benchmark. EXHAUSTIVE enumeration of interleavings of a tiny step model (not a measurement of a real system). Designs:
NAIVE (check, then act as separate steps), ATOMIC (check+act under one linearization point), EPOCH_FENCED (act carries the epoch it checked; sink rejects if revoked_epoch > carried), CHECK_AFTER (act then check: detects, cannot prevent).
A VIOLATION is an act that takes effect after the revocation step. Crash steps model a worker dying between steps."""
from __future__ import annotations
import itertools

DESIGNS = {"NAIVE": ["check", "act"], "ATOMIC": ["check_act"], "EPOCH_FENCED": ["check", "fenced_act"], "CHECK_AFTER": ["act", "check"]}


def interleavings(a: list, b: list):
    n = len(a) + len(b)
    for pos in itertools.combinations(range(n), len(a)):
        out, ai, bi = [], 0, 0
        for i in range(n):
            if i in pos: out.append(("C", a[ai])); ai += 1
            else: out.append(("R", b[bi])); bi += 1
        yield out


def evaluate(design: str) -> dict:
    steps = DESIGNS[design]; total = viol = 0; detectable = 0
    for sched in interleavings(steps, ["revoke"]):
        total += 1; revoked = False; acted = False; v = False; ok = False
        for who, st in sched:
            if who == "R": revoked = True; continue
            if design == "CHECK_AFTER":
                if st == "act": acted = True; v = v or revoked
                else: ok = not revoked
            elif st == "check": ok = not revoked
            elif st == "act":
                if ok: acted = True; v = v or revoked
            elif st == "check_act":
                if not revoked: acted = True
            elif st == "fenced_act":
                if ok and not revoked: acted = True
        viol += 1 if v else 0
        if design == "CHECK_AFTER" and v: detectable += 1
    return {"design": design, "schedules": total, "violating_schedules": viol, "detected_after_the_fact": detectable}


def crash_recovery_safe() -> bool:
    """A worker that crashes between check and act and is retried must re-check: model both retry policies. Returns True iff re-check-on-retry has no violating schedule."""
    for resume_recheck in (True, False):
        bad = 0
        for before_crash in (True, False):          # revoke happens before or after the crash
            for after_check_crash in (True,):
                revoked_at_retry = before_crash
                acted = (not resume_recheck) or (not revoked_at_retry)       # without re-check the stale pass is reused
                if acted and revoked_at_retry: bad += 1
        if resume_recheck and bad: return False
    return True
