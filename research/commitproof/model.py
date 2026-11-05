"""Bounded EXHAUSTIVE model of the effect-commit protocol (CANDIDATE; a model, not the implementation).

Scope: ONE effect with ONE permit (one nonce), N workers (default 3: the legitimate dispatcher plus replayers/zombies), one ledger, one sink.
Every interleaving of worker steps, crashes, recovery and reconciliation is explored (BFS over all reachable states), and four invariants are
checked in EVERY reachable state.  Designs are parameters, so BASELINE designs can be shown to violate the invariants (shortest counterexample
trace returned) while the proposed design satisfies them within the bounds.  Not modelled: multiple effects, permit-to-effect binding (covered by
commit_verify tests), clocks, ledger/sink data loss, a malicious sink, byzantine workers that bypass the sink (OS separation, tests/e06).
"""
from __future__ import annotations
from collections import deque

# worker pcs
IDLE, AUTHED, STARTED, WROTE, DONE, DEAD = "IDLE", "AUTHED", "STARTED", "WROTE", "DONE", "DEAD"
# ledger states
NONE, AUTH, LSTART, COMMITTED, UNKNOWN, REC_C, REC_B, BLOCKED = "NONE", "AUTHORIZED", "STARTED", "COMMITTED", "UNKNOWN", "RECONCILED_COMMITTED", "RECONCILED_BLOCKED", "BLOCKED"

DESIGNS = {
    # proposed: shared atomic nonce+state ledger, recovery only after owner death, sink-side atomic fence-and-observe on reconcile
    "proposed": dict(shared_ledger=True, recover="after_death", fenced=True, retry_unknown=False, retry_started=False, expire_auth=True),
    # proposed but recovery may fire on a TIMEOUT while the owner is alive (zombie) -> needs the fence
    # proposed minus orphan-expiry: permit consumed, authorizer died before begin -> ledger stuck AUTHORIZED forever (safe but unresolved)
    # orphan expiry that may fire while the authorizer is still alive (a TTL): safe because begin() is an atomic compare-and-set
    "proposed_expiry_any_time": dict(shared_ledger=True, recover="timeout", fenced=True, retry_unknown=False, retry_started=False, expire_auth="any"),
    "proposed_no_orphan_expiry": dict(shared_ledger=True, recover="after_death", fenced=True, retry_unknown=False, retry_started=False, expire_auth=False),
    "proposed_timeout_recovery": dict(shared_ledger=True, recover="timeout", fenced=True, retry_unknown=False, retry_started=False, expire_auth=True),
    # baselines (each removes exactly one safeguard)
    "no_fence_timeout_recovery": dict(shared_ledger=True, recover="timeout", fenced=False, retry_unknown=False, retry_started=False, expire_auth=True),
    "no_fence_after_death": dict(shared_ledger=True, recover="after_death", fenced=False, retry_unknown=False, retry_started=False, expire_auth=True),
    "retry_from_unknown": dict(shared_ledger=True, recover="after_death", fenced=True, retry_unknown=True, retry_started=False, expire_auth=True),
    "retry_on_timeout": dict(shared_ledger=True, recover="after_death", fenced=True, retry_unknown=False, retry_started=True, expire_auth=True),
    "per_worker_nonce": dict(shared_ledger=False, recover="after_death", fenced=True, retry_unknown=False, retry_started=False, expire_auth=True),
}


def initial(n):
    # (ledger_state, nonce_used, owner, sink_count, sink_fenced, workers)
    return (NONE, False, -1, 0, False, tuple([IDLE] * n))


def _set(ws, i, v): return ws[:i] + (v,) + ws[i + 1:]


def successors(s, d):
    L, used, owner, c, fenced, ws = s
    out = []
    for i, pc in enumerate(ws):
        if pc == IDLE:
            if d["shared_ledger"]:
                if not used and L in (NONE, "REQUESTED"): out.append((f"w{i}.authorize", (AUTH, True, owner, c, fenced, _set(ws, i, AUTHED))))
                else: out.append((f"w{i}.authorize_refused(nonce_used)", (L, used, owner, c, fenced, _set(ws, i, DONE))))
            else:                                   # per-worker nonce store: every worker thinks the permit is fresh
                out.append((f"w{i}.authorize(local_nonce)", (LSTART if L in (NONE, AUTH) else L, True, owner if owner >= 0 else i, c, fenced, _set(ws, i, STARTED))))
        elif pc == AUTHED:
            if L == AUTH: out.append((f"w{i}.begin", (LSTART, used, i, c, fenced, _set(ws, i, STARTED))))
            else: out.append((f"w{i}.begin_refused", (L, used, owner, c, fenced, _set(ws, i, DONE))))
        elif pc == STARTED:
            if fenced: out.append((f"w{i}.sink_write_refused(fenced)", (L, used, owner, c, fenced, _set(ws, i, DONE))))
            else: out.append((f"w{i}.sink_write", (L, used, owner, c + 1, fenced, _set(ws, i, WROTE))))
        elif pc == WROTE:
            if L == LSTART and owner == i: out.append((f"w{i}.finish(COMMITTED)", (COMMITTED, used, owner, c, fenced, _set(ws, i, DONE))))
            else: out.append((f"w{i}.finish_refused(ledger={L})", (L, used, owner, c, fenced, _set(ws, i, DONE))))
        if pc in (AUTHED, STARTED, WROTE): out.append((f"w{i}.CRASH", (L, used, owner, c, fenced, _set(ws, i, DEAD))))
    # recovery: STARTED -> UNKNOWN
    if L == LSTART:
        owner_alive = owner >= 0 and ws[owner] in (STARTED, WROTE, AUTHED)
        if d["recover"] == "timeout" or not owner_alive: out.append(("recover(STARTED->UNKNOWN)", (UNKNOWN, used, owner, c, fenced, ws)))
    # orphan expiry: AUTHORIZED with no live authorizer -> BLOCKED (no begin ever happened, so no sink effect is possible afterwards)
    if d["expire_auth"] and L == AUTH and (d["expire_auth"] == "any" or not any(w == AUTHED for w in ws)): out.append(("expire_orphan(AUTHORIZED->BLOCKED)", (BLOCKED, used, owner, c, fenced, ws)))
    # reconcile UNKNOWN from the sink
    if L == UNKNOWN:
        nf = True if d["fenced"] else fenced           # fence-and-observe is ONE atomic sink operation
        out.append(("reconcile(" + ("fence_and_observe" if d["fenced"] else "observe") + ")", (REC_C if c >= 1 else REC_B, used, owner, c, nf, ws)))
    # baseline retries (a NEW dispatcher re-runs begin)
    if d["retry_unknown"] and L == UNKNOWN:
        for i, pc in enumerate(ws):
            if pc in (IDLE, DEAD): out.append((f"w{i}.RETRY_begin_from_UNKNOWN", (LSTART, used, i, c, fenced, _set(ws, i, STARTED))))
    if d["retry_started"] and L == LSTART:
        for i, pc in enumerate(ws):
            if pc == IDLE and i != owner: out.append((f"w{i}.RETRY_begin_while_STARTED(timeout)", (LSTART, used, i, c, fenced, _set(ws, i, STARTED))))
    return out


def invariants(s):
    L, used, owner, c, fenced, ws = s
    bad = []
    if c > 1: bad.append("I1_at_most_one_sink_effect")
    if c >= 1 and not used: bad.append("I2_no_effect_without_consumed_permit")
    if L in (COMMITTED, REC_C) and c != 1: bad.append("I3a_committed_requires_sink_evidence")
    if L in (BLOCKED, REC_B) and c != 0: bad.append("I3b_blocked_means_no_sink_effect")
    return bad


def explore(design, n=3, max_states=2_000_000):
    d = DESIGNS[design] if isinstance(design, str) else design
    s0 = initial(n); parent = {s0: None}; q = deque([s0]); viol = {}
    while q:
        s = q.popleft()
        bad = invariants(s)
        for name in bad:
            if name not in viol: viol[name] = _trace(parent, s)
        if bad: continue                      # do not expand past a violation (keeps unsafe designs finite)
        succ = successors(s, d)
        if not succ and s[0] in (AUTH, LSTART, UNKNOWN) and "I5_unresolved_deadend" not in viol: viol["I5_unresolved_deadend"] = _trace(parent, s)
        for lab, t in succ:
            if t not in parent:
                parent[t] = (s, lab)
                if len(parent) > max_states: raise RuntimeError("state bound exceeded")
                q.append(t)
    return {"design": design, "workers": n, "states": len(parent), "violations": viol, "safe": not viol}


def _trace(parent, s):
    path = []
    while parent[s] is not None: s, lab = parent[s]; path.append(lab)
    return list(reversed(path))


if __name__ == "__main__":
    import json, sys
    for name in DESIGNS:
        r = explore(name); print(f"{name:28s} states={r['states']:6d} safe={r['safe']} violated={sorted(r['violations'])}")
        for k, tr in sorted(r["violations"].items()): print("   ", k, "<-", " ; ".join(tr))
