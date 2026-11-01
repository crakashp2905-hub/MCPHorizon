"""Small exhaustive REFERENCE model (P40-14) for deploy_prod. Written independently of engine.py, as a trace function over the event string. Alphabet:
T test-pass evidence, A approval (by a different principal, bound to the exact args), S signature evidence, X guarded request, K clock advance that expires ALL earlier evidence, C cancel.
Semantics stated here (and in OPERATORS): the approval in force is the most recent COUNTED one; it counts only if a still-valid test existed when it was presented; an ALLOWed X consumes it."""
import itertools

ALPHA = "TASXKC"


def ref_decisions(seq):
    lastK, tests, sigs, appr, cancelled, out = -1, [], [], None, False, []        # appr = [index, consumed]
    for i, e in enumerate(seq):
        if e == "K": lastK = i
        elif e == "C": cancelled = True
        elif e == "T": tests.append(i)
        elif e == "S": sigs.append(i)
        elif e == "A":
            if any(j > lastK for j in tests): appr = [i, False]
        elif e == "X":
            ok = (not cancelled and any(j > lastK for j in tests) and any(j > lastK for j in sigs) and appr is not None and appr[0] > lastK and not appr[1])
            if ok: appr[1] = True
            out.append(ok)
    return out


def all_sequences(n):
    for k in range(1, n + 1):
        yield from ("".join(p) for p in itertools.product(ALPHA, repeat=k))
