"""INDEPENDENT reference accountant (P45-12). Imports nothing from horizon.privacy. Arbitrary-precision decimal arithmetic (60 digits), formulas re-derived from the cited theorems, and a different code path (it reduces an event LOG, including cancellations and
expiries, instead of receiving a pre-filtered charge list). Event: {"op": "charge"|"refund", "id": str, "mech": "laplace"|"gaussian", "eps": str, "delta": str, "sens": number, "sigma": number|None}. A refund removes the earlier charge with that id.
Returns cost summaries; `within(...)` is the decision. No margin is applied: callers compare against the ledger's stricter margin and report the boundary band separately."""
from decimal import Decimal, getcontext

getcontext().prec = 60


def _live(events):
    live = {}
    for e in events:
        if e["op"] == "charge": live[e["id"]] = e
        elif e["op"] == "refund": live.pop(e["id"], None)
    return list(live.values())


def costs(events, delta_b):
    L = _live(events); D = Decimal
    e_sum = sum((D(x["eps"]) for x in L), D(0)); d_sum = sum((D(x["delta"]) for x in L), D(0))
    out = {"n": len(L), "basic": {"eps": e_sum, "delta": d_sum}}
    db = D(str(delta_b)); prod = D(1)
    for x in L: prod *= (D(1) - D(x["delta"]))
    if L and prod > D(1) - db:
        dt = D(1) - (D(1) - db) / prod
        if dt > 0:
            A = sum((D(x["eps"]) * ((D(x["eps"]).exp() - 1) / (D(x["eps"]).exp() + 1)) for x in L), D(0)); B = sum((D(x["eps"]) ** 2 for x in L), D(0))
            out["advanced"] = {"eps": min(e_sum, A + (2 * B * (D(1) / dt).ln()).sqrt()), "delta": db}
    if "advanced" not in out: out["advanced"] = {"eps": e_sum, "delta": d_sum}
    if db > 0:
        rho = D(0)
        for x in L: rho += (D(x["eps"]) ** 2 / 2) if x["mech"] == "laplace" else (D(str(x["sens"])) ** 2 / (2 * D(str(x["sigma"])) ** 2))
        out["zcdp"] = {"rho": rho, "eps": rho + 2 * (rho * (D(1) / db).ln()).sqrt(), "delta": db}
    return out


def within(events, budget, accountant):
    c = costs(events, budget["delta"]); eb, db = Decimal(str(budget["eps"])), Decimal(str(budget["delta"]))
    if accountant == "basic": return c["basic"]["eps"] <= eb and c["basic"]["delta"] <= db
    if accountant == "advanced": return c["basic"]["eps"] <= eb and c["basic"]["delta"] <= db or (c["advanced"]["eps"] <= eb and c["advanced"]["delta"] <= db)
    if accountant == "zcdp": return c["zcdp"]["eps"] <= eb
    raise ValueError(accountant)
