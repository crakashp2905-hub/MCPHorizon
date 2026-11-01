"""Exact accounting rules (P45-03). Each accountant decides, from the FULL list of charges, whether the composed cost is within the budget. It is stateless: the ledger recomputes from all charged entries, so there is no incremental drift.

basic     sum eps_i <= eps_B and sum delta_i <= delta_B, in exact rational arithmetic (decimal strings -> Fraction).  [Dwork-Roth Thm 3.16 / basic composition]
advanced  Kairouz-Oh-Viswanath (2015) Thm 3.5, heterogeneous (eps_i, delta_i)-DP: for any dt in (0,1], the composition is (eps~, 1-(1-dt) prod(1-delta_i))-DP with
          eps~ = min( sum eps_i , sum eps_i (e^eps_i - 1)/(e^eps_i + 1) + sqrt(2 sum eps_i^2 ln(1/dt)) ).  We pick dt so that the total delta equals delta_B:
          dt = 1 - (1-delta_B)/prod(1-delta_i); admissible iff prod(1-delta_i) > 1-delta_B. The basic branch is also tried; the charge fits if either branch fits.
zcdp      sum rho_i with rho(Laplace eps)=eps^2/2 and rho(Gaussian)=sens^2/(2 sigma^2); then (eps, delta_B) with eps = rho + 2 sqrt(rho ln(1/delta_B)) (Bun-Steinke Prop 1.3).
          Fits iff eps(rho_total) <= eps_B. Needs delta_B > 0.
Floating-point accountants (advanced, zcdp) accept a charge only if cost*(1+MARGIN) <= budget, so rounding can only make the ledger stricter, never looser.
"""
import math
from fractions import Fraction
from .mechanisms import rho_of

MARGIN = 1e-9
ACCOUNTANTS = ("basic", "advanced", "zcdp")


class Unsupported(Exception): pass


def _F(x): return Fraction(str(x))


def basic(b, charges):
    se, sd = sum((_F(c["eps"]) for c in charges), Fraction(0)), sum((_F(c["delta"]) for c in charges), Fraction(0))
    return se <= _F(b["eps"]) and sd <= _F(b["delta"]), {"eps": float(se), "delta": float(sd)}


def advanced(b, charges):
    ok_b, sp = basic(b, charges)
    eb, db = float(_F(b["eps"])), float(_F(b["delta"]))
    es, ds = [float(_F(c["eps"])) for c in charges], [float(_F(c["delta"])) for c in charges]
    prod = 1.0
    for d in ds: prod *= (1.0 - d)
    if not charges: return True, {"eps": 0.0, "delta": 0.0}
    if prod <= 1.0 - db: return ok_b, {**sp, "branch": "basic"}
    dt = 1.0 - (1.0 - db) / prod                 # in (0, 1] because prod > 1 - db here
    A = sum(e * (math.exp(e) - 1.0) / (math.exp(e) + 1.0) for e in es); B = sum(e * e for e in es)
    adv = A + math.sqrt(2.0 * B * math.log(1.0 / dt))
    return ok_b or adv * (1.0 + MARGIN) <= eb, {"eps": min(sp["eps"], adv), "delta": db if adv < sp["eps"] else sp["delta"], "branch": "advanced" if adv < sp["eps"] else "basic"}


def zcdp(b, charges):
    db = float(_F(b["delta"]))
    if db <= 0.0: raise Unsupported("zCDP accounting converts to (eps, delta) and needs delta_B > 0")
    rho = sum(rho_of(c) for c in charges); eps = rho + 2.0 * math.sqrt(rho * math.log(1.0 / db))
    return eps * (1.0 + MARGIN) <= float(_F(b["eps"])), {"eps": eps, "delta": db, "rho": rho}


FN = {"basic": basic, "advanced": advanced, "zcdp": zcdp}


def fits(accountant: str, budget: dict, charges: list):
    if accountant not in FN: raise Unsupported("unknown accountant " + accountant)
    return FN[accountant](budget, charges)
