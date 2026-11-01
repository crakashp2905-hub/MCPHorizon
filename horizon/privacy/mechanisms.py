"""Supported DP mechanisms and their charge records (P45-03/04).

Supported:
  * discrete Laplace (two-sided geometric) on integer-valued queries: pure eps-DP, P(Z=k) ~ exp(-eps*|k|/sens). eps-DP implies (eps^2/2)-zCDP (Bun & Steinke 2016, Prop. 1.4).
  * continuous Gaussian with the classical calibration sigma = sens*sqrt(2 ln(1.25/delta))/eps, valid for 0 < eps < 1 (Dwork & Roth Thm A.1); its zCDP cost is rho = sens^2/(2 sigma^2).
Noise comes from a keyed PRF stream indexed by (service secret, request id): re-executing the same request id returns the SAME noise, so a retry cannot be used to draw a second sample.
Floating-point caveat: sampling uses IEEE doubles; the known floating-point attacks on naive Laplace sampling (Mironov 2012) apply to continuous Laplace and are avoided here by integer-valued noise for Laplace, but the Gaussian sampler is a double-precision Box-Muller and is NOT claimed to be exactly DP.
"""
import hashlib, hmac, math


class Stream:
    """HMAC-SHA256 counter-mode stream of uniform doubles in (0,1)."""
    def __init__(self, secret: bytes, request_id: str, label: str = ""): self.k, self.n = hmac.new(secret, ("horizon.privacy.noise\x00%s\x00%s" % (request_id, label)).encode(), hashlib.sha256).digest(), 0
    def u(self) -> float:
        d = hmac.new(self.k, self.n.to_bytes(8, "big"), hashlib.sha256).digest(); self.n += 1
        return (int.from_bytes(d[:7], "big") >> 3 | 1) / float(1 << 53)          # 53 random bits, never 0, never 1


def geometric(u: float, alpha: float) -> int:
    """P(G=k) = (1-alpha) alpha^k, k>=0, by inversion."""
    return int(math.floor(math.log(u) / math.log(alpha)))


def discrete_laplace(st: Stream, eps: float, sens: int) -> int:
    alpha = math.exp(-eps / sens); return geometric(st.u(), alpha) - geometric(st.u(), alpha)


def gaussian(st: Stream, sigma: float) -> float:
    u1, u2 = st.u(), st.u(); return sigma * math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)


def laplace_charge(eps: str, sens: int) -> dict:
    return {"mech": "laplace", "eps": str(eps), "delta": "0", "sens": sens, "sigma": None}


def gaussian_sigma(eps: float, delta: float, sens: float) -> float:
    if not (0 < eps < 1): raise ValueError("classical Gaussian calibration needs 0 < eps < 1")
    if not (0 < delta < 1): raise ValueError("delta must be in (0,1)")
    return sens * math.sqrt(2.0 * math.log(1.25 / delta)) / eps


def gaussian_charge(eps: str, delta: str, sens: float) -> dict:
    return {"mech": "gaussian", "eps": str(eps), "delta": str(delta), "sens": sens, "sigma": gaussian_sigma(float(eps), float(delta), sens)}


def rho_of(c: dict) -> float:
    """zCDP cost of one charge."""
    if c["mech"] == "laplace": return float(c["eps"]) ** 2 / 2.0
    return c["sens"] ** 2 / (2.0 * c["sigma"] ** 2)
