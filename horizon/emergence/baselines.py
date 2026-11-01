"""Matched-instrumentation baselines (P39-13): every detector sees the same recorded op chain; none sees the oracle's journal."""
from __future__ import annotations
from .summaries import PUB, RANK
from .model import Endpoints, Step, step_effect, chain_of

NAME_BLOCKLIST = ("exfiltrate", "steal", "send_secret", "dump_credentials")      # D0: legacy malicious-tool-name flagger


def d0(steps, eps=None): return any(any(k in s.op for k in NAME_BLOCKLIST) for s in steps)


def d3(steps, eps=None):
    """Legacy-style capability co-occurrence: credentials_in_context AND network_send_external anywhere in the chain (no arguments, endpoints, sanitization)."""
    return any(s.op == "read_secret" for s in steps) and any(s.op in ("get", "post") for s in steps)


def direct_taint(steps, eps):
    """Per-call policy with taint but WITHOUT delegated remote effects: judges only the host the call addresses."""
    tg = {}
    for s in steps:
        if s.op in ("get", "post"):
            if s.in_taint != PUB and not eps.by_port[eps.ports[s.target.split("/")[0]]].secure_sink: return True
    return False


def emergence(steps, eps, sums):
    """Effect checker: re-derives taint from the summaries and resolves delegated chains. Returns 'VIOLATION' | 'UNKNOWN' | 'SAFE'."""
    taints, last = [], None
    for s in steps:
        if s.op in ("get", "post"):
            t = taints[s.args[0]] if s.args else PUB
            st = Step(s.op, s.args, s.target, PUB, t); step_effect(taints, st, eps, sums); last = st
        else:
            from .model import apply_transform
            taints.append(sums[s.op].out_taint if s.op.startswith("read") else apply_transform(sums[s.op], taints[s.args[0]]))
    if last is None: return "SAFE"
    if last.violation: return "VIOLATION"
    if last.unknown and last.in_taint != PUB: return "UNKNOWN"
    return "SAFE"
