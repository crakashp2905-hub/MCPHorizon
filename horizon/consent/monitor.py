"""Independent consent monitor (P48-04, 05, 06, 07, 11): at effect time it recomputes the manifest from trusted platform state and checks signed approvals against it.
It never reads the sink journal or the approval ledger; it sees public-key evidence and the read-only normalizer."""
from dataclasses import dataclass
from ..hpolicy.authority import EvidenceError
from . import core as K


@dataclass(frozen=True)
class CCfg:
    bind_content: bool = True; bind_hosts: bool = True; bind_versions: bool = True; bind_args: bool = True; bind_effect: bool = True; bind_agent: bool = True; bind_tenant: bool = True; bind_task: bool = True; bind_policy: bool = True
    consume: bool = True; separation: bool = True; authority: bool = True; dual_control: bool = True; enforce_bounds: bool = True; org_prohibitions: bool = True


@dataclass
class Verdict:
    allow: bool; reasons: tuple = ()


def strip(m, cfg, keep_hosts=False):
    m = K.json.loads(K.json.dumps(m))
    if not cfg.bind_tenant: m["tenant"] = None
    if not cfg.bind_task: m["task"] = None
    if not cfg.bind_content: m["resource"]["digest"] = None
    if not cfg.bind_versions:
        m["resource"]["version"] = 0
        for r in m["receivers"]: r["version"] = 0
    if not cfg.bind_hosts and not keep_hosts:
        for i, r in enumerate(m["receivers"]): r["host"] = "#%d" % i
    return m


class ConsentMonitor:
    def __init__(self, verifier, clock, reader, policy=K.POLICY, cfg: CCfg = CCfg()):
        self.v, self.clock, self.reader, self.policy, self.cfg = verifier, clock, reader, policy, cfg; self.log = []
    def check(self, req) -> Verdict:
        a, ten, task, ag, owner = req["action"], req["tenant"], req["task"], req["agent"], req["owner"]; cfg = self.cfg
        E = self.reader.effect_of(a, ten, task); why = []
        if cfg.org_prohibitions:
            pr = K.prohibited(E, self.policy)
            if pr: return self._done(False, ("ORG_PROHIBITED:" + ",".join(pr),))
        need = K.requirement(E, self.policy)
        if need is None: return self._done(True, ())
        good = {}; env = req.get("envelope"); pol = K.policy_digest(self.policy)
        for tok in req.get("tokens") or []:
            try: p = self.v.verify(tok, now=self.clock.now())
            except EvidenceError as e: why.append("TOKEN_" + e.code); continue
            cl = p["claim"]
            if p["kind"] != "APPROVAL": why.append("WRONG_KIND"); continue
            if cfg.bind_tenant and cl.get("ten") != ten: why.append("WRONG_TENANT"); continue
            if cfg.bind_task and (cl.get("task") != task or p["artifact"] != task): why.append("WRONG_TASK"); continue
            if cfg.bind_agent and cl.get("ag") != ag: why.append("WRONG_AGENT"); continue
            if cfg.bind_policy and cl.get("pol") != pol: why.append("POLICY_CHANGED"); continue
            if cfg.bind_args and p["args_digest"] != K.digest(a) and not (p["args_digest"] == "*" and env and env.get("bounds")): why.append("ARGUMENTS_CHANGED"); continue
            if cfg.bind_effect:
                if env is None or K.digest(env)[:23] != cl.get("eff"): why.append("ENVELOPE_NOT_BOUND"); continue
                kh = bool(env.get("bounds", {}).get("receiver_set")); actual = strip(E, cfg, kh)
                if env.get("bounds") and not cfg.enforce_bounds:
                    for k in ("receivers", "amount"): actual[k] = env["exact"].get(k, actual[k])
                bad = K.within(actual, {"exact": strip(env["exact"], cfg, kh) if "resource" in env["exact"] else env["exact"], "bounds": env.get("bounds", {})})
                if bad: why.append("EFFECT_OUTSIDE_APPROVAL:" + ",".join(bad)); continue
            apr = p["principal"]
            if cfg.separation and apr in (owner, ag): why.append("SEPARATION_OF_DUTIES"); continue
            if cfg.authority and self.policy["authority"].get(apr, 0) < need["level"]: why.append("INSUFFICIENT_AUTHORITY"); continue
            good[apr] = tok
        n = need["approvals"] if cfg.dual_control else 1
        if len(good) < n: return self._done(False, tuple(why) or ("NO_APPROVAL",))
        if cfg.consume:
            for tok in list(good.values())[:n]:
                try: self.v.verify(tok, now=self.clock.now(), consume=True)
                except EvidenceError as e: return self._done(False, ("TOKEN_" + e.code,))
        return self._done(True, ())
    def _done(self, ok, why): v = Verdict(ok, why); self.log.append(v); return v
