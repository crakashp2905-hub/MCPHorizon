"""The operation gateway (P52-04..08) and the compared baselines (P52-13).

Gateway.begin() is the before-effect revalidation; Gateway.finish() applies the effect. When the gateway and the effect service share one transaction (`atomic` and the sink supports conditional writes) the scheduler runs
both as ONE step, so no mutation can interleave; otherwise they are two steps and the interleaving explorer can put a mutation between them. A sink that cannot be conditioned (external provider) makes the effect UNKNOWN
even when every check passed.
Checks, each switchable for the ablations: token signature/kind/role/expiry on the AUTHORITATIVE clock; actor = token principal; object identity, version, class and content digest; grant version/scopes; digest of exactly the
rules that decide the action; revocation of the approval (logical clock); single use; destination re-resolved at use and PINNED; every redirect hop re-checked; the policy function re-evaluated on current state."""
import base64, json
from dataclasses import dataclass
from ..hpolicy.authority import EvidenceError
from . import core as C

@dataclass(frozen=True)
class TCfg:
    actor: bool = True; object_id: bool = True; object_version: bool = True; object_class: bool = True; content: bool = True; grant: bool = True; policy_slice: bool = True; policy_recheck: bool = True; revocation: bool = True
    destination: bool = True; redirect: bool = True; nonce: bool = True; expiry: bool = True; authoritative_clock: bool = True; atomic: bool = True; idempotent: bool = True; fail_closed: bool = True; cas_writes: bool = True

def _commit(w, ctx, k, host, ip, final):
    """Hand the effect to the sink. An external sink that cannot be conditioned makes the outcome UNKNOWN; a deferred one applies it later, unrevalidated, when the provider flushes."""
    if w.deferred: w.pending.append((k, host, ip, final)); r = _res(ctx["rid"], "UNKNOWN", "DEFERRED_EXTERNAL_EFFECT")
    else:
        w.store.apply_export(k["actor"], k["obj"], host, ip, final, k["approval"]); r = _res(ctx["rid"], "OK" if w.sink_atomic else "UNKNOWN", "APPLIED" if w.sink_atomic else "SINK_NOT_CONDITIONAL")
    w.done[ctx["rid"]] = r; ctx["final"] = r; w.results.append(r); return ctx

def _peek(tok): return json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4)))
def _res(rid, status, reason, **kw): return {"rid": rid, "status": status, "reason": reason, **kw}

class Gateway:
    kind = "gateway"
    def __init__(self, name, cfg=TCfg()): self.name, self.cfg = name, cfg
    def phases(self, w): return 1 if (self.cfg.atomic and w.sink_atomic) else 2
    def _deny(self, w, ctx, reason, status="DENIED"): ctx["final"] = _res(ctx["rid"], status, reason); w.results.append(ctx["final"]); return ctx
    def begin(self, w, tok, caller, act, rid):
        c = self.cfg; ctx = {"rid": rid, "act": act, "caller": caller}
        if c.idempotent and rid in w.done: ctx["final"] = {**w.done[rid], "replayed": True}; w.results.append(ctx["final"]); return ctx
        if tok is None: return self._deny(w, ctx, "NO_TOKEN")
        now = int(w.clock() if c.authoritative_clock else w.worker_clock())
        try: p = w.verifier.verify(tok, now=now)
        except EvidenceError as e:
            if e.code == "EXPIRED" and not c.expiry: p = w.verifier.verify(tok, now=_peek(tok)["iat"])
            else: return self._deny(w, ctx, e.code)
        claim = p["claim"]; host = claim["d"][0]
        if p["args_digest"] != C.digest(C.envelope("export", p["principal"], p["artifact"], host, claim)): return self._deny(w, ctx, "BINDING_MISMATCH")
        if c.actor and p["principal"] != caller: return self._deny(w, ctx, "ACTOR_MISMATCH")
        if host != act["host"]: return self._deny(w, ctx, "HOST_MISMATCH")
        if c.object_id and p["artifact"] != act["obj"]: return self._deny(w, ctx, "OBJECT_MISMATCH")
        with w.store.tx():
            ap = w.store.approval(p["nonce"])
            if ap is None: return self._deny(w, ctx, "UNKNOWN_APPROVAL")
            if c.nonce and ap["used"]: return self._deny(w, ctx, "REPLAY")
            if c.revocation:
                if not w.telemetry_up:
                    if c.fail_closed: return self._deny(w, ctx, "REVOCATION_FEED_DOWN", "UNKNOWN")
                elif ap["revoked"] or w.store.revoked_since(p["nonce"], ap["issued_seq"]): return self._deny(w, ctx, "APPROVAL_REVOKED")
            ips = w.net.resolve(host) if c.destination else ap["claim"]["ips"]
            v = w.store.view(caller, act["obj"], host, ips); now_v = v["vec"]; o = v["obj"]
            pairs = [("OBJECT_ID", claim["o"][0], now_v["o"][0], c.object_id), ("OBJECT_VERSION", claim["o"][1], now_v["o"][1], c.object_version), ("CLASS_CHANGED", claim["o"][2], now_v["o"][2], c.object_class), ("CONTENT_CHANGED", claim["c"], now_v["c"], c.content),
                     ("GRANT_CHANGED", claim["g"], now_v["g"], c.grant), ("POLICY_CHANGED", claim["s"], now_v["s"], c.policy_slice), ("DESTINATION_CHANGED", claim["d"][1], now_v["d"][1], c.destination)]
            for why, a, b, on in pairs:
                if on and a != b: return self._deny(w, ctx, why)
            if c.policy_recheck:
                ok, why = C.permits(v["rules"], v["scopes"], o["cls"], host, ips)
                if not ok: return self._deny(w, ctx, "NOT_PERMITTED:" + why)
            ctx["checked"] = {"ips": ips, "approval": p["nonce"], "actor": caller, "obj": act["obj"], "host": host}
            if self.phases(w) == 1: return self.finish(w, ctx)
        return ctx
    def finish(self, w, ctx):
        if "final" in ctx: return ctx
        c = self.cfg; k = ctx["checked"]; host = k["host"]
        with w.store.tx():
            if c.nonce: w.store.mark_used(k["approval"])
            ip = k["ips"][0] if c.destination and k["ips"] else w.net.connect(host); final = host; nxt = w.net.redirected(host)
            if nxt:
                if c.redirect:
                    rules, _ = w.store.rules(); d = rules.get("dest." + nxt); hop = w.net.resolve(nxt)
                    if d is None or not hop or not set(hop) <= set(d["ips"]): return self._deny(w, ctx, "REDIRECT_DENIED")
                    ip = hop[0]
                else: ip = w.net.connect(nxt)
                final = nxt
            return _commit(w, ctx, k, host, ip, final)
    def write(self, w, caller, obj, base_version, content):
        if self.cfg.cas_writes: return w.store.cas_update(obj, base_version, content=content)
        w.store.lww_update(obj, base_version, content=content); return True

class Naive:
    """Baselines. Each trusts less than the gateway: what it checks is stated in `desc`."""
    kind = "baseline"
    DESC = {"one-time-check": "authorized once when approval was requested; the effect only needs the approval to exist", "jwt-expiry": "signature and expiry only, verified on the worker's clock; no state binding, no single use",
            "op-token-no-object": "token bound to operation, actor and destination host, single use, authoritative expiry; not bound to the object, its version or the policy", "restrictive-rule": "hand-written: token must be at most 5 s old, single use, never for a queued dispatch; no state check"}
    def __init__(self, name): self.name = name
    def phases(self, w): return 1 if w.sink_atomic else 2
    def begin(self, w, tok, caller, act, rid):
        ctx = {"rid": rid, "act": act, "caller": caller}; n = self.name
        if tok is None: ctx["final"] = _res(rid, "DENIED", "NO_TOKEN"); w.results.append(ctx["final"]); return ctx
        try:
            if n == "one-time-check": p = _peek(tok)
            elif n == "jwt-expiry": p = w.verifier.verify(tok, now=int(w.worker_clock()))
            else: p = w.verifier.verify(tok, now=int(w.clock()))
        except EvidenceError as e: ctx["final"] = _res(rid, "DENIED", e.code); w.results.append(ctx["final"]); return ctx
        host = p["claim"]["d"][0]
        if n in ("op-token-no-object", "restrictive-rule"):
            if p["principal"] != caller: ctx["final"] = _res(rid, "DENIED", "ACTOR_MISMATCH"); w.results.append(ctx["final"]); return ctx
            if host != act["host"]: ctx["final"] = _res(rid, "DENIED", "HOST_MISMATCH"); w.results.append(ctx["final"]); return ctx
            if w.store.approval(p["nonce"])["used"]: ctx["final"] = _res(rid, "DENIED", "REPLAY"); w.results.append(ctx["final"]); return ctx
        if n == "restrictive-rule" and (w.clock() - p["iat"] > 5 or act.get("queued")): ctx["final"] = _res(rid, "DENIED", "TOO_OLD_OR_QUEUED"); w.results.append(ctx["final"]); return ctx
        ctx["checked"] = {"approval": p["nonce"], "actor": caller, "obj": p["artifact"] if n in ("one-time-check", "restrictive-rule") else act["obj"], "host": host}
        if self.phases(w) == 1: return self.finish(w, ctx)
        return ctx
    def finish(self, w, ctx):
        if "final" in ctx: return ctx
        k = ctx["checked"]; host = k["host"]
        with w.store.tx():
            if self.name in ("op-token-no-object", "restrictive-rule"): w.store.mark_used(k["approval"])
            ip = w.net.connect(host); final = host; nxt = w.net.redirected(host)
            if nxt: final = nxt; ip = w.net.connect(nxt)
            return _commit(w, ctx, k, host, ip, final)
    def write(self, w, caller, obj, base_version, content): w.store.lww_update(obj, base_version, content=content); return True
