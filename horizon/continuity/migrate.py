"""Migration systems (P53-02..10, 15): HorizonContinuity and the compared baselines. Every system builds the same checkpoint (`build_env`); they differ in what they verify, what they adopt from it and what they do about the source."""
from dataclasses import dataclass
from ..hpolicy.authority import EvidenceError
from . import core as C

def build_env(w, nonce):
    s, now = w.src.state, int(w.clock()); g = w.grants
    return {"v": 1, "task": g.task, "chain": list(g.chain), "permissions": sorted(s["perms"]), "controls": dict(w.K), "labels": dict(s["labels"] or {}), "obligations": [dict(o) for o in (s["obligations"] or [])],
            "budgets": {"api": {"cap": s["caps"].get("api", 0), "ledger": "led-1", "spent": w.ledger.get("api") if s["ledger"] else s["spent"]}},
            "approvals": [{"id": i, "action": a["action"], "exp": a["exp"]} for i, a in sorted(s["approvals"].items())], "credentials": [{"handle": s["cred"], "scope": "read", "broker": "broker-1"}] if s["cred"] else [],
            "artifacts": {d: C.digest([d, l]) for d, l in sorted((s["labels"] or {}).items())}, "policy": {"id": "pol-1", "version": 3}, "revocation": {"handle": s["rev"]},
            "ops": {"done": sorted(s["done"]), "pending": [dict(o) for o in w.src.pending]}, "provenance": {"source": w.src.id, "seq": 1, "parent": None, "model": w.model}, "iat": now, "exp": now + 300, "resume_nonce": nonce}

@dataclass(frozen=True)
class CCfg:
    signature: bool = True; schema: bool = True; nonce: bool = True; expiry: bool = True; widening: bool = True; att_fresh: bool = True; att_identity: bool = True; covers: bool = True; sink_policy: bool = True; revocation: bool = True
    fail_closed: bool = True; approval_expiry: bool = True; freeze: bool = True; drain: bool = True; ledger: bool = True; obligations_carry: bool = True; labels_carry: bool = True; broker_rebind: bool = True; rollback: bool = True

class Continuity:
    kind = "continuity"; uses_ledger_attr = "ledger"
    def __init__(self, name, cfg=CCfg()): self.name, self.cfg = name, cfg
    @property
    def uses_ledger(self): return self.cfg.ledger
    @property
    def broker_enforced(self): return self.cfg.broker_rebind
    def migrate(self, w, bundle=None, tgt=None):
        c = self.cfg; src = w.src; tgt = tgt or w.tgt
        if bundle is None:
            if c.freeze: src.freeze()
            if c.drain: w.drain(src)
            w.nonce += 1; env = build_env(w, "n-%d" % w.nonce); tok = w.checkpointer.issue("ATTESTATION", principal=src.id, artifact=env["task"], args_digest=C.digest(env), claim={"k": "envelope"}, ttl=300, nonce=env["resume_nonce"], now=int(w.clock()))
            bundle = {"env": env, "token": tok, "att": None}; w.bundle = bundle; w.hook("mid", bundle)
        why, unk = self.admit(w, bundle, tgt)
        if why: return self.fail(w, why, unk)
        self.resume(w, bundle, tgt); return {"status": "MIGRATED", "reasons": [], "unknown": False}
    def admit(self, w, b, tgt):
        c = self.cfg; env, tok = b["env"], b["token"]; now = int(w.clock())
        try: p = w.verifier.verify(tok, now=now) if c.signature else w.peek(tok)
        except EvidenceError as e: return [e.code], False
        if p["role"] != "source-runtime" or p["claim"].get("k") != "envelope": return ["WRONG_TOKEN_KIND"], False
        if c.signature and p["args_digest"] != C.digest(env): return ["ENVELOPE_DIGEST"], False
        if c.schema:
            try: C.validate(env)
            except C.EnvError as e: return [e.code], False
        if c.signature and (p["artifact"] != env.get("task") or p["nonce"] != env.get("resume_nonce")): return ["TOKEN_ENVELOPE_MISMATCH"], False
        if c.nonce and p["nonce"] in w.used_nonces: return ["REPLAY"], False
        if c.expiry and not env["iat"] <= now < env["exp"]: return ["ENVELOPE_EXPIRED"], False
        if c.widening:
            r = C.widening(env, w.grants.grant(), w.grants.labels)
            if r: return r, False
        if c.revocation:
            for key in ("policy:pol-1:3", env["revocation"]["handle"]):
                st = w.rev.status(key)
                if st == "REVOKED": return ["REVOKED"], False
                if st == "UNKNOWN" and c.fail_closed: return ["REVOCATION_UNKNOWN"], True
        try: att = b["att"] or w.attestor.attest(tgt)
        except KeyError: return ["NO_ATTESTATION"], True
        try: ap = w.verifier.verify(att, now=now) if c.att_fresh else w.peek(att)
        except EvidenceError as e: return ["ATTESTATION_" + e.code], False
        if ap["role"] != "attestor": return ["ATTESTATION_WRONG_ROLE"], False
        cl = ap["claim"]
        if c.att_identity and (cl["rt"] != tgt.id or ap["principal"] != tgt.id or ap["args_digest"] != C.digest(cl)): return ["ATTESTATION_IDENTITY"], False
        if c.covers:
            miss = C.covers(env["controls"], cl["g"])
            if miss: return ["NOT_COVERED:" + ",".join(miss)], False
        if c.sink_policy and not cl["sm"]: return ["SINK_UNVERIFIED"], True
        return [], False
    def fail(self, w, why, unk):
        c = self.cfg
        if c.rollback and w.source_alive: w.src.unfreeze(); st = "ROLLED_BACK"
        else: st = "SAFE_STOP"
        return {"status": st, "reasons": why, "unknown": unk}
    def resume(self, w, b, tgt):
        c = self.cfg; env = b["env"]; s, S = w.src, tgt.state; w.used_nonces.add(env["resume_nonce"])
        if c.broker_rebind: w.broker.revoke_runtime(s.id); S["cred"] = w.broker.issue(env["task"], tgt.id, "read")
        else: S["cred"] = env["credentials"][0]["handle"] if env["credentials"] else None
        S["perms"] = list(env["permissions"]); S["task"] = env["task"]; S["caps"] = {"api": env["budgets"]["api"]["cap"]}; S["ledger"] = c.ledger; S["spent"] = 0 if c.ledger else env["budgets"]["api"]["spent"]
        S["labels"] = dict(env["labels"]) if c.labels_carry and "labels" in env else None; S["obligations"] = [dict(o) for o in env["obligations"]] if c.obligations_carry and "obligations" in env else None
        S["approvals"] = {a["id"]: {"action": a["action"], "exp": a["exp"]} for a in env["approvals"] if not c.approval_expiry or a["exp"] > w.clock()}
        S["rev"] = env["revocation"]["handle"]; S["done"] = set(env["ops"]["done"]); tgt.eff = {k: max(tgt.defaults.get(k, 0), min(env["controls"].get(k, 0), tgt.supports.get(k, 0))) for k in set(env["controls"]) | set(tgt.defaults)}

class Baseline:
    kind = "baseline"; uses_ledger = False; broker_enforced = False
    DESC = {"state-serialization": "serialize the agent state (permissions, credentials, pending calls, approvals as already-validated flags) and resume it elsewhere; the source keeps running; the target applies its own default controls; counters reset",
            "token-copying": "copy the bearer credentials and permissions to the target; nothing else; the source keeps running", "container-snapshot": "snapshot the whole process (labels, obligations, local counters, revocation handle) and restore it at the target; host-level controls do not travel; in-flight calls are not drained",
            "config-sync": "copy the policy configuration; the target silently enables each control it happens to support and ignores the rest; labels, obligations and counters are not synced; the source keeps running", "tool-name-check": "admit iff the target exposes every tool the source uses; then serialize state as in state-serialization",
            "restrictive-rule": "hand-written: migrate only to a runtime of the same vendor; container-snapshot state"}
    FREEZE = {"container-snapshot", "restrictive-rule"}; CARRY = {"container-snapshot", "restrictive-rule"}
    def __init__(self, name): self.name = name
    def migrate(self, w, bundle=None, tgt=None):
        n = self.name; src = w.src; tgt = tgt or w.tgt
        if bundle is None:
            if n in self.FREEZE: src.freeze()
            w.nonce += 1; bundle = {"env": build_env(w, "n-%d" % w.nonce), "token": None, "att": None}; w.bundle = bundle; w.hook("mid", bundle)
        ok = True
        if n == "tool-name-check": ok = set(src.tools) <= set(tgt.tools)
        if n == "restrictive-rule": ok = tgt.vendor == src.vendor
        if not ok:
            src.unfreeze(); return {"status": "ROLLED_BACK", "reasons": ["POLICY_COMPAT"], "unknown": False}
        env, S, carry = bundle["env"], tgt.state, n in self.CARRY
        S["perms"] = list(env["permissions"]); S["task"] = env["task"]; S["caps"] = {"api": env["budgets"]["api"]["cap"]}; S["raw_secret"] = w.broker.secret if env["credentials"] else None; S["spent"] = env["budgets"]["api"]["spent"] if carry else 0
        S["approvals"] = {a["id"]: {"action": a["action"], "exp": None} for a in env["approvals"]}
        tgt.eff = dict(tgt.defaults)
        if carry: S["labels"] = dict(env.get("labels") or {}) or None; S["obligations"] = [dict(o) for o in env["obligations"]] if "obligations" in env else None; S["rev"] = env["revocation"]["handle"]; S["done"] = set(env["ops"]["done"])
        if n == "config-sync": S["rev"] = env["revocation"]["handle"]; tgt.eff = {k: max(tgt.defaults.get(k, 0), min(lvl, tgt.supports.get(k, 0))) for k, lvl in env["controls"].items()}
        for o in env["ops"]["pending"]: tgt.op(w, o)                                # unacknowledged calls are retried at the target
        return {"status": "MIGRATED", "reasons": [], "unknown": False}
