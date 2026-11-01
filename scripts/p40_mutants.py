#!/usr/bin/env python3
"""Mutation check for P40: every mutant must make tests.p40.test_obligation fail (run on a copy of the tree)."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EN, IN, AU = "horizon/obligation/engine.py", "horizon/obligation/infer.py", "horizon/hpolicy/authority.py"
MUT = [(EN, "if any(not self._valid_now(t, a, now) for a in o.order_after):", "if False:", "ORDER check removed"),
       (EN, "if o.bind_args and p[\"args_digest\"] != ad:", "if False:", "exact-args binding removed"),
       (EN, "if p[\"artifact\"] != t.artifact: reasons.append", "if False: reasons.append", "artifact binding at action time removed"),
       (EN, "if o.consume: consumed.append((o.id, p[\"nonce\"]))", "pass", "single-use consumption removed"),
       (EN, "if o.distinct_from_requester and p[\"iss\"] == t.requester:", "if False:", "self-approval check removed"),
       (EN, "if t.frozen: reasons.append", "if False: reasons.append", "freeze after unmet POST removed"),
       (EN, "if t.cancelled: reasons.append", "if False: reasons.append", "cancellation ignored"),
       (EN, "if ov != t.object_version: reasons.append", "if False: reasons.append", "stale-version check removed"),
       (EN, "if action in self.unguarded else Decision(\"DENY\", [\"UNKNOWN_ACTION\"], guarded=False)", "if True else Decision(\"DENY\", [\"UNKNOWN_ACTION\"], guarded=False)", "unknown actions allowed"),
       (EN, "if op_id in t.ops:", "if False:", "idempotent retry removed"),
       (EN, "if any(p[\"claim\"].get(k_) != v for k_, v in o.claim_equals):", "if False:", "claim constraint ignored"),
       (EN, "if mine != theirs:", "if False:", "handoff catalog mismatch ignored"),
       (EN, "for oid in v: t.frozen = True", "pass", "deadline monitor does not freeze"),
       (IN, "if not set(new.roles) <= set(base.roles): r.append(\"roles widened\")", "pass", "role widening allowed"),
       (IN, "if base.distinct_from_requester and not new.distinct_from_requester: r.append(\"self-approval allowed\")", "pass", "self-approval relaxation allowed"),
       (IN, "if e[\"seq\"] != i or e[\"prev\"] != prev or e[\"h\"] != h: return False", "pass", "change log verification disabled"),
       (IN, "if p[\"role\"] != \"policy_owner\" or p[\"kind\"] != \"APPROVAL\" or p[\"artifact\"] != digest:", "if False:", "any approval activates a proposal"),
       (AU, "if pl[\"policy_version\"] != (policy_version or self._a.version): raise", "if False: raise", "policy-version binding removed"),
       (AU, "if kind not in self._a.roles.get(self.role, ()): raise", "if False: raise", "issuer role restriction removed")]


def main():
    surv, ran = [], 0
    for f, a, b, why in MUT:
        d = tempfile.mkdtemp(prefix="p40m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target"))
        s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        r = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "tests.p40.test_obligation"], cwd=t, capture_output=True, text=True, timeout=600)
        print(("KILLED  " if r.returncode else "SURVIVED"), why)
        if not r.returncode: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
