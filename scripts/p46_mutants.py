#!/usr/bin/env python3
"""Mutation check for P46: each mutant must make tests.p46.test_downgrade fail (run on a copy of the tree)."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); P = lambda x: "horizon/downgrade/%s.py" % x
OR, MF, EN, GW, SC = [P(x) for x in ("order", "manifest", "engine", "gateway", "scenarios")]
MUT = [(OR, 'return SAT if CHAINS[dim].index(got) >= CHAINS[dim].index(required) else UNSAT', 'return SAT if CHAINS[dim].index(got) > CHAINS[dim].index(required) else UNSAT', "chain boundary made strict"),
       (OR, '    if got is None: return UNKNOWN', '    if got is None: return SAT', "UNKNOWN satisfies a requirement"),
       (OR, 'if k == "scope": return SAT if frozenset(got) <= frozenset(required) else UNSAT', 'if k == "scope": return SAT if frozenset(got) >= frozenset(required) else UNSAT', "scope order reversed"),
       (OR, '    return a == b                                                    # members are pairwise incomparable', '    return True', "regions ranked"),
       (OR, 'return ("INCOMPARABLE" if better else "DOWNGRADE"), per', 'return "DOWNGRADE", per', "incomparable folded into downgrade"),
       (OR, '    if any(v == UNSAT for v in per.values()):', '    if False:', "known violation hidden behind UNKNOWN"),
       (OR, 'if k == "chain": out[d] = r if CHAINS[d].index(r) > CHAINS[d].index(a) else a', 'if k == "chain": out[d] = r if CHAINS[d].index(r) < CHAINS[d].index(a) else a', "join keeps the weaker level"),
       (OR, 'elif k == "scope": out[d] = frozenset(a) & frozenset(r)', 'elif k == "scope": out[d] = frozenset(a) | frozenset(r)', "join widens scope"),
       (OR, 'if k == "scope" and not frozenset(new[d]) <= frozenset(r): return False', 'if k == "scope" and not frozenset(new[d]) >= frozenset(r): return False', "strictness check reverses scope"),
       (OR, '        if d not in new: return False', '        if d not in new: continue', "dropped requirement counted as strict"),
       (OR, '        if v not in CHAINS[dim]: raise ValueError', '        if False: raise ValueError', "out-of-domain value accepted"),
       (MF, 'if old and b["version"] <= old["body"]["version"]:', 'if old and b["version"] < old["body"]["version"]:', "same-version replacement accepted"),
       (MF, 'if old and b["version"] <= old["body"]["version"]:', 'if False:', "profile rollback accepted"),
       (MF, 'pl["artifact"] == name and ', '', "attestation not bound to endpoint"),
       (MF, 'pl["args_digest"] == profile_digest(b) and ', '', "attestation not bound to profile digest"),
       (MF, 'and pl["claim"].get("level") == "ATTESTED"', '', "attestation level unchecked"),
       (MF, 'if e["status"] == "ATTESTED" and self.clock() >= e["exp"]:', 'if False:', "attestation never expires"),
       (MF, 'except Exception: self.log.append((name, "BAD_PROFILE_SIGNATURE")); return "REJECTED"', 'except Exception: pass', "unsigned profile accepted"),
       (MF, '        if self.status(name) != "ATTESTED": return {d: None for d in O.DIMS}', '        if False: return {d: None for d in O.DIMS}', "unattested claims count as evidence"),
       (MF, 'self.p[name]["status"] = "REVOKED"; self.epoch += 1;', 'self.p[name]["status"] = "REVOKED";', "revocation does not invalidate the cache"),
       (EN, '        self.reg.status(cand.endpoint)    ', '        pass    ', "expiry not applied before the cache lookup"),
       (MF, 'if self.r.epoch != self.epoch or policy_version != self.pv:', 'if self.r.epoch != self.epoch:', "policy change does not invalidate the cache"),
       (MF, 'if self.r.epoch != self.epoch or policy_version != self.pv:', 'if policy_version != self.pv:', "registry change does not invalidate the cache"),
       (EN, 'or p["args_digest"] != floor_digest(floor, nonwaivable): raise', ': raise', "floor token not bound to the floor"),
       (EN, 'or p["artifact"] != task or', 'or', "floor token not bound to the task"),
       (EN, 'or p["claim"].get("type") != "task-floor"', '', "floor claim type unchecked"),
       (EN, '        if self.cfg.floor_binding and not O.at_least_as_strict(ctx.floor, ctx.root_floor): return "FLOOR_WEAKENED"', '        pass', "evaluation ignores weakened floor"),
       (EN, 'if self.cfg.floor_binding and not O.at_least_as_strict(claimed_floor, ctx.root_floor): raise', 'if False: raise', "delegation may weaken the floor"),
       (EN, 'f = claimed_floor if not self.cfg.floor_binding else O.join(ctx.floor, claimed_floor)', 'f = claimed_floor', "delegated floor replaces instead of tightening"),
       (EN, 'if any(d in ctx.nonwaivable for d in bad_dims): return ("BLOCK"', 'if False: return ("BLOCK"', "non-waivable dimensions can be reviewed"),
       (EN, 'if self.reg.status(cand.endpoint) == "REVOKED": return', 'if False: return', "revoked profile usable"),
       (EN, 'if cand.endpoint not in self.reg.p: return', 'if False: return', "endpoint without profile evaluated"),
       (EN, 'vec["scope"] = frozenset(vec["scope"]) | frozenset(cand.scope)', 'vec["scope"] = frozenset(vec["scope"])', "requested scope ignored"),
       (EN, 'self.pv, floor_digest(ctx.floor, ctx.nonwaivable), tuple(sorted(cand.scope))', 'self.pv, tuple(sorted(cand.scope))', "cache not keyed by floor"),
       (EN, 'if adm: return {"action": "USE", "decision": adm[0]', 'if adm: return {"action": "USE", "decision": adm[-1]', "last admissible wins"),
       (EN, 'if p["principal"] == requester: return False, "SELF_APPROVAL"', 'if False: return False, "SELF_APPROVAL"', "self-approval allowed"),
       (EN, 'if p["nonce"] in self.consumed: return False, "APPROVAL_ALREADY_USED"', 'if False: return False, "APPROVAL_ALREADY_USED"', "approval reusable"),
       (EN, 'if p["kind"] != "APPROVAL" or p["artifact"] != req["task"]:', 'if p["artifact"] != req["task"]:', "approval kind unchecked"),
       (EN, 'if p["kind"] != "APPROVAL" or p["artifact"] != req["task"]:', 'if p["kind"] != "APPROVAL":', "approval task unchecked"),
       (EN, 'if self.cfg.approval_binding and p["args_digest"] != req["action_digest"]:', 'if False:', "approval not bound to the action"),
       (EN, '"profile": self.reg.digest(cand.endpoint), ', '', "action digest ignores the profile"),
       (EN, ', "scope": sorted(self.scope)}', '}', "action digest ignores credential scope"),
       (EN, 'scope = want & allowed if self.clamp else want', 'scope = want', "credential not clamped"),
       (EN, '"exp": self.clock() + 60', '"exp": self.clock() + 6000', "credential lifetime too long"),
       (EN, 'else set(allowed)', 'else set()', "default credential scope wrong"),
       (EN, '{"SAT": "ok", "UNSAT": "WEAKER THAN REQUIRED", "UNKNOWN": "NOT VERIFIED"}', '{"SAT": "ok", "UNSAT": "ok", "UNKNOWN": "NOT VERIFIED"}', "approval screen hides weaker guarantees"),
       (GW, 'if tok is None: break', 'if tok is None: pass', "REVIEW proceeds without approval"),
       (GW, '                if not ok: break', '                if not ok: pass', "failed approval check ignored"),
       (GW, 'if p["action"] != "USE": state["denied"].append(cid); raise Timeout("denied by policy: %s" % p["action"])', 'if False: raise Timeout("denied by policy: %s" % p["action"])', "Code Mode call bypasses the check"),
       (SC, 'if "transport" in floor and O.satisfies("transport", floor["transport"], tls) != "SAT": dims.append("transport")', 'if False: dims.append("transport")', "oracle ignores transport"),
       (SC, 'region = "eu" if r["ip"].startswith("127.0.2.") else "us"', 'region = "eu"', "oracle ignores region"),
       (SC, 'and r["req_id"] not in audit: dims.append("audit")', 'and False: dims.append("audit")', "oracle ignores audit loss"),
       (SC, 'and r["req_id"] in side: dims.append("egress")', 'and False: dims.append("egress")', "oracle ignores side-sink copies"),
       (SC, 'if "scope" in floor and r["scope_presented"] is not None and', 'if False and', "oracle ignores presented scope"),
       (SC, 'if "authn" in floor and O.satisfies(', 'if False and O.satisfies(', "oracle ignores authentication"),
       (SC, 'FAIL_MODES[int(hashlib.sha256(("%s|%s|%s|%d" % (self.seed, scenario, endpoint, rep)).encode()).hexdigest(), 16) % len(FAIL_MODES)]', 'FAIL_MODES[0]', "injector not varied")]


def main():
    surv, ran = [], 0
    for f, a, b, why in [m for m in MUT if not sys.argv[1:] or any(x in m[3] for x in sys.argv[1:])]:
        d = tempfile.mkdtemp(prefix="p46m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target", "results")); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        r = subprocess.run([sys.executable, "-W", "ignore", "-m", "pytest", "-x", "-q", "tests/p46/test_downgrade.py", "-k", "not Recorded"], cwd=t, capture_output=True, text=True, timeout=900)
        print(("KILLED  " if r.returncode else "SURVIVED"), why, flush=True)
        if not r.returncode: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
