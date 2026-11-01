#!/usr/bin/env python3
"""Mutation check for P53: each mutant must make tests.p53.test_continuity fail (run on a copy of the tree). A pytest timeout counts as KILLED. Optional argv: only mutants whose description contains one of the words."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); P = lambda x: "horizon/continuity/%s.py" % x
CO, MI, RT, SV, OR, WO, EX = [P(x) for x in ("core", "migrate", "runtime", "services", "oracle", "world", "experiment")]
MUT = [(CO, 'if miss: raise EnvError("MISSING_SECTION"', 'if False: raise EnvError("MISSING_SECTION"', "missing section accepted"),
       (CO, 'if extra: raise EnvError("EXTRA_SECTION"', 'if False: raise EnvError("EXTRA_SECTION"', "extra section accepted"),
       (CO, 'or not 0 <= v <= CONTROLS[k]', '', "control level range unchecked"),
       (CO, 'if CANARY.encode() in canonical(env): raise EnvError("RAW_SECRET")', 'if False: raise EnvError("RAW_SECRET")', "raw secret accepted in an envelope"),
       (CO, 'any(set(x) != set(CRED_KEYS) for x in env["credentials"])', 'False', "credential value field accepted"),
       (CO, 'or env["exp"] <= env["iat"]', '', "expiry before issue accepted"),
       (CO, 'if guarantees.get(c, 0) < lvl]', 'if guarantees.get(c, 0) <= lvl]', "coverage boundary strict"),
       (CO, 'guarantees.get(c, 0) < lvl', 'guarantees.get(c, 1) < lvl', "absent guarantee counted as present"),
       (CO, 'out.append("PERMISSIONS_WIDENED")', 'pass', "permission widening allowed"),
       (CO, 'out.append("CHAIN_CHANGED")', 'pass', "principal chain change allowed"),
       (CO, 'if lab is None or any(d not in lab for d in labels_truth): out.append("LABEL_DROPPED")', 'if False: out.append("LABEL_DROPPED")', "dropped labels allowed"),
       (CO, 'rank(lab[d]) < rank(l)', 'rank(lab[d]) > rank(l)', "lowered label allowed"),
       (MI, 'if p["role"] != "source-runtime" or p["claim"].get("k") != "envelope": return', 'if False: return', "envelope token kind unchecked"),
       (MI, 'if c.signature and p["args_digest"] != C.digest(env): return ["ENVELOPE_DIGEST"], False', 'if False: return ["ENVELOPE_DIGEST"], False', "envelope not bound to its token"),
       (MI, '(p["artifact"] != env.get("task") or p["nonce"] != env.get("resume_nonce"))', 'False', "token not bound to task and nonce"),
       (MI, 'if c.nonce and p["nonce"] in w.used_nonces: return ["REPLAY"], False', 'if False: return ["REPLAY"], False', "replay accepted"),
       (MI, 'w.used_nonces.add(env["resume_nonce"])', 'pass', "envelope never consumed"),
       (MI, 'if c.expiry and not env["iat"] <= now < env["exp"]', 'if c.expiry and not env["iat"] <= now', "envelope expiry unchecked"),
       (MI, 'if st == "REVOKED": return ["REVOKED"], False', 'if False: return ["REVOKED"], False', "revocation ignored at admission"),
       (MI, 'if st == "UNKNOWN" and c.fail_closed: return ["REVOCATION_UNKNOWN"], True', 'if False: return ["REVOCATION_UNKNOWN"], True', "feed outage fails open at admission"),
       (MI, 'except KeyError: return ["NO_ATTESTATION"], True', 'except KeyError: return ["NO_ATTESTATION"], False', "unattested target not reported UNKNOWN"),
       (MI, 'if ap["role"] != "attestor": return', 'if False: return', "attestation role unchecked"),
       (MI, 'cl["rt"] != tgt.id or ap["principal"] != tgt.id or ap["args_digest"] != C.digest(cl)', 'False', "attestation identity unchecked"),
       (MI, 'miss = C.covers(env["controls"], cl["g"])', 'miss = []', "coverage not checked"),
       (MI, 'if c.sink_policy and not cl["sm"]: return ["SINK_UNVERIFIED"], True', 'if False: return ["SINK_UNVERIFIED"], True', "unmediated sink accepted"),
       (MI, 'if c.rollback and w.source_alive: w.src.unfreeze(); st = "ROLLED_BACK"', 'if False: w.src.unfreeze(); st = "ROLLED_BACK"', "no rollback after failed admission"),
       (MI, 'if c.broker_rebind: w.broker.revoke_runtime(s.id); S["cred"]', 'if c.broker_rebind: S["cred"]', "source credential not revoked"),
       (MI, 'S["cred"] = w.broker.issue(env["task"], tgt.id, "read")', 'S["cred"] = env["credentials"][0]["handle"]', "credential not re-issued for the target"),
       (MI, 'if not c.approval_expiry or a["exp"] > w.clock()}', 'if True}', "expired approvals carried"),
       (MI, 'S["ledger"] = c.ledger;', 'S["ledger"] = False;', "shared ledger not used"),
       (MI, 'S["obligations"] = [dict(o) for o in env["obligations"]] if c.obligations_carry and "obligations" in env else None', 'S["obligations"] = None', "obligations dropped"),
       (MI, 'S["labels"] = dict(env["labels"]) if c.labels_carry and "labels" in env else None', 'S["labels"] = None', "labels dropped"),
       (MI, 'S["done"] = set(env["ops"]["done"])', 'S["done"] = set()', "completed calls not carried"),
       (MI, 'if c.freeze: src.freeze()', 'pass', "source not frozen before checkpoint"),
       (MI, 'if c.drain: w.drain(src)', 'pass', "in-flight calls not drained"),
       (MI, 'min(env["controls"].get(k, 0), tgt.supports.get(k, 0))', 'env["controls"].get(k, 0)', "target enforcement assumed rather than supported"),
       (MI, 'tgt.eff = dict(tgt.defaults)\n', 'tgt.eff = {k: 1 for k in tgt.defaults}\n', "baseline enforces more than the target default"),
       (MI, 'if n == "restrictive-rule": ok = tgt.vendor == src.vendor', 'if n == "restrictive-rule": ok = True', "hand-written rule allows other vendors"),
       (MI, 'if n == "tool-name-check": ok = set(src.tools) <= set(tgt.tools)', 'if n == "tool-name-check": ok = True', "tool-name check not applied"),
       (RT, 'if o["host"] not in C.ALLOWED[eff.get("egress", 0)]: return "DENIED", "EGRESS"', 'if False: return "DENIED", "EGRESS"', "egress not enforced"),
       (RT, 'if eff.get("secret_export"): return "DENIED", "SECRET_EXPORT"', 'if False: return "DENIED", "SECRET_EXPORT"', "secret export not enforced"),
       (RT, 'if eff.get("label") and lab is not None and C.rank(lab) >= 2', 'if eff.get("label") and lab is not None and C.rank(lab) >= 3', "label not enforced"),
       (RT, 'if S["spent"] + n > S["caps"].get("api", 0): return "DENIED", "BUDGET"', 'if False: return "DENIED", "BUDGET"', "local budget not enforced"),
       (RT, 'if not w.ledger.charge("api", n): return "DENIED", "BUDGET"', 'if False: return "DENIED", "BUDGET"', "ledger budget not enforced"),
       (RT, 'if not ap or (ap.get("exp") is not None and ap["exp"] <= w.clock()): return "DENIED", "APPROVAL"', 'if not ap: return "DENIED", "APPROVAL"', "approval expiry not enforced by the runtime"),
       (RT, 'if o["action"] not in S["perms"]: return "DENIED", "PERMISSION"', 'if False: return "DENIED", "PERMISSION"', "permissions not enforced"),
       (RT, 'if eff.get("obligation") and any(ob["status"] != "done" for ob in S["obligations"] or []): return "DENIED", "OBLIGATION_PENDING"', 'if False: return "DENIED", "OBLIGATION_PENDING"', "obligation not enforced at finish"),
       (RT, 'if st != "LIVE": return "DENIED", "REVOKED" if st == "REVOKED" else "REVOCATION_UNKNOWN"', 'if st == "REVOKED": return "DENIED", "REVOKED"', "runtime fails open on feed outage"),
       (RT, 'if rid in S["done"]: return "OK", "DEDUP"', 'if False: return "OK", "DEDUP"', "retries not deduplicated"),
       (RT, 'eff = self.eff if self.sinks_mediated else {}', 'eff = self.eff', "unmediated sink still enforced"),
       (RT, 'if self.frozen: return "DENIED", "FROZEN"', 'if False: return "DENIED", "FROZEN"', "frozen runtime acts"),
       (SV, 'return c["rt"] == rt and not c["revoked"]' if False else 'return bool(c) and c["rt"] == rt and not c["revoked"]', 'return bool(c) and not c["revoked"]', "credential not bound to a runtime"),
       (SV, 'if self.spent.get(name, 0) + n > self.caps.get(name, 0): return False', 'if self.spent.get(name, 0) + n > self.caps.get(name, 0) + 1: return False', "ledger cap boundary"),
       (SV, 'if not self.feed_up: return "UNKNOWN"', 'if not self.feed_up: return "LIVE"', "feed outage reported as live"),
       (SV, 'g = self.deceived.get(r.id, r.supports)', 'g = r.supports | {"egress": 2}', "attestation overstates the target"),
       (OR, 'if spent[e["budget"]] > m["caps"][e["budget"]]', 'if spent[e["budget"]] > m["caps"][e["budget"]] + 100', "oracle ignores budget"),
       (OR, 'if C.CANARY in json.dumps(e.get("data", ""))', 'if False', "oracle ignores secret export"),
       (OR, 'if e["rid"] in seen: k.append("DUPLICATE_EFFECT")', 'if False: k.append("DUPLICATE_EFFECT")', "oracle ignores duplicates"),
       (OR, 'if e["rt"] == "src" and tgt_started: k.append("SPLIT_BRAIN")', 'if False: k.append("SPLIT_BRAIN")', "oracle ignores split brain"),
       (OR, 'a["exp"] <= e["at"]', 'a["exp"] <= -1', "oracle ignores approval expiry"),
       (OR, 'any(o not in audits for o in m["obligations"])', 'False', "oracle ignores lost obligations"),
       (WO, 'f, rt.frozen = rt.frozen, False', 'f = rt.frozen', "drain blocked by the freeze"),
       (EX, '"unsupported_unflagged_with_effect": [r["scenario"] for r in U if r["violations"] and not r["unknown"]]', '"unsupported_unflagged_with_effect": []', "unflagged effects hidden")]


def main():
    surv, ran = [], 0
    for f, a, b, why in [m for m in MUT if not sys.argv[1:] or any(x in m[3] for x in sys.argv[1:])]:
        d = tempfile.mkdtemp(prefix="p53m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target", "results")); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        try: r = subprocess.run([sys.executable, "-W", "ignore", "-m", "pytest", "-x", "-q", "tests/p53/test_continuity.py", "-k", "not Recorded and not Gates"], cwd=t, capture_output=True, text=True, timeout=240); rc = r.returncode
        except subprocess.TimeoutExpired: rc = 1
        print(("KILLED  " if rc else "SURVIVED"), why, flush=True)
        if not rc: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
