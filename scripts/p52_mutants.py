#!/usr/bin/env python3
"""Mutation check for P52: each mutant must make tests.p52.test_temporal fail (run on a copy of the tree). A pytest timeout counts as KILLED. Optional argv: only mutants whose description contains one of the words."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); P = lambda x: "horizon/temporal/%s.py" % x
CO, GA, ST, AP, OR, WO, NE, EX = [P(x) for x in ("core", "gate", "store", "approver", "oracle", "world", "net", "experiment")]
MUT = [(CO, 'if "export" not in scopes: return False, "NO_GRANT"', 'if False: return False, "NO_GRANT"', "policy ignores the grant"),
       (CO, 'not set(ips) <= set(d["ips"])', 'not set(ips) & set(d["ips"]) == set()', "any matching address accepted"),
       (CO, 'if r.get("internal_dest_only") and not d["internal"]', 'if False and not d["internal"]', "internal-only rule ignored"),
       (CO, 'if r.get("needs_scope") and r["needs_scope"] not in scopes', 'if False', "needed scope ignored"),
       (CO, 'def slice_ids(cls, host): return ["export." + cls, "dest." + host]', 'def slice_ids(cls, host): return ["export." + cls]', "policy slice ignores the destination rule"),
       (CO, 'versions.get(i, 0), rules.get(i)]', 'versions.get(i, 0)]', "policy slice ignores rule content"),
       (CO, '"d": [host, short(sorted(ips))]', '"d": [host, ""]', "vector ignores the addresses"),
       (CO, '"c": content_d}', '"c": ""}', "vector ignores the content"),
       (CO, '"g": [grant[0], grant[1], sorted(grant[2])]', '"g": [grant[0], 0, sorted(grant[2])]', "vector ignores the grant version"),
       (CO, '{"op": op, "actor": actor, "obj": obj_id, "host": host, "vec": vec}', '{"op": op, "obj": obj_id, "host": host, "vec": vec}', "envelope ignores the actor"),
       (GA, 'if c.actor and p["principal"] != caller', 'if False and p["principal"] != caller', "actor not checked"),
       (GA, 'if host != act["host"]: return self._deny(w, ctx, "HOST_MISMATCH")', 'if False: return self._deny(w, ctx, "HOST_MISMATCH")', "host not checked"),
       (GA, 'if c.object_id and p["artifact"] != act["obj"]', 'if False and p["artifact"] != act["obj"]', "object identity not checked"),
       (GA, 'if c.nonce and ap["used"]', 'if False and ap["used"]', "replay allowed"),
       (GA, 'if c.nonce: w.store.mark_used(k["approval"])', 'if False: w.store.mark_used(k["approval"])', "approval never consumed"),
       (GA, 'if ap["revoked"] or w.store.revoked_since(p["nonce"], ap["issued_seq"])', 'if False', "revocation ignored"),
       (GA, 'if c.fail_closed: return self._deny(w, ctx, "REVOCATION_FEED_DOWN", "UNKNOWN")', 'if False: return self._deny(w, ctx, "REVOCATION_FEED_DOWN", "UNKNOWN")', "feed outage fails open"),
       (GA, 'ips = w.net.resolve(host) if c.destination else ap["claim"]["ips"]', 'ips = ap["claim"]["ips"]', "destination not re-resolved"),
       (GA, 'ip = k["ips"][0] if c.destination and k["ips"] else w.net.connect(host)', 'ip = w.net.connect(host)', "destination not pinned"),
       (GA, 'if d is None or not hop or not set(hop) <= set(d["ips"]): return self._deny(w, ctx, "REDIRECT_DENIED")', 'if False: return self._deny(w, ctx, "REDIRECT_DENIED")', "redirect target not checked"),
       (GA, 'if c.policy_recheck:', 'if False:', "policy not re-evaluated"),
       (GA, '("OBJECT_VERSION", claim["o"][1], now_v["o"][1], c.object_version)', '("OBJECT_VERSION", claim["o"][1], claim["o"][1], c.object_version)', "object version not compared"),
       (GA, '("CONTENT_CHANGED", claim["c"], now_v["c"], c.content)', '("CONTENT_CHANGED", claim["c"], claim["c"], c.content)', "content digest not compared"),
       (GA, '("GRANT_CHANGED", claim["g"], now_v["g"], c.grant)', '("GRANT_CHANGED", claim["g"], claim["g"], c.grant)', "grant not compared"),
       (GA, '("POLICY_CHANGED", claim["s"], now_v["s"], c.policy_slice)', '("POLICY_CHANGED", claim["s"], claim["s"], c.policy_slice)', "policy slice not compared"),
       (GA, 'if c.idempotent and rid in w.done', 'if False and rid in w.done', "retries not idempotent"),
       (GA, 'now = int(w.clock() if c.authoritative_clock else w.worker_clock())', 'now = int(w.worker_clock())', "expiry on the worker clock"),
       (GA, 'def phases(self, w): return 1 if (self.cfg.atomic and w.sink_atomic) else 2', 'def phases(self, w): return 2', "check and effect never atomic"),
       (GA, 'if self.cfg.cas_writes: return w.store.cas_update(obj, base_version, content=content)', 'if False: return w.store.cas_update(obj, base_version, content=content)', "writes unconditional"),
       (GA, 'if p["args_digest"] != C.digest(C.envelope("export", p["principal"], p["artifact"], host, claim))', 'if False', "token not bound to the envelope"),
       (GA, 'w.pending.append((k, host, ip, final)); r = _res(ctx["rid"], "UNKNOWN", "DEFERRED_EXTERNAL_EFFECT")', 'w.pending.append((k, host, ip, final)); r = _res(ctx["rid"], "OK", "DEFERRED_EXTERNAL_EFFECT")', "deferred effect reported OK"),
       (GA, '"OK" if w.sink_atomic else "UNKNOWN"', '"OK"', "unconditional sink reported OK"),
       (ST, 'if r is None or r[0] != expected_version:', 'if r is None:', "compare-and-swap does not compare"),
       (ST, 'int(C.CANARY in o["content"])', '0', "effect record hides the canary"),
       (ST, 'rules.get("dest." + final_host)', 'rules.get("dest." + host)', "effect record reads the wrong destination rule"),
       (AP, 'if not ok: return None', 'if False: return None', "approver approves forbidden actions"),
       (AP, 'ttl=60', 'ttl=6000', "default approval lifetime long"),
       (AP, 'self.s.rev_seq(), self.clock(), self.clock() + ttl', 'self.s.rev_seq(), self.clock(), self.clock() + 10 * ttl', "ledger expiry longer than the token"),
       (OR, 'if not (a["iat"] <= e["at"] < a["exp"])', 'if False', "oracle ignores expiry"),
       (OR, 'if per[e["approval"]] > 1:', 'if False:', "oracle ignores replay"),
       (OR, 'if e["content_d"] != c["c"]: why.append("CONTENT_CHANGED")', 'if False: why.append("CONTENT_CHANGED")', "oracle ignores content change"),
       (OR, 'if e["canary"]: why.append("CANARY_EXPORTED")', 'if False: why.append("CANARY_EXPORTED")', "oracle ignores the canary"),
       (OR, 'if base != actual:', 'if False:', "oracle ignores lost updates"),
       (OR, 'a["issued_seq"] < x["seq"] <= e["rev_seq"]', 'a["issued_seq"] < x["seq"] <= 0', "oracle ignores revocation"),
       (WO, 'w.reapprovals = getattr(w, "reapprovals", 0) + 1; ', '', "re-approvals not counted"),
       (WO, 'return self.t[0] + self.skew', 'return self.t[0]', "worker skew ignored"),
       (NE, 'self.redirects.get(host)', 'None', "redirects never followed"),
       (EX, '"unknown_orders": sum(1 for r in R if r["unknown"])', '"unknown_orders": 0', "UNKNOWN not counted"),
       (EX, '"stale_only_orders": len(bad) - len(harm)', '"stale_only_orders": 0', "stale-only effects not separated")]


def main():
    surv, ran = [], 0
    for f, a, b, why in [m for m in MUT if not sys.argv[1:] or any(x in m[3] for x in sys.argv[1:])]:
        d = tempfile.mkdtemp(prefix="p52m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target", "results")); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        try: r = subprocess.run([sys.executable, "-W", "ignore", "-m", "pytest", "-x", "-q", "tests/p52/test_temporal.py", "-k", "not Recorded and not Gates"], cwd=t, capture_output=True, text=True, timeout=240); rc = r.returncode
        except subprocess.TimeoutExpired: rc = 1
        print(("KILLED  " if rc else "SURVIVED"), why, flush=True)
        if not rc: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
