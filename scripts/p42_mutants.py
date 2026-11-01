#!/usr/bin/env python3
"""Mutation check for P42: each mutant must make the (non-live) P42 tests fail on a copy of the tree. Live-sandbox mutants are checked with the Live class when running as root."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); EN, HA, RG = "horizon/coverage/engine.py", "horizon/coverage/harness.py", "horizon/coverage/regress.py"
FAST = ["tests.p42.test_coverage.Classify", "tests.p42.test_coverage.States", "tests.p42.test_coverage.Claims", "tests.p42.test_coverage.Streams", "tests.p42.test_coverage.Recorded"]
MUT = [(EN, 'if now >= bundle["issued_at"] + bundle["ttl_s"]: why.append("TTL_EXPIRED")', "pass", "TTL ignored"),
       (EN, 'if current.get(k) != v: why.append("INVALIDATED:" + k)', "pass", "component change does not invalidate"),
       (EN, 'if st == "VERIFIED" and why: st = "UNKNOWN"', "pass", "stale VERIFIED kept"),
       (EN, 'if bundle["issued_at"] > now + 5:', "if False:", "future-dated evidence accepted"),
       (EN, 'bad = {i: st.get(i, "MISSING") for i in need if st.get(i) != "VERIFIED"}', 'bad = {i: st.get(i, "MISSING") for i in need if st.get(i) == "MISSING"}', "UNKNOWN sink still supports a claim"),
       (EN, 'if not self.up: self.dropped.append((seq, "COLLECTOR_DOWN")); return False', "pass", "events during outage not recorded as gap"),
       (EN, 'if len(self.q) >= self.cap: self.dropped.append((seq, "BACKPRESSURE")); return False', "pass", "backpressure overflow silently accepted"),
       (EN, "self.epoch += 1; self.q.clear()", "self.epoch += 1", "restart keeps lost queue (gap hidden)"),
       (EN, 'return ("VERIFIED", []) if not self.gaps(last_seq) else ("UNKNOWN", self.gaps(last_seq))', 'return ("VERIFIED", [])', "gaps still VERIFIED window"),
       (EN, '"state": "VERIFIED" if H_ == A else "UNKNOWN"}', '"state": "VERIFIED"}', "host-only effects not flagged"),
       (EN, '"state": "VERIFIED" if r["ok"] else "UNKNOWN"', '"state": "VERIFIED"', "tampered log still VERIFIED"),
       (HA, 'elif all(w is True for w in wk): obs = ("VERIFIED"', 'elif any(w is True for w in wk): obs = ("VERIFIED"', "partially blind observer VERIFIED"),
       (HA, 'elif any(x is True for x in st): enf = ("MISSING"', 'elif False: enf = ("MISSING"', "leak under enforcement not flagged"),
       (HA, 'elif obs[0] == "VERIFIED" and all(x is False for x in st): enf', 'elif all(x is False for x in st): enf', "enforcement verified without calibrated observer"),
       (HA, 'if s["observation_channel"] is None: obs = ("MISSING"', 'if False: obs = ("MISSING"', "missing observation channel not MISSING"),
       (HA, 'if s["enforcement_point"] is None: enf = ("MISSING"', 'if False: enf = ("MISSING"', "missing enforcement point not MISSING"),
       (HA, "overall = max((enf[0], obs[0]), key=lambda x: order[x])", "overall = min((enf[0], obs[0]), key=lambda x: order[x])", "overall is best-of instead of worst-of"),
       (HA, 'if ref: return {"enforcement": ("UNKNOWN"', 'if False: return {"enforcement": ("UNKNOWN"', "sandbox refusal not UNKNOWN"),
       (EN, "return {k: v for", "return {k: v for", "(placeholder never applicable)")][:-1]


def main():
    surv, ran = [], 0
    for f, a, b, why in MUT:
        d = tempfile.mkdtemp(prefix="p42m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target")); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        r = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", *FAST], cwd=t, capture_output=True, text=True, timeout=900)
        print(("KILLED  " if r.returncode else "SURVIVED"), why)
        if not r.returncode: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
