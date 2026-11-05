"""Mutation check of the REAL implementation (filesink fence, ledger expiry, writer reconcile) against conformance + e04 + e05 tests. Timeout counts as killed."""
import subprocess, sys, os
TESTS = ["tests.commitproof.test_conformance", "tests.e05.test_filesink", "tests.e04.test_ledger", "tests.e06.test_sinkproc"]
M = [("horizon/effects/filesink.py", 'if any(r.get("fence") == effect_id for r in recs): raise SinkError("FENCED"', 'if False: raise SinkError("FENCED"'),
     ("horizon/effects/filesink.py", 'if not any(r.get("fence") == effect_id for r in self._records()):', 'if False:'),
     ("horizon/effects/filesink.py", 'if any(r.get("effect_id") == effect_id and "fence" not in r for r in recs): raise SinkError("ALREADY_WRITTEN"', 'if False: raise SinkError("ALREADY_WRITTEN"'),
     ("horizon/effects/filesink.py", 'obs = self.sink.fence_and_observe(effect_id)', 'obs = self.sink.observed(effect_id)'),
     ("horizon/effects/filesink.py", 'except LedgerError: return {"status": "UNKNOWN" if e.code != "FENCED" else "BLOCKED", "code": e.code}', 'except LedgerError: raise'),
     ("horizon/effects/filesink.py", 'except LedgerError: return {"status": "UNKNOWN", "code": "LEDGER_MOVED_ON", "sink_receipt": rec}', 'except LedgerError: raise'),
     ("horizon/effects/filesink.py", 'with self._locked():\n            recs = self._records()', 'if True:\n            recs = self._records()'),
     ("horizon/effects/sinkproc.py", 'elif req["effect_id"] in fenced: out = {"ok": False, "code": "FENCED"}', 'elif False: out = {"ok": False, "code": "FENCED"}'),
     ("horizon/effects/sinkproc.py", 'if req["effect_id"] not in fenced:\n                fenced.add(req["effect_id"]);', 'if False:\n                fenced.add(req["effect_id"]);'),
     ("horizon/effects/sinkproc.py", 'elif req["effect_id"] in done: out = {"ok": False, "code": "ALREADY_WRITTEN"}', 'elif False: out = {"ok": False, "code": "ALREADY_WRITTEN"}'),
     ("horizon/effects/sinkproc.py", 'if "fence" in r: fenced.add(r["fence"])', 'if "fence" in r: pass'),
     ("horizon/effects/sinkproc.py", 'done[req["effect_id"]] = rec; out =', 'out ='),
     ("horizon/effects/ledger.py", "where state='AUTHORIZED' and ts<=?", "where state in ('AUTHORIZED','STARTED') and ts<=?"),
     ("horizon/effects/ledger.py", "where state='AUTHORIZED' and ts<=?", "where state='AUTHORIZED' and ts<=? and 1=0"),
     ("horizon/effects/ledger.py", 'cut = self.clock() - older_than', 'cut = self.clock() - older_than + 1000000'),
     ("horizon/effects/ledger.py", 'if row[0] != "AUTHORIZED": return False', 'if row[0] not in ("AUTHORIZED", "BLOCKED"): return False'),
     ("horizon/effects/ledger.py", 'for i in ids: self._move(i, "UNKNOWN", {"reason": "crash_recovery"})', 'pass')]
def run():
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", *TESTS], capture_output=True, timeout=240, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1")).returncode
    except subprocess.TimeoutExpired: return 1
if run() != 0: print("BASELINE FAILED"); sys.exit(1)
surv = []
for f, a, b in M:
    src = open(f).read()
    if a not in src: surv.append(("MISSING", f, a)); continue
    try:
        open(f, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", f, a))
    finally: open(f, "w").write(src)
print(f"{len(M) - len(surv)}/{len(M)} killed"); [print(x) for x in surv]; sys.exit(1 if surv else 0)
