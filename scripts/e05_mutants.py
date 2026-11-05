"""ENG-PR05 mutation check. Timeout counts as killed."""
import subprocess, sys, os
G = "horizon/effects/filesink.py"
M = [('real = os.path.realpath(path)', 'real = os.path.abspath(path)'),
     ('if not (real == self.root or real.startswith(self.root + os.sep)): raise', 'if False: raise'),
     ('if real == self.root or os.path.isdir(real): raise', 'if False: raise'),
     ('if ce.args != {"sha256": _h.sha256(data).hexdigest()}: return', 'if False: return'),
     ('if ce.effect != "write" or ce.target_kind != "file": return', 'if False: return'),
     ('try: claim = commit_verify(self.v, token, ce)', 'try: claim = {"nonce": os.urandom(4).hex()}'),
     ('if not self.ledger.begin(effect_id): return {"status": "DUPLICATE"}', 'pass'),
     ('try: self.ledger.finish(effect_id, "UNKNOWN", {"error": type(e).__name__})', 'try: self.ledger.finish(effect_id, "BLOCKED", {"error": type(e).__name__})'),
     ('if not self.ledger.request(effect_id, {"target": ce.target_raw}): return {"status": "DUPLICATE"}', 'self.ledger.request(effect_id, {"target": ce.target_raw})'),
     ('bool(obs and obs["present_now"])', 'bool(obs)'),
     ('"sha256": hashlib.sha256(open(real, "rb").read()).hexdigest(), "bytes"', '"sha256": hashlib.sha256(data[:1]).hexdigest(), "bytes"'),
     ('r["present_now"] = os.path.exists(r["path"]) and hashlib.sha256(open(r["path"], "rb").read()).hexdigest() == r["sha256"]', 'r["present_now"] = True'),
     ('if self.ledger.state(effect_id) == "REQUESTED": self.ledger.block', 'if False: self.ledger.block')]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.e05.test_filesink"], capture_output=True, timeout=60, env=env).returncode
    except subprocess.TimeoutExpired: return 1
src = open(G).read(); assert run() == 0; surv = []
try:
    for a, b in M:
        if a not in src: surv.append(("MISSING", a)); continue
        open(G, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", a))
finally: open(G, "w").write(src)
print(f"{len(M)-len(surv)}/{len(M)} killed"); [print(*x) for x in surv]; sys.exit(1 if surv else 0)
