"""Novel-ideas mutation check. Timeout counts as killed."""
import subprocess, sys, os
R = "research/novel/"
M = [("coverage.py", "if n == 0: return (0.0, 1.0)", "if n == 0: return (0.0, 0.0)"), ("coverage.py", "elif d != \"COVERED\" or n.get(i, 0) == 0: state[i] = \"UNKNOWN\"", "elif d != \"COVERED\": state[i] = \"UNKNOWN\""),
     ("coverage.py", "elif k[i] < n[i]: state[i] = \"FAILED\"", "elif False: state[i] = \"FAILED\""), ("coverage.py", "if d == \"UNSUPPORTED\": state[i] = \"UNSUPPORTED\"", "if False: state[i] = \"UNSUPPORTED\""),
     ("coverage.py", "(len(cov) / len(sup)) * lo_pass if sup", "(len(cov) / len(sup)) if sup"), ("coverage.py", "if i not in items: raise", "if False: raise"),
     ("permitfuzz.py", "for f, v in CLAIM_ALT.items():\n        tested += 1", "for f, v in ():\n        tested += 1"), ("permitfuzz.py", "EXPECT_UNBOUND = {\"decision_id\"}", "EXPECT_UNBOUND = {\"decision_id\", \"sub\", \"tenant\"}"),
     ("permitfuzz.py", "accepted.append(f\"ce.{f}\")", "pass"),
     ("diffkernel.py", "(\"EXPIRED\", env[\"now\"] <= claim[\"exp\"] + env[\"skew\"])", "(\"EXPIRED\", env[\"now\"] < claim[\"exp\"])"), ("diffkernel.py", "(\"REPLAY\", claim[\"nonce\"] not in seen)", "(\"REPLAY\", True)"),
     ("diffkernel.py", "env[\"policy\"] is None or claim[\"policy_version\"] == env[\"policy\"]", "True"), ("diffkernel.py", "claim[\"exp\"] - claim[\"iat\"] <= env[\"max_ttl\"]", "True"),
     ("diffkernel.py", "claim[\"tenant\"] == req[\"tenant\"]", "True"), ("diffkernel.py", "env[\"now\"] + env[\"skew\"] >= claim[\"iat\"]", "True"),
     ("sinkdiff.py", "removed = [r for r in off if r not in on]", "removed = []"), ("sinkdiff.py", "\"claims_without_effect\": [c for c in claimed if not any(c.split(\":\", 1)[1] == r[1] for r in removed)]", "\"claims_without_effect\": []"),
     ("sinkdiff.py", "added = [r for r in on if r not in off]", "added = []"),
     ("witnesses.py", "HARD = (\"trust_root\", \"signing_key\", \"operator\")", "HARD = (\"trust_root\",)"), ("witnesses.py", "a.get(k) is not None and a.get(k) == b.get(k)) / len(SOFT)", "a.get(k) == b.get(k)) / len(SOFT)"),
     ("witnesses.py", "return similarity(a, b) >= threshold", "return similarity(a, b) > threshold"), ("witnesses.py", "parent[find(a)] = find(b)", "pass"), ("witnesses.py", ">= 2", ">= 1"),
     ("racebench.py", "if ok: acted = True; v = v or revoked", "if ok: acted = True"), ("racebench.py", "if ok and not revoked: acted = True", "if ok: acted = True; v = v or revoked"),
     ("racebench.py", "acted = (not resume_recheck) or (not revoked_at_retry)", "acted = True"),
     ("negreg.py", "if r[\"seq\"] != i or r[\"prev\"] != prev or r[\"hash\"] != _h(raw): return False", "if r[\"hash\"] != _h(raw): return False"), ("negreg.py", "trust.resolve(r[\"kid\"], \"custodian\", now).verify(bytes.fromhex(r[\"sig\"]), raw)", "pass"),
     ("negreg.py", "if outcome not in OUTCOMES: raise", "if False: raise"), ("negreg.py", "r[\"outcome\"] in (\"FAILED\", \"PARTIAL\")", "r[\"outcome\"] in (\"FAILED\",)"), ("negreg.py", "r[\"outcome\"] in (\"FAILED\", \"PARTIAL\")", "True")]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.novel.test_novel"], capture_output=True, timeout=90, env=env).returncode
    except subprocess.TimeoutExpired: return 1
assert run() == 0; surv = []
for f, a, b in M:
    src = open(R + f).read()
    if a not in src: surv.append(("MISSING", f, a)); continue
    try:
        open(R + f, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", f, a))
    finally: open(R + f, "w").write(src)
print(f"{len(M)-len(surv)}/{len(M)} killed"); [print(*x) for x in surv]; sys.exit(1 if surv else 0)
