"""Dataset generator/scorer/defender mutation check. Timeout counts as killed. Mutates source, regenerates nothing (committed files stay), tests must notice via --check or logic tests."""
import subprocess, sys, os
M = [("bench/dataset/generate.py", '"heldout" if split_kind == "heldout"', '"train" if split_kind == "heldout"'), ("bench/dataset/generate.py", 'tpl == 2 else', 'tpl == 1 else'),
     ("bench/dataset/generate.py", 'identifiable = fam != "F11_opaque_offhost"', 'identifiable = True'), ("bench/dataset/generate.py", '"UNKNOWN" if not identifiable', '"ALLOW" if not identifiable'),
     ("bench/dataset/generate.py", 'dest = host if attack else good', 'dest = host'), ("bench/dataset/generate.py", '[] if fam == "F11_opaque_offhost" else ["sink"]', '["sink"]'),
     ("bench/dataset/evaluate.py", 'if missing: raise ValueError', 'if False: raise ValueError'), ("bench/dataset/evaluate.py", 'if n == 0: return None', 'if n == 0: return [0, 1]'),
     ("bench/dataset/evaluate.py", 'decisions[s["id"]] == "ALLOW"); bu', 'decisions[s["id"]] != "BLOCK"); bu'),
     ("bench/dataset/reference_defender.py", 'if host not in APPROVED_HOSTS: return "BLOCK"', 'pass'), ("bench/dataset/reference_defender.py", 'if p and (p in used or p in revoked): return "BLOCK"', 'pass'),
     ("bench/dataset/reference_defender.py", 'if len(set(digests)) > 1: return "BLOCK"', 'pass'), ("bench/dataset/reference_defender.py", 'return "UNKNOWN" if unknown else "ALLOW"', 'return "ALLOW"')]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.ds.test_dataset"], capture_output=True, timeout=120, env=env).returncode
    except subprocess.TimeoutExpired: return 1
assert run() == 0; surv = []
for f, a, b in M:
    src = open(f).read()
    if a not in src: surv.append(("MISSING", f, a)); continue
    try:
        open(f, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", f, a))
    finally: open(f, "w").write(src)
print(f"{len(M)-len(surv)}/{len(M)} killed"); [print(*x) for x in surv]; sys.exit(1 if surv else 0)
