"""Dataset validator mutation check. Timeout counts as killed."""
import subprocess, sys, os
F = "bench/real/datasets.py"
M = [(F, 'if rep["license"] in ("NONE", "UNRECOGNISED"):', 'if False:'),
     (F, 'if not files:\n        reasons.append("no parsable data files")', 'if False:\n        reasons.append("no parsable data files")'),
     (F, 'if n_fail:\n        reasons.append(f"{n_fail} parse failures")', 'if False:\n        reasons.append("x")'),
     (F, 'if n_lfs:\n        reasons.append', 'if False:\n        reasons.append'),
     (F, 'if head.startswith(b"version ', 'if False and head.startswith(b"version '),
     (F, '            if k in seen:\n                n_dups += 1', '            if False:\n                n_dups += 1'),
     (F, 'if SECRET.search(k if isinstance(k, str) else ""):', 'if False:'),
     (F, 'tree.update(rel.encode()); tree.update(bytes.fromhex(sha256_file(p)))', 'tree.update(rel.encode())'),
     (F, '.rstrip("/").removesuffix(".git") == expect_url.lower().rstrip("/")', '.rstrip("/") == expect_url.lower().rstrip("/")'),
     (F, '(expect_url is None or (rep["origin"] or "").lower()', '(True or (rep["origin"] or "").lower()'),
     (F, 'dirs[:] = [x for x in dirs if x not in (".git", "node_modules")]', 'pass'),
     (F, 'if any(rel.startswith(s) for s in skip_dirs):', 'if False:'),
     (F, 'delim = "\\t" if low.endswith(".tsv") else ","', 'delim = ","'),
     (F, '("Apache-2.0", r"apache license,? version 2\\.0")', '("Apache-2.0", r"zzz")'),
     (F, 'rep["status"] = "PASS" if not reasons else "WARN"', 'rep["status"] = "PASS"'),
     (F, 'if fn.lower().endswith(DATA_EXT) and not NON_DATA.match(fn):', 'if fn.lower().endswith(DATA_EXT):'),
     (F, 'x not in (".git", "node_modules")', 'x not in (".git",)'),
     (F, '"non-commercial" if "NC" in lic', '"none-known" if "NC" in lic'),
     (F, '"custom/restricted" if "custom" in lic', '"none-known" if "custom" in lic'),
     ]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.real.test_datasets"], capture_output=True, timeout=180, env=env).returncode
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
