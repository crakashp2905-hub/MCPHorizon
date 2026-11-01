#!/usr/bin/env python3
"""P38-16 / MG-G12 (author-run part): reproduces the checks from a FRESH local clone with an empty environment inside a network namespace, then records actual commands, exit codes and times in docs/evidence/p38/CLEAN_REPRO.md.
This is a clean-environment reproduction BY THE AUTHOR. It is not independent reproduction: MG-G12 stays NOT MET until another maintainer does this."""
import os, platform, shutil, subprocess, sys, tempfile, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# CleanRepro (a test class) is excluded from the p38 run below: it checks the record this very run produces
CMDS = [["python3", "scripts/p38_runner_check.py", "--require"], ["python3", "scripts/p23_freeze.py", "--check"], ["python3", "scripts/hr_gates.py", "--check"], ["python3", "bench/h4/run.py", "check"], ["python3", "bench/h4/report.py", "--check"], ["python3", "bench/haa/aggregate.py", "results/v2/haa-main", "--check"],
        ["python3", "scripts/p38_casebook.py", "--check"], ["python3", "scripts/p38_compare.py", "--check"], ["python3", "scripts/p38_papers.py", "--check"], ["python3", "scripts/p38_gates.py", "--check"], ["python3", "scripts/p30_no_external.py"], ["python3", "scripts/p30_claims_audit.py"],
        ["python3", "-W", "ignore", "-m", "unittest", "tests.p31.test_intake", "tests.p32.test_triggerlab", "tests.p36.test_guard", "tests.p37.test_h4"] + [f"tests.p38.test_p38.{c}" for c in ("Casebook", "Matrix", "Runner", "LayerDocs", "SinkRepro", "Drills", "Comparison", "Gates", "Papers", "Bundle")]  ,
        ["python3", "-W", "ignore", "-m", "unittest", "tests.p33.test_hccb", "tests.p34.test_isolation", "tests.p35.test_telemetry", "tests.p29.test_haa", "tests.p30.test_p30"]]
def sh(cmd, cwd, env):
    t = time.time(); p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=1500); o = (p.stdout + p.stderr).strip().splitlines(); return {"cmd": " ".join(cmd[3:] if cmd[:2] == ["unshare", "-n"] else cmd), "rc": p.returncode, "sec": round(time.time() - t, 1), "tail": "\n".join(o[-4:])}
def main():
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(); dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip())
    work = tempfile.mkdtemp(prefix="h4repro-"); clone = os.path.join(work, "clone"); subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", ROOT, clone], check=True); subprocess.run(["git", "checkout", "--quiet", head], cwd=clone, check=True)
    env = {"PATH": os.environ["PATH"], "HOME": os.path.join(work, "home"), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}; os.makedirs(env["HOME"]); pre = ["unshare", "-n", sys.executable, "bench/h4/netns_lo.py"]
    rs = [sh(pre + c, clone, env) for c in CMDS]; ok = all(r["rc"] == 0 for r in rs)
    L = ["# P38-16 clean-environment reproduction — author-run (NOT independent)", "", f"* commit: `{head}`" + (" (**working tree had uncommitted changes; the clone contains only committed files**)" if dirty else ""), "* fresh `git clone` of the local repository, empty environment (PATH, HOME=temp, LANG), network namespace with only loopback up", f"* machine: {platform.system()} {platform.release()} {platform.machine()}, Python {platform.python_version()}",
         "* **Who ran this:** the author of the code under test. MG-G12 requires a different maintainer; this file does not satisfy it.", "", "| # | command | exit | seconds |", "|---|---|---|---|"]
    for i, r in enumerate(rs, 1): L.append(f"| {i} | `{r['cmd']}` | {r['rc']} | {r['sec']} |")
    L += ["", "## Output tails", ""]
    for i, r in enumerate(rs, 1): L += [f"**{i}.** `{r['cmd']}`", "```", r["tail"], "```"]
    L += ["", f"**Overall: {'ALL COMMANDS EXIT 0' if ok else 'FAILURE'}**", ""]; shutil.rmtree(work, ignore_errors=True)
    open(os.path.join(ROOT, "docs", "evidence", "p38", "CLEAN_REPRO.md"), "w").write("\n".join(L)); print("overall", "ok" if ok else "FAIL"); sys.exit(0 if ok else 1)
main()
