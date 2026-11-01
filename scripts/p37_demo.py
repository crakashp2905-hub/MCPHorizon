#!/usr/bin/env python3
"""P37-14: runs the demo in a FRESH local clone with an empty environment, inside a network namespace with no interfaces (if `unshare -n` works), and records the actual commands, exit codes, wall times and output in docs/evidence/p37/DEMO.md.
The record is a log of one real execution, not a reproducible byte-for-byte artifact (timings vary)."""
import os, platform, shutil, subprocess, sys, tempfile, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def sh(cmd, cwd, env=None):
    t = time.time(); p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=900); return {"cmd": " ".join(cmd), "rc": p.returncode, "sec": round(time.time() - t, 1), "out": (p.stdout + p.stderr).strip()}
def main():
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(); work = tempfile.mkdtemp(prefix="h4demo-"); clone = os.path.join(work, "clone"); steps = []
    steps.append(sh(["git", "clone", "--quiet", "--no-hardlinks", ROOT, clone], work)); steps.append(sh(["git", "checkout", "--quiet", head], clone))
    env = {"PATH": os.environ["PATH"], "HOME": os.path.join(work, "home"), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}; os.makedirs(env["HOME"])
    # loopback inside a fresh netns is down: bench/h4/netns_lo.py brings only `lo` up before exec
    probe = subprocess.run(["unshare", "-n", "true"], capture_output=True); netns = probe.returncode == 0; pre = ["unshare", "-n", sys.executable, "bench/h4/netns_lo.py"] if netns else []
    steps.append(sh(pre + ["python3", "-c", "import socket,sys\ns = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(); socket.create_connection(s.getsockname(), timeout=1); print('loopback reachable')\ntry:\n    socket.create_connection(('127.0.0.1', 9), timeout=1)\nexcept OSError as e: print('loopback+external connect refused/unreachable:', type(e).__name__)\ntry:\n    socket.create_connection(('192.0.2.1', 80), timeout=1); print('EXTERNAL REACHABLE'); sys.exit(1)\nexcept OSError as e: print('external (TEST-NET) unreachable:', type(e).__name__)"], clone, env))
    steps.append(sh(pre + ["python3", "-W", "ignore", "bench/h4/demo.py"], clone, env))
    steps.append(sh(pre + ["python3", "-W", "ignore", "-m", "unittest", "tests.p37.test_h4.Counts", "tests.p37.test_h4.Lint", "tests.p37.test_h4.Oracles", "-v"], clone, env))
    steps.append(sh(pre + ["python3", "bench/h4/run.py", "check"], clone, env))
    L = ["# P37 end-to-end demo — recorded execution (CANDIDATE)", "", f"* source: local clone of this repository at `{head}` (no network fetch)", f"* isolation: empty environment (`env` has only PATH, HOME=temp, LANG); network namespace via `unshare -n`: **{'yes' if netns else 'NO (unshare unavailable; ran without network namespace)'}**",
         f"* machine: {platform.system()} {platform.release()} {platform.machine()}, Python {platform.python_version()}", "* The scenarios run only loopback/in-process synthetic fixtures; nothing is contacted.", ""]
    for i, s in enumerate(steps, 1):
        L += [f"## Step {i}: `{s['cmd']}`", f"exit code **{s['rc']}**, wall {s['sec']} s", "", "```", s["out"][-3500:], "```", ""]
    ok = all(s["rc"] == 0 for s in steps); L.append(f"**Overall: {'ALL STEPS EXIT 0' if ok else 'FAILURE'}**"); shutil.rmtree(work, ignore_errors=True)
    open(os.path.join(ROOT, "docs", "evidence", "p37", "DEMO.md"), "w").write("\n".join(L) + "\n"); print("overall", "ok" if ok else "FAIL"); sys.exit(0 if ok else 1)
main()
