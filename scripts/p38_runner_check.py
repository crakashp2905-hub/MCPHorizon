#!/usr/bin/env python3
"""P38-05: reports whether THIS runner can execute the kernel-isolation tests. `--require` exits 1 (fail loudly) when it cannot; without it the exit is 0 and the report says SKIPPED so a dashboard cannot read 'green' as 'ran'. Output is one JSON line."""
import json, os, platform, subprocess, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
def probe() -> dict:
    r = {"machine": platform.machine(), "kernel": platform.release(), "euid": os.geteuid(), "landlock_abi": 0, "unshare_netns": False, "ipv6": False}
    try:
        from horizon.runtime import sandbox as S; r["landlock_abi"] = S.landlock_abi()
    except Exception as e: r["landlock_error"] = type(e).__name__
    try: r["unshare_netns"] = subprocess.run(["unshare", "-n", "true"], capture_output=True).returncode == 0
    except OSError: pass
    try:
        import socket; s = socket.socket(socket.AF_INET6); s.bind(("::1", 0)); s.close(); r["ipv6"] = True
    except OSError: pass
    reasons = []
    if r["machine"] != "x86_64": reasons.append("not x86_64")
    if r["euid"] != 0: reasons.append("not root")
    if r["landlock_abi"] < 4: reasons.append("Landlock ABI < 4")
    if not r["unshare_netns"]: reasons.append("cannot create network namespace")
    r["kernel_tests_runnable"] = not reasons; r["reasons"] = reasons; r["verdict"] = "RUN" if not reasons else "SKIPPED_UNSUPPORTED"; return r
if __name__ == "__main__":
    r = probe(); print(json.dumps(r, sort_keys=True)); sys.exit(1 if ("--require" in sys.argv and not r["kernel_tests_runnable"]) else 0)
