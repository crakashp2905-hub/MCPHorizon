"""ENG-PR06-sinkproc mutation check (needs root). Timeout counts as killed."""
import subprocess, sys, os
G = "horizon/effects/sinkproc.py"
M = [("if uid != allowed_uid: out", "if False: out"), ("(data, 0o700)", "(data, 0o755)"), ("(jr, 0o600)", "(jr, 0o666)"), ("if not (real.startswith(root + os.sep)) or os.path.isdir(real)", "if False"),
     ("real = os.path.realpath(req[\"path\"])", "real = os.path.abspath(req[\"path\"])"), ("def demote(): os.setgid(sink_uid); os.setuid(sink_uid)", "def demote(): pass"), ("\"uid_peer\": uid", "\"uid_peer\": 0"),
     ("except Exception as e: out = {\"ok\": False, \"code\": \"SINK_ERROR:\" + type(e).__name__}", "except Exception as e: raise"), ("os.chown(p, sink_uid, sink_uid)", "pass")]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.e06.test_sinkproc"], capture_output=True, timeout=90, env=env).returncode
    except subprocess.TimeoutExpired: return 1
if os.geteuid() != 0: print("SKIP: needs root"); sys.exit(0)
src = open(G).read(); assert run() == 0; surv = []
try:
    for a, b in M:
        if a not in src: surv.append(("MISSING", a)); continue
        open(G, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", a))
finally: open(G, "w").write(src)
print(f"{len(M)-len(surv)}/{len(M)} killed"); [print(*x) for x in surv]; sys.exit(1 if surv else 0)
