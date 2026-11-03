"""ENG-PR02 mutation check for MCP gate scoping. Timeout counts as killed."""
import subprocess, sys, os
G = "horizon/adapters/mcp/gate.py"
M = [("return (type(rid).__name__, str(rid))", "return (str(rid),)"),
     ("return (self.tenant, server_id, session_id, principal, self._rid(rid))", "return (self.tenant, principal, self._rid(rid))"),
     ("return (self.tenant, server_id, session_id, principal, self._rid(rid))", "return (self.tenant, server_id, principal, self._rid(rid))"),
     ("return (self.tenant, server_id, session_id, principal, self._rid(rid))", "return (self.tenant, session_id, principal, self._rid(rid))"),
     ("f\"{self.tenant}|{server_id}|{req.session_id}|{req.principal}|{self._rid(req.id)}|{req.method}|{fp}\"", "f\"{self.tenant}|{req.principal}|{self._rid(req.id)}|{req.method}|{fp}\""),
     ("f\"{self.tenant}/{server_id}/{req.session_id}/{req.principal}-{req.id}\"", "f\"{self.tenant}/{req.principal}-{req.id}\""),
     ("x[\"state\"] != \"uncertain\"), None)", "True), None)"),
     ("server_id=server_id, session_id=req.session_id)", "server_id=server_id, session_id=None)")]
def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.e02.test_mcp_scoping"], capture_output=True, timeout=60, env=env).returncode
    except subprocess.TimeoutExpired: return 1
src = open(G).read(); assert run() == 0, "baseline must pass"; surv = []
try:
    for a, b in M:
        n = src.count(a)
        if n == 0: surv.append(("MISSING", a)); continue
        open(G, "w").write(src.replace(a, b)); 
        if run() == 0: surv.append(("SURVIVED", a))
finally: open(G, "w").write(src)
print(f"{len(M)-len(surv)}/{len(M)} killed"); [print(*x) for x in surv]; sys.exit(1 if surv else 0)
