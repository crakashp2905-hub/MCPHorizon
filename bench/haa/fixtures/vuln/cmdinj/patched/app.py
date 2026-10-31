import re, subprocess
def handle(req):
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,64}", req["host"]): return {"out": "invalid host"}
    return {"out": subprocess.run(["echo", "pinging", req["host"]], capture_output=True, text=True).stdout.strip()}
