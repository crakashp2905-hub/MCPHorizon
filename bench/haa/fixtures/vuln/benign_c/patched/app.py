import subprocess, sys
def handle(req): return {"v": subprocess.run([sys.executable, "-c", "print(%d)" % int(req["n"])], capture_output=True, text=True).stdout.strip()}
