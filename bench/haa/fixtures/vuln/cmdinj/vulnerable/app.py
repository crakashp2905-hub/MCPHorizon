import subprocess
def handle(req):
    out = subprocess.run("echo pinging " + req["host"], shell=True, capture_output=True, text=True).stdout
    return {"out": out.strip()}
