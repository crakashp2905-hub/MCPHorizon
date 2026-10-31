import os
os.makedirs("public", exist_ok=True); os.makedirs("private", exist_ok=True)
open("public/readme.txt", "w").write("hello"); open("private/secret.txt", "w").write(open("secret.txt").read())

def handle(req):
    base = os.path.realpath("public"); p = os.path.realpath(os.path.join(base, req["path"]))
    if os.path.commonpath([base, p]) != base: return {"error": "not found"}
    try: return {"data": open(p).read()}
    except OSError: return {"error": "not found"}
