import os
os.makedirs("public", exist_ok=True); os.makedirs("private", exist_ok=True)
open("public/readme.txt", "w").write("hello"); open("private/secret.txt", "w").write(open("secret.txt").read())

def handle(req):
    p = os.path.join("public", req["path"])
    try: return {"data": open(p).read()}
    except OSError as e: return {"error": "not found"}
