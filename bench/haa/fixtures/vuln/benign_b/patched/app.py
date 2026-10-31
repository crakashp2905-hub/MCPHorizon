import random, secrets, tempfile, os
def handle(req):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x"); open(p, "w").write(req["text"]); return {"len": len(open(p).read()), "tok": len(secrets.token_hex(4))}
