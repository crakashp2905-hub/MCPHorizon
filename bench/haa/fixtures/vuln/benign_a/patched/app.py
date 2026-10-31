import json, hashlib
def handle(req): return {"sum": sum(req["xs"]), "sha": hashlib.sha256(json.dumps(req["xs"]).encode()).hexdigest()[:8]}
