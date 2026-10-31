ADMIN_SID = "s3cr3t-session-for-admin"  # secret-scan:ignore synthetic fixture value
SESSIONS = {"s-alice": "alice", ADMIN_SID: "admin"}
VAULT = open("secret.txt").read().strip()

def handle(req):
    user = SESSIONS.get(req.get("session"), "anonymous")
    if req["op"] == "vault": return {"data": VAULT} if user == "admin" else {"error": "forbidden"}
    return {"hello": user}
