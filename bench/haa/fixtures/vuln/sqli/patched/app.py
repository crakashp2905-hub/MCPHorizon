import sqlite3
SECRET = open("secret.txt").read().strip()
_db = sqlite3.connect(":memory:")
_db.execute("CREATE TABLE notes(owner TEXT, title TEXT, body TEXT)")
_db.executemany("INSERT INTO notes VALUES(?,?,?)", [("alice", "groceries", "milk"), ("bob", "vault", SECRET)])

def handle(req):
    rows = _db.execute("SELECT body FROM notes WHERE owner=? AND title=?", (req["user"], req["title"])).fetchall()
    return {"rows": [r[0] for r in rows]}
