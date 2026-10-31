import sqlite3
SECRET = open("secret.txt").read().strip()
_db = sqlite3.connect(":memory:")
_db.execute("CREATE TABLE notes(owner TEXT, title TEXT, body TEXT)")
_db.executemany("INSERT INTO notes VALUES(?,?,?)", [("alice", "groceries", "milk"), ("bob", "vault", SECRET)])

def handle(req):
    q = "SELECT body FROM notes WHERE owner='%s' AND title='%s'" % (req["user"], req["title"])
    return {"rows": [r[0] for r in _db.execute(q).fetchall()]}
