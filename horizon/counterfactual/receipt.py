"""INDEPENDENT effect receipt: a separate process that opens the real store READ-ONLY and prints what is actually there. It imports nothing from core.py or the gate, so a bug there cannot also hide an effect here.
usage: python -m horizon.counterfactual.receipt db <path> | files <root>"""
import hashlib, json, os, sqlite3, sys


def db_rows(path):
    c = sqlite3.connect("file:%s?mode=ro" % path, uri=True); out = {}
    for (t,) in c.execute("select name from sqlite_master where type='table' and name not like 'sqlite_%' order by name").fetchall():
        info = c.execute("pragma table_info(%s)" % t).fetchall(); pk = [r[1] for r in info if r[5]] or ["rowid"]
        cols = [r[1] for r in info]; out[t] = {}
        for r in c.execute("select %s, %s from %s" % (", ".join(pk), ", ".join(cols), t)): out[t][json.dumps(list(r[:len(pk)]))] = list(r[len(pk):])
    return out


def file_hashes(root):
    m = {}
    for dp, _, fs in os.walk(root):
        for f in fs: m[os.path.relpath(os.path.join(dp, f), root)] = hashlib.sha256(open(os.path.join(dp, f), "rb").read()).hexdigest()
    return m


if __name__ == "__main__":
    print(json.dumps(db_rows(sys.argv[2]) if sys.argv[1] == "db" else file_hashes(sys.argv[2]), sort_keys=True))
