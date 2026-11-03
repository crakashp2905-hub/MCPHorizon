"""Print SHA-256 and size of every file under a directory (for pinning models in SOURCE.txt). Usage: python scripts/hash_model_dir.py <dir>"""
import hashlib, os, sys
def main(d):
    for root, _, fs in sorted(os.walk(d)):
        for f in sorted(fs):
            p = os.path.join(root, f); h = hashlib.sha256()
            with open(p, "rb") as fh:
                for b in iter(lambda: fh.read(1 << 20), b""): h.update(b)
            print(h.hexdigest(), os.path.getsize(p), os.path.relpath(p, d).replace(os.sep, "/"))
if __name__ == "__main__":
    if len(sys.argv) != 2 or not os.path.isdir(sys.argv[1]): sys.exit("usage: hash_model_dir.py <dir>")
    main(sys.argv[1])
