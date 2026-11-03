"""Verify a local AgentDojo checkout against bench/real/MANIFEST.json."""
import glob, hashlib, json, os, sys
root = sys.argv[sys.argv.index("--root") + 1]
m = json.load(open(os.path.join(os.path.dirname(__file__), "..", "bench", "real", "MANIFEST.json")))["agentdojo"]
h = hashlib.sha256(); n = 0
for p in sorted(glob.glob(root + "/runs/*/*/*/*/*.json")):
    h.update(os.path.relpath(p, root).encode()); h.update(hashlib.sha256(open(p, "rb").read()).digest()); n += 1
ok = (n == m["run_files"] and h.hexdigest() == m["runs_tree_sha256"])
print("MATCH" if ok else "MISMATCH", n)
sys.exit(0 if ok else 1)
