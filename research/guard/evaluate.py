"""Held-out evaluation of horizon.guard.scan on MCPTox poisoned descriptions (positives) vs author-written benign descriptions (negatives).
Protocol (fixed before looking at the held-out fold): weights/threshold are fitted using ONLY paradigm Template-1 and Template-2 positives and the benign 'dev' set;
Template-3 positives and the benign 'test' set are scored once. Reports recall per paradigm/category and false-positive rate with Wilson 95% intervals. Positives are ATTACK descriptions only:
no benign MCPTox descriptions exist, so precision depends entirely on the small author-written benign set and is indicative, not a measurement of the real world."""
from __future__ import annotations
import itertools, json, math, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, ROOT)
from horizon.guard import scan as S
def wilson(k, n, z=1.96):
    if n == 0: return [None, None]
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)); return [round((c - m) / d, 3), round((c + m) / d, 3)]
def load():
    rows = [v for x in json.load(open(os.path.join(ROOT, "MCPTox", "pure_tool.json"))) for v in x.values()]
    return rows, json.load(open(os.path.join(ROOT, "research", "guard", "benign_descriptions.json")))
def metrics(pos, neg, w, th):
    tp = sum(S.score(t, w) >= th for t in pos); fp = sum(S.score(t, w) >= th for t in neg); return {"recall": round(tp / len(pos), 3) if pos else None, "recall_ci95": wilson(tp, len(pos)), "fpr": round(fp / len(neg), 3), "fpr_ci95": wilson(fp, len(neg)), "tp": tp, "n_pos": len(pos), "fp": fp, "n_neg": len(neg)}
def run():
    rows, ben = load(); dev_pos = [r["tool_content"] for r in rows if r["paradigm"] in ("Template-1", "Template-2")]; held = [r for r in rows if r["paradigm"] == "Template-3"]
    out = {"weights": S.WEIGHTS, "threshold": S.THRESHOLD, "dev": metrics(dev_pos, ben["dev"], None, S.THRESHOLD)}
    out["heldout_template3"] = metrics([r["tool_content"] for r in held], ben["test"], None, S.THRESHOLD)
    out["heldout_recall_by_category"] = {}
    for cat in sorted({r["security risk"] for r in held}):
        sub = [r["tool_content"] for r in held if r["security risk"] == cat]; k = sum(S.score(t) >= S.THRESHOLD for t in sub); out["heldout_recall_by_category"][cat] = {"recall": round(k / len(sub), 3), "n": len(sub)}
    out["missed_signal_profile_heldout"] = {"no_signal_at_all": sum(not any(S.features(r["tool_content"]).values()) for r in held)}
    ev = json.load(open(os.path.join(ROOT, "research", "guard", "evasions.json")))["evasions"]; k = sum(S.score(t) >= S.THRESHOLD for t in ev)
    out["author_written_evasions"] = {"flagged": k, "n": len(ev), "recall": round(k / len(ev), 3), "note": "adaptive/obfuscated phrasing is NOT detected; this is the scanner's main known weakness"}
    out["note"] = "positives are MCPTox attack descriptions only; negatives are author-written; both small; no adaptive attacker; licence of MCPTox unverified"
    return out
if __name__ == "__main__":
    r = run(); json.dump(r, open(sys.argv[1], "w"), indent=1, sort_keys=True) if len(sys.argv) > 1 else print(json.dumps(r, indent=1, sort_keys=True))
