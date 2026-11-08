"""S0-01: freeze manifest for the blueprint experiments (commit-protocol/durable/Pareto/Spectra-comparison code, their tests and results).
What it fixes: sha256 of every frozen file, the platform it was frozen on, the threat scope text, and the claim 'no LLM is called' (checked by AST: no frozen python file imports an LLM SDK).
What it does NOT do: pin a model (none is used), pin the interpreter patch version, or prove the files were not edited BEFORE freezing. `frozen_after_commit` is the parent commit at write time and is informational: a squash merge changes commit ids.
Changing any frozen file requires `--write` again, which is a visible diff in the manifest."""
import ast, glob, hashlib, json, os, platform, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "evidence", "blueprint", "FREEZE_MANIFEST.json")
SCOPE = ("Threat scope: an agent process may be fully adversarial toward the gateway/sink interfaces it can reach; the gateway, authority keys, sink process and operator are trusted; "
         "host root, kernel, clock and network are out of scope; no independent reviewer exists; results are author-run on one host.")
LLM_SDKS = ("anthropic", "openai", "google.generativeai", "cohere", "mistralai", "litellm", "transformers", "langchain")
EXTRA = ["scripts/assurance_graph.py", "scripts/blueprint_roadmap.py", "scripts/blueprint_mutants.py", "scripts/experiment_freeze.py", "research/spectra/results/probe_selection.json",
         "/".join(("docs", "evidence", "blueprint", "ASSURANCE_" + "DEPENDENCY_GRAPH.json")), "security_hardening/roadmap.py"]
def frozen_files():
    fs = set(EXTRA)
    for pat in ("horizon/effects/*.py", "horizon/assurance/*.py", "horizon/forge/*.py", "horizon/coverage/schema.py", "horizon/authz/effect.py", "horizon/ops/audience.py", "research/spectra/*.py", "tests/blueprint/*.py"):
        fs |= {os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, pat))}
    return sorted(f for f in fs if "__pycache__" not in f)
def sha(p): return hashlib.sha256(open(os.path.join(ROOT, p), "rb").read()).hexdigest()
def llm_imports(files, root=None):
    root = root or ROOT; bad = []
    for f in files:
        if not f.endswith(".py"): continue
        for n in ast.walk(ast.parse(open(os.path.join(root, f)).read())):
            names = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module or ""] if isinstance(n, ast.ImportFrom) and not n.level else []
            for m in names:
                if any(m == s or m.startswith(s + ".") for s in LLM_SDKS): bad.append(f"{f}:{m}")
    return bad
def _parent():
    try: return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, timeout=10).stdout.strip() or "unknown"
    except Exception: return "unknown"
def build():
    fs = frozen_files(); body = {"scope": SCOPE, "scope_sha256": hashlib.sha256(SCOPE.encode()).hexdigest(), "platform": platform.system(), "model": "none (no frozen file imports an LLM SDK)",
                                 "files": {f: sha(f) for f in fs}, "frozen_after_commit": _parent()}
    body["manifest_sha256"] = manifest_hash(body); return body
def manifest_hash(m): return hashlib.sha256(json.dumps({k: v for k, v in m.items() if k not in ("manifest_sha256", "frozen_after_commit")}, sort_keys=True).encode()).hexdigest()
def problems(m, root=None):
    p = []; root = root or ROOT
    if m.get("manifest_sha256") != manifest_hash(m): p.append("MANIFEST_HASH")
    if m.get("scope") != SCOPE or m.get("scope_sha256") != hashlib.sha256(SCOPE.encode()).hexdigest(): p.append("SCOPE_CHANGED")
    for f, h in m.get("files", {}).items():
        full = os.path.join(root, f)
        if not os.path.exists(full): p.append("MISSING:" + f)
        elif hashlib.sha256(open(full, "rb").read()).hexdigest() != h: p.append("CHANGED:" + f)
    if root == ROOT:
        cur = set(frozen_files()); old = set(m.get("files", {}))
        p += ["UNFROZEN_NEW:" + f for f in sorted(cur - old)]
    p += ["LLM_IMPORT:" + x for x in llm_imports([f for f in m.get("files", {}) if os.path.exists(os.path.join(root, f))], root)]
    return p
def main(argv):
    if "--write" in argv: m = build(); open(OUT, "w").write(json.dumps(m, indent=1, sort_keys=True) + "\n"); print("frozen", len(m["files"]), "files"); return 0
    pr = problems(json.load(open(OUT))) if os.path.exists(OUT) else ["NO_MANIFEST"]; print("OK" if not pr else pr[:10]); return 1 if pr else 0
if __name__ == "__main__": sys.exit(main(sys.argv[1:]))
