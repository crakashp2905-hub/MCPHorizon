"""S0-02: static module dependency graph of the assurance-relevant code, with declared rules.
Edges come from `ast` (imports only). It sees neither dynamic imports nor runtime data flow, and it says nothing about the *semantic* independence of two modules. Rules are declared here, before the graph is read:
  R1 acyclic; R2 horizon/ never imports research/; R3 horizon/effects/sinkproc.py imports nothing from the repo (it must run unprivileged and self-contained);
  R4 the verifier side (authz, ops) never imports effects, assurance, forge or research; R5 coverage never imports effects or assurance; R6 horizon/forge/checker.py imports only horizon/forge/ir.py (the independent checker shares no code with the synthesizer beyond the IR types)."""
import ast, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEEDS = ("horizon/authz", "horizon/ops", "horizon/effects", "horizon/assurance", "horizon/coverage", "horizon/forge", "research/spectra")
OUT = os.path.join(ROOT, "docs", "evidence", "blueprint", "ASSURANCE_DEPENDENCY_GRAPH.json")
def _file(mod):
    p = mod.replace(".", "/")
    for c in (p + ".py", p + "/__init__.py"):
        if os.path.exists(os.path.join(ROOT, c)): return c
def _imports(rel):
    src = open(os.path.join(ROOT, rel)).read(); pkg = os.path.dirname(rel).replace("/", "."); out = set()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Import): names = [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            base = n.module or ""
            if n.level:
                parts = pkg.split(".")[: len(pkg.split(".")) - (n.level - 1)]; base = ".".join(parts + ([n.module] if n.module else []))
            names = [base] + [base + "." + a.name for a in n.names]
        else: continue
        for m in names:
            f = _file(m)
            if f and f != rel: out.add(f)
    return out
def build():
    seeds = sorted(os.path.join(d, f) for d in SEEDS for f in os.listdir(os.path.join(ROOT, d)) if f.endswith(".py"))
    nodes, edges, todo = set(), {}, list(seeds)
    while todo:
        f = todo.pop()
        if f in nodes: continue
        nodes.add(f); edges[f] = sorted(_imports(f)); todo += edges[f]
    return {"seeds": seeds, "edges": {k: edges[k] for k in sorted(edges)}}
def _pkg(f): return "/".join(f.split("/")[:2])
def violations(g):
    v, E = [], g["edges"]
    state = {}
    def dfs(n, path):
        state[n] = 1
        for m in E.get(n, []):
            if state.get(m) == 1: v.append("R1_CYCLE:" + " -> ".join(path + [n, m]))
            elif m not in state: dfs(m, path + [n])
        state[n] = 2
    for n in E:
        if n not in state: dfs(n, [])
    for a, bs in E.items():
        for b in bs:
            if a.startswith("horizon/") and b.startswith("research/"): v.append(f"R2:{a}->{b}")
            if a == "horizon/effects/sinkproc.py": v.append(f"R3:{a}->{b}")
            if _pkg(a) in ("horizon/authz", "horizon/ops") and _pkg(b) in ("horizon/effects", "horizon/assurance", "horizon/forge", "research/spectra"): v.append(f"R4:{a}->{b}")
            if _pkg(a) == "horizon/coverage" and _pkg(b) in ("horizon/effects", "horizon/assurance"): v.append(f"R5:{a}->{b}")
            if a == "horizon/forge/checker.py" and b != "horizon/forge/ir.py": v.append(f"R6:{a}->{b}")
    return sorted(set(v))
def main(argv):
    g = build(); g["violations"] = violations(g); text = json.dumps(g, indent=1, sort_keys=True) + "\n"
    if "--write" in argv: open(OUT, "w").write(text); print("written", len(g["edges"]), "nodes", len(g["violations"]), "violations")
    else:
        ok = os.path.exists(OUT) and open(OUT).read() == text and not g["violations"]; print("OK" if ok else "STALE_OR_VIOLATIONS", g["violations"]); return 0 if ok else 1
    return 1 if g["violations"] else 0
if __name__ == "__main__": sys.exit(main(sys.argv[1:]))
