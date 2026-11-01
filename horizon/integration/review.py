"""P54-05 / P54-09 / P54-12: static review. Pure AST, no execution.
 * oracle independence: no oracle file reaches a system-under-test file through intra-package imports;
 * authority sites: where signers/authorities are created (one shared HorizonPolicy; evidence services hold issuers);
 * dangerous calls and network literals in library code."""
import ast, os, re
from .registry import MODULES, ROOT

def _parse(rel): return ast.parse(open(os.path.join(ROOT, rel)).read(), rel)
def _imports(rel, pkg):
    """Intra-package modules imported by file `rel` (names like 'core')."""
    out = set()
    for n in ast.walk(_parse(rel)):
        if isinstance(n, ast.ImportFrom) and n.level == 1:
            if n.module: out.add(n.module.split(".")[0])
            else: out.update(a.name for a in n.names)
        elif isinstance(n, ast.ImportFrom) and n.module and n.module.startswith("horizon.%s." % pkg): out.add(n.module.split(".")[2])
        elif isinstance(n, ast.ImportFrom) and n.module == "horizon.%s" % pkg: out.update(a.name for a in n.names)
    return out

def reach(rel, pkg):
    """Transitive closure of intra-package imports starting at file rel."""
    seen, todo = set(), [os.path.basename(rel)[:-3]]
    while todo:
        m = todo.pop()
        if m in seen: continue
        seen.add(m); f = "horizon/%s/%s.py" % (pkg, m)
        if os.path.exists(os.path.join(ROOT, f)): todo += list(_imports(f, pkg) - seen)
    return seen - {os.path.basename(rel)[:-3]}

def independence(m):
    sysm = {os.path.basename(f)[:-3] for f in m["system"]}; rows = []
    for o in m["oracle"]:
        r = reach(o, m["pkg"]); rows.append({"oracle": o, "reaches": sorted(r), "reaches_system": sorted(r & sysm)})
    return {"module": m["id"], "oracle_files": rows, "independent": all(not x["reaches_system"] for x in rows)}

def all_independence(): return [independence(m) for m in MODULES]

SIGN = re.compile(r"\bSigner\.generate\b|\bHorizonPolicy\(|\.register_issuer\(")
ROLE = {"world.py": "fixture", "experiment.py": "fixture", "harness.py": "fixture", "scenarios.py": "fixture", "rig.py": "fixture", "services.py": "evidence-service", "receipts.py": "evidence-service", "statemachine.py": "fixture", "service.py": "evidence-service", "approver.py": "evidence-service", "evaluator.py": "evidence-service"}
def authority_sites():
    """Every non-test place in horizon/ that creates a signer, an authority or an issuer, with a role label. Unlabelled sites are reported as `other` and are the honest part of ES-G2."""
    out = []
    for root, _, fs in os.walk(os.path.join(ROOT, "horizon")):
        for f in sorted(fs):
            if not f.endswith(".py") or f == "authority.py" and "hpolicy" in root: continue
            rel = os.path.relpath(os.path.join(root, f), ROOT); src = open(os.path.join(ROOT, rel)).read()
            for i, ln in enumerate(src.splitlines(), 1):
                if SIGN.search(ln): out.append({"file": rel, "line": i, "role": ROLE.get(f, "other"), "text": ln.strip()[:120]})
    return out
def authority_summary():
    s = authority_sites(); by = {}
    for x in s: by.setdefault(x["role"], set()).add(x["file"])
    return {"sites": len(s), "by_role": {k: sorted(v) for k, v in sorted(by.items())}, "other_files": sorted(by.get("other", []))}

DANGER = {"eval", "exec", "compile", "__import__"}; DANGER_ATTR = {("os", "system"), ("os", "popen"), ("pickle", "loads"), ("pickle", "load"), ("subprocess", "Popen"), ("subprocess", "run"), ("subprocess", "call"), ("subprocess", "check_output"), ("marshal", "loads"), ("yaml", "load")}
def dangerous_calls():
    out = []
    for root, _, fs in os.walk(os.path.join(ROOT, "horizon")):
        for f in sorted(fs):
            if not f.endswith(".py"): continue
            rel = os.path.relpath(os.path.join(root, f), ROOT)
            for n in ast.walk(_parse(rel)):
                if isinstance(n, ast.Call):
                    if isinstance(n.func, ast.Name) and n.func.id in DANGER: out.append({"file": rel, "line": n.lineno, "call": n.func.id})
                    elif isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and (n.func.value.id, n.func.attr) in DANGER_ATTR: out.append({"file": rel, "line": n.lineno, "call": "%s.%s" % (n.func.value.id, n.func.attr)})
                    for k in n.keywords:
                        if k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True: out.append({"file": rel, "line": n.lineno, "call": "shell=True"})
    return out

URL = re.compile(r"https?://([A-Za-z0-9.\-]+)"); RESERVED = re.compile(r"(^|\.)(example\.(com|org|net)|test|invalid|localhost|example)\.?$|^[0-9a-fx.]+$|^[a-z]$|^[a-z]{1,3}$|^evil$|^host\.123$|^-bad\.test$")
def network_literals():
    out = {}
    for root, _, fs in os.walk(os.path.join(ROOT, "horizon")):
        for f in fs:
            if not f.endswith(".py"): continue
            rel = os.path.relpath(os.path.join(root, f), ROOT)
            for h in URL.findall(open(os.path.join(ROOT, rel)).read()): out.setdefault(h.lower(), set()).add(rel)
    return {h: sorted(v) for h, v in sorted(out.items())}

def review():
    d = dangerous_calls()
    n = network_literals(); real = {h: f for h, f in n.items() if not RESERVED.search(h)}
    return {"independence": all_independence(), "authority": authority_summary(), "dangerous_calls": d, "network_hosts": sorted(n), "non_reserved_hosts": real}
