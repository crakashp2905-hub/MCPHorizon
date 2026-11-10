"""M0-02: static + dynamic route trace (masterplan). Writes docs/evidence/integration/ROUTE_TRACE.json (`--write`) or checks it is current (default).
STATIC: transitive repo-import closure from each named entrypoint (file level, `ast`; dynamic imports and getattr tricks are invisible), plus every place that CONSTRUCTS an authority-like object
(signer, verifier, nonce store, ledger, claim registry, trust store) and every class whose name says it is one. DYNAMIC: while two real scenarios run (reference MCP write_file allowed + denied; Spectra->Forge->Zero
fixture), `sys.setprofile` records caller-module -> callee-module call edges inside horizon/ and research/. It shows what ran in THOSE scenarios only; absence is not evidence a route does not exist."""
from __future__ import annotations
import ast, importlib.util, json, os, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
OUT = os.path.join(ROOT, "docs", "evidence", "integration", "ROUTE_TRACE.json")
ENTRYPOINTS = {"policy_service": "horizon/service/__init__.py", "reference_mcp_gateway": "horizon/effects/mcp_gateway.py", "file_sink": "horizon/effects/filesink.py", "http_sink": "horizon/effects/httpsink.py",
               "net_broker": "horizon/effects/netbroker.py", "proc_broker": "horizon/effects/procbroker.py", "linux_sandbox": "horizon/runtime/sandbox.py", "mcp_adapter": "horizon/adapters/mcp/__init__.py",
               "utcp_adapter": "horizon/adapters/utcp/__init__.py", "codemode": "horizon/codemode/__init__.py", "spectra_forge_zero": "research/spectra/pipeline.py", "durable_assurance": "horizon/assurance/durable.py",
               "contracts_v1": "horizon/contracts/v1/__init__.py"}
CTORS = {"Signer": "signer", "Verifier": "verifier", "NonceStore": "nonce_store", "TrustStore": "trust_store", "EffectLedger": "effect_ledger", "DurableRegistry": "claim_registry", "Registry": "claim_registry",
         "FileSink": "file_sink", "ProtectedFileWriter": "protected_writer", "ProtectedHttpWriter": "protected_writer", "NetBroker": "net_broker", "ProcBroker": "proc_broker"}
CLASS_WORDS = ("Ledger", "Registry", "Verifier", "Signer", "NonceStore", "Authority", "TrustStore")


def _mod_file(mod):
    p = os.path.join(ROOT, mod.replace(".", "/"))
    for c in (p + ".py", os.path.join(p, "__init__.py")):
        if os.path.exists(c): return os.path.relpath(c, ROOT)


def _imports(rel):
    out = set(); tree = ast.parse(open(os.path.join(ROOT, rel)).read()); pkg = rel[:-3].replace("/", ".").split(".")
    base = pkg if rel.endswith("__init__.py") is False else pkg[:-1]
    for n in ast.walk(tree):
        names = []
        if isinstance(n, ast.Import): names = [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            if n.level: b = pkg[:len(pkg) - n.level] if not rel.endswith("__init__.py") else pkg[:-1][:len(pkg[:-1]) - (n.level - 1)]; m = ".".join(b + ([n.module] if n.module else []))
            else: m = n.module or ""
            names = [m] + [m + "." + a.name for a in n.names]
        for m in names:
            if m.split(".")[0] in ("horizon", "research"):
                f = _mod_file(m)
                if f: out.add(f)
    return out


def closure(start):
    seen, todo = set(), [start]
    while todo:
        f = todo.pop()
        if f in seen or not os.path.exists(os.path.join(ROOT, f)): continue
        seen.add(f); todo += sorted(_imports(f))
    return sorted(seen)


def authority_scan():
    found = {}; classes = []
    for top in ("horizon", "research"):
        for dp, dn, fs in os.walk(os.path.join(ROOT, top)):
            dn[:] = sorted(d for d in dn if d != "__pycache__")
            for f in sorted(fs):
                if not f.endswith(".py"): continue
                rel = os.path.relpath(os.path.join(dp, f), ROOT)
                try: tree = ast.parse(open(os.path.join(ROOT, rel)).read())
                except SyntaxError: continue
                for n in ast.walk(tree):
                    if isinstance(n, ast.ClassDef) and any(w in n.name for w in CLASS_WORDS): classes.append(f"{rel}:{n.name}")
                    if isinstance(n, ast.Call):
                        fn = n.func; name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
                        owner = fn.value.id if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else None
                        key = CTORS.get(owner) if name == "generate" and owner == "Signer" else CTORS.get(name) if name in CTORS and name != "Signer" else None
                        if key: found.setdefault(key, []).append(f"{rel}:{n.lineno}")
    return {k: sorted(set(v)) for k, v in sorted(found.items())}, sorted(set(classes))


def dynamic():
    edges = set(); modname = lambda fn: (os.path.relpath(fn, ROOT) if fn.startswith(ROOT + os.sep) else None)
    def prof(frame, event, arg):
        if event != "call": return
        callee = modname(frame.f_code.co_filename); caller = frame.f_back and modname(frame.f_back.f_code.co_filename)
        if callee and caller and callee != caller and callee.split("/")[0] in ("horizon", "research") and caller.split("/")[0] in ("horizon", "research", "scripts"): edges.add((caller, callee))
    def scenario_gateway():
        from horizon.effects.mcp_gateway import Gateway
        d = tempfile.mkdtemp(); g = Gateway(d, os.path.join(d, "j"), os.path.join(d, "l.db"))
        g.call_write({"path": "a.txt", "content": "hi", "effect_id": "e1"}); g.call_write({"path": "../x.txt", "content": "hi", "effect_id": "e2"})
    def scenario_pipeline():
        sys.path.insert(0, ROOT)
        from tests.blueprint import test_spectra_pipeline as T
        T.go({"net_0": {"net"}}, T.FULL)
    sys.setprofile(prof)
    try: scenario_gateway(); scenario_pipeline()
    finally: sys.setprofile(None)
    return sorted([a, b] for a, b in edges if not a.startswith("scripts/"))


def build():
    auth, classes = authority_scan()
    return {"entrypoint_closure": {k: closure(v) for k, v in sorted(ENTRYPOINTS.items())}, "authority_constructions": auth, "authority_like_classes": classes, "dynamic_call_edges": dynamic(),
            "limits": "static: file-level imports only; dynamic: two scenarios only (reference MCP write_file allowed/denied; Spectra->Forge->Zero fixture). Absence of an edge is not evidence of absence."}


def main(argv):
    g = build()
    if "--write" in argv: os.makedirs(os.path.dirname(OUT), exist_ok=True); open(OUT, "w").write(json.dumps(g, indent=1, sort_keys=True) + "\n"); print("written", {k: len(v) for k, v in g.items() if hasattr(v, "__len__") and k != "limits"}); return 0
    cur = json.load(open(OUT)) if os.path.exists(OUT) else None
    ok = cur == json.loads(json.dumps(g)); print("OK" if ok else "STALE: run scripts/route_trace.py --write"); return 0 if ok else 1


if __name__ == "__main__": sys.exit(main(sys.argv[1:]))
