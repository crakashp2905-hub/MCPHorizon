"""P54-06: canonical protocol equivalence across MCP (modern and legacy), UTCP and Code Mode (the shared parity rig), the P50 carrier codec, and the browser adapter.
The browser adapter is NOT run here: it is recorded separately (results/v2/p51-vision-browser) and is reported as such. Native non-protocol adapters are not available in this environment."""
import json, os
from ..equiv import parity as PA, effects as F
from ..budget import broker as B
from .registry import ROOT

def parity(seed=54, n=60):
    wfs = PA.generate(seed, n); d = []; ver = {}
    for wf in wfs: d += PA.compare(wf)
    return {"workflows": len(wfs), "paths": list(PA.PATHS), "discrepancies": d, "metamorphic_discrepancies": PA.metamorphic_mcp(seed, 20), "traps": PA.trap_results()}
def fixtures():
    """Intentionally non-equivalent pairs: the checker must flag every one or it is vacuous."""
    return [(n, F.equivalent(a, b)) for n, a, b in PA.non_equivalent_fixtures()]
def carriers():
    ctx = {"task": "T", "scope": "T", "rid": "r1"}; args = {"rows": 5}; out = {}
    for c in B.CARRIERS: out[c] = B.decode(c, B.encode(c, ctx, "export_csv", args)) == (ctx, "export_csv", args)
    return out
def browser_adapter():
    p = os.path.join(ROOT, "results/v2/p51-vision-browser/browser.json")
    return {"run_here": False, "recorded": os.path.exists(p), "source": "results/v2/p51-vision-browser/browser.json" if os.path.exists(p) else None}

def expected_classes():
    return {(e["path"], e["cls"]) for e in json.load(open(os.path.join(ROOT, "results/v2/p14-parity/expected_discrepancies.json")))["expected"]}
def unexpected(p):
    """Discrepancies not listed in the P14 expected-discrepancy file. The UTCP payload-encoding difference is a documented, unfixed finding; anything else is new."""
    ex = expected_classes(); return [d for d in p["discrepancies"] if (d["path"], d["cls"]) not in ex]
