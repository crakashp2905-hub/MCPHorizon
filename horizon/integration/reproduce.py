"""P54-07 / P54-08 / P54-13 / P54-16 (the part that can be done without a person): rerun every module that has a runnable experiment from a fresh process and compare the paired headline with the recorded one; for the others run the module's own `--check` (definitions match the recorded run) and say that the numbers were NOT recomputed.
This is a same-machine, same-author reproduction. It is not the independent clean-checkout review P54-16 asks for."""
import json, os, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
from .registry import MODULES, BY_ID, headline, load, ROOT

RERUN = {"P43": "mutation", "P44": "reach", "P45": "privacy", "P46": "downgrade", "P47": "incentive", "P48": "consent", "P49": "evalint", "P50": "budget", "P51": "vision", "P52": "temporal", "P53": "continuity"}
CODE = "import json,sys,importlib;sys.path.insert(0,%r);from horizon.integration.registry import BY_ID,headline;m=BY_ID[%r];r=importlib.import_module('horizon.%s.experiment').run();print(json.dumps(headline(m,json.loads(json.dumps(r,default=str)))))"

def rerun(mid, timeout=2400):
    m = BY_ID[mid]; p = subprocess.run([sys.executable, "-W", "ignore", "-c", CODE % (ROOT, mid, m["pkg"])], cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if p.returncode: return {"module": mid, "level": "rerun", "ok": False, "error": p.stderr[-300:]}
    fresh = json.loads(p.stdout.strip().splitlines()[-1]); rec = headline(m)
    return {"module": mid, "level": "rerun", "ok": fresh == rec, "recorded": rec, "fresh": fresh}
def check_defs(mid, timeout=600):
    m = BY_ID[mid]; p = subprocess.run([sys.executable, "-W", "ignore", "scripts/%s_run.py" % mid.lower(), "--check"], cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    return {"module": mid, "level": "definitions-only", "ok": p.returncode == 0, "output": (p.stdout + p.stderr).strip()[-200:], "note": "numbers not recomputed: the module has no importable experiment entry point; its own --check confirms the definitions match the recorded run"}
def module_tests(mid, timeout=900):
    """P39..P42 have no importable experiment entry point; run the module's own live tests (the oracle runs against real local mocks) except the classes that only read recorded results."""
    p = subprocess.run([sys.executable, "-W", "ignore", "-m", "pytest", "-q", "-x", "tests/%s" % mid.lower(), "-k", "not Recorded and not Gates"], cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    return {"module": mid, "level": "module-tests", "ok": p.returncode == 0, "output": (p.stdout.strip().splitlines() or [""])[-1][:120]}
def reproduce_all(workers=4):
    def one(m):
        if m["id"] in RERUN: return rerun(m["id"])
        a = check_defs(m["id"]); b = module_tests(m["id"]); return {**a, "module_tests": b, "ok": a["ok"] and b["ok"]}
    with ThreadPoolExecutor(workers) as ex: return list(ex.map(one, MODULES))
