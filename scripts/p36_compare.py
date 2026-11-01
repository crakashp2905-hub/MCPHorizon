#!/usr/bin/env python3
"""P36-15: compare InfraGuard against checkov on the SAME local fixtures (benchmarks/hieb/iac). checkov must be installed (a venv at CHECKOV or on PATH); result written write-once to results/v2/p36-checkov-compare/.
The comparison is format-limited by design and says so: checkov does not parse this compose-with-x-annotations format, so 'no findings' there means 'unsupported', which we report separately from 'passed'."""
import glob, hashlib, json, os, shutil, subprocess, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.infraguard import guard as G
CK = os.environ.get("CHECKOV") or shutil.which("checkov") or "/tmp/ckv/bin/checkov"
def checkov(f):
    p = subprocess.run([CK, "-f", f, "--quiet", "--compact", "-o", "json"], capture_output=True, text=True, timeout=300)
    try: d = json.loads(p.stdout)
    except ValueError: return {"parsed": False, "failed": 0, "frameworks": []}
    d = d if isinstance(d, list) else [d]; fw = [x["check_type"] for x in d if isinstance(x, dict) and "check_type" in x]
    return {"parsed": bool(fw), "failed": sum(x["summary"]["failed"] for x in d if isinstance(x, dict) and "summary" in x), "frameworks": fw, "checks": sorted({c["check_id"] for x in d if isinstance(x, dict) for c in x.get("results", {}).get("failed_checks", [])})}
def main():
    out = os.path.join(ROOT, "results/v2/p36-checkov-compare"); 
    if os.path.exists(os.path.join(out, "result.json")): sys.exit("refusing to overwrite " + out)
    if not os.path.exists(CK): sys.exit("checkov not installed; cannot compare (no result written)")
    ver = subprocess.run([CK, "--version"], capture_output=True, text=True).stdout.strip(); rows = []
    for f in sorted(glob.glob(os.path.join(ROOT, "benchmarks/hieb/iac/*.yml"))):
        n = os.path.basename(f); g = G.lint_text(open(f).read(), n, admin_allowlist=["/admin/config"]); c = checkov(f)
        rows.append({"fixture": n, "expected_bad": n.startswith("bad_"), "infraguard_rules": sorted({x["rule"] for x in g}), "infraguard_flags": bool(g), "checkov": c, "checkov_flags": c["failed"] > 0, "checkov_supports_format": c["parsed"]})
    bad = [r for r in rows if r["expected_bad"]]; good = [r for r in rows if not r["expected_bad"]]
    res = {"checkov_version": ver, "n_bad": len(bad), "n_good": len(good), "infraguard_detected": sum(r["infraguard_flags"] for r in bad), "checkov_detected": sum(r["checkov_flags"] for r in bad), "infraguard_false_positives": sum(r["infraguard_flags"] for r in good), "checkov_false_positives": sum(r["checkov_flags"] for r in good),
           "checkov_unsupported_format": sum(not r["checkov_supports_format"] for r in rows), "rows": rows,
           "caveats": ["fixtures were written by the InfraGuard author in InfraGuard's own annotated format; this favours InfraGuard", "checkov does not parse this format (frameworks listed per row), so most checkov 'no findings' are UNSUPPORTED, not PASS", "checkov covers a far larger space (Terraform, Kubernetes, CloudFormation, secrets, ...) that InfraGuard does not attempt", "a fair breadth comparison would need real Terraform/Kubernetes fixtures and was not done"]}
    os.makedirs(out); json.dump(res, open(os.path.join(out, "result.json"), "w"), indent=1, sort_keys=True); json.dump({"write_once": True, "files": {"result.json": hashlib.sha256(open(os.path.join(out, "result.json"), "rb").read()).hexdigest()}, "created_unix": int(time.time())}, open(os.path.join(out, "manifest.json"), "w"), indent=1); print({k: v for k, v in res.items() if k not in ("rows", "caveats")})
main()
