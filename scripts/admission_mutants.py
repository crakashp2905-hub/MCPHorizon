"""Mutation check for security_hardening/admission.py (timeout counts as killed)."""
import subprocess, sys, os
F = "security_hardening/admission.py"
M = [('if "signature" not in m: return self._deny(["UNSIGNED"])', 'pass'),
     ('if sg["issuer"] != REVIEW_ISSUER: why.append("SIGNER_NOT_A_REVIEW_ISSUER")', 'pass'),
     ('if sg["kid"] == m["authored_by"]:', 'if False:'),
     ('except Exception: why.append("BAD_SIGNATURE")', 'except Exception: pass'),
     ('if self.platform not in m["supported_platforms"]:', 'if False:'),
     ('or not os.path.isfile(full): why.append(tag + "_MISSING_OR_OUTSIDE_ROOT")', 'or False: why.append(tag + "_MISSING_OR_OUTSIDE_ROOT")'),
     ('not full.startswith(os.path.realpath(self.root) + os.sep) or', 'False or'),
     ('elif file_sha(full) != dig:', 'elif False:'),
     ('or file_sha(ev) != m["evidence_digest"]', 'or False'),
     ('if dep not in self.admitted: why.append', 'if False: why.append'),
     ('elif self.admitted[dep]["version"] != ver:', 'elif False:'),
     ('self.admitted[dep]["track"] == "research"', 'False'),
     ('if wanted - self.allow.get(m["name"], set()):', 'if False:'),
     ('if m["track"] == "research" and "mandatory_enforcement" in wanted:', 'if False:'),
     ('and m["track"] == "research": why.append("RESEARCH_MODULE_CANNOT_CLAIM_PROTECTED")', 'and False: why.append("RESEARCH_MODULE_CANNOT_CLAIM_PROTECTED")'),
     ('if m["name"] in self.admitted: return', 'if False: return'),
     ('todo += [k for k, v in self.admitted.items() if n in v["dependencies"]]', 'pass'),
     ('if m["contract_version"] != CONTRACT_VERSION:', 'if False:'),
     ('p = [f"UNKNOWN_FIELD:{k}" for k in m if k not in REQUIRED and k not in OPTIONAL]', 'p = []'),
     ('if c not in COVERAGE: p.append', 'if False: p.append'),
     ('except Exception as e: return self._deny', 'except ValueError as e: return self._deny'),
     ('self.admitted[m["name"]] = m; return', 'return'),
     ('for k, v in (allow_elevation or {}).items()}', 'for k, v in {}.items()}')]
def run():
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "tests.hardening.test_admission"], capture_output=True, timeout=120, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1")).returncode
    except subprocess.TimeoutExpired: return 1
assert run() == 0
surv = []
for a, b in M:
    src = open(F).read()
    if a not in src: surv.append(("MISSING", a)); continue
    try:
        open(F, "w").write(src.replace(a, b, 1))
        if run() == 0: surv.append(("SURVIVED", a))
    finally: open(F, "w").write(src)
print(f"{len(M) - len(surv)}/{len(M)} killed"); [print(s) for s in surv]; sys.exit(1 if surv else 0)
