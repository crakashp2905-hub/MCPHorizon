#!/usr/bin/env python3
"""P30 CI check: no harness/runtime source contains a literal URL or hostname outside loopback, link-local metadata (mock alias), reserved example/test names, or the pinned package-index policy strings.
Static literal scan only — it cannot prove a program never resolves a name at run time; the sandbox default-deny egress is the actual control. Exit 1 on violation."""
import os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOW = re.compile(r"^(127\.|2130706433|0x7f000001|0177\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|.*\.(test|invalid|example|localhost)$|.*example\.(com|net|org)$|pypi\.org|files\.pythonhosted\.org|github\.com|crakashp2905-hub|claude\.(ai|com)|docs\.claude\.com|anthropic\.com|json-schema\.org|www\.w3\.org|cyclonedx\.org)")
URL = re.compile(r"https?://([A-Za-z0-9._-]+)")
def scan():
    bad = []
    for dp in ("horizon/runtime", "bench/haa", "scripts"):
        for f in sorted(os.listdir(os.path.join(ROOT, dp))):
            if not f.endswith(".py") or f == "p30_no_external.py": continue
            for n, line in enumerate(open(os.path.join(ROOT, dp, f), errors="replace"), 1):
                for h in URL.findall(line):
                    if not ALLOW.match(h) and "{" not in h and "%" not in h: bad.append(f"{dp}/{f}:{n}: {h}")
    return bad
if __name__ == "__main__":
    b = scan(); [print(x) for x in b]; print("p30 no-external-contact (static literal scan):", "FAIL" if b else "PASS"); sys.exit(1 if b else 0)
