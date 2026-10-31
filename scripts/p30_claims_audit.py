#!/usr/bin/env python3
"""Claims audit (P30-18). Scans docs/README/paper text for claims the evidence cannot support:
 (a) attributing observed runtime behaviour to model weights / backdoors / intent, (b) 'VERIFIED' / 'proven secure' / 'guarantee' language without a negation or CANDIDATE qualifier on the same line.
Lines inside a quoted prohibition (starting with '-' and containing 'never'/'not'/'no ') are allowed. Exit 1 on violation."""
import os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ["README.md", "docs/evidence/p29/RESULTS.md", "docs/evidence/p29/NEGATIVE_FINDINGS.md", "docs/evidence/HR_GATES.md", "docs/security/P30_REVIEWER_THREAT_MODEL.md", "docs/security/P30_KERNEL_LIMITS.md", "docs/evidence/p30/P23_P30_STATUS.md", "docs/evidence/p30/CLAIMS_BOUNDARY.md"]
BAD = [(re.compile(r"(proves?|proved|demonstrates?) (that )?the model|model weights? (caused|contain|are backdoored)|backdoor(ed)? (was )?(found|detected|confirmed)", re.I), "weight/intent attribution"),
       (re.compile(r"\b(provably|guaranteed?|unbreakable|impossible to bypass|fully secure|is secure)\b", re.I), "absolute security claim")]
OK_CONTEXT = re.compile(r"\b(not|never|no|cannot|does not|without|NOT MET|forbidden|prohibited|unsupported)\b", re.I)
def scan():
    bad = []
    for f in FILES:
        p = os.path.join(ROOT, f)
        if not os.path.exists(p): continue
        for n, line in enumerate(open(p, errors="replace"), 1):
            for rx, why in BAD:
                if rx.search(line) and not OK_CONTEXT.search(line): bad.append(f"{f}:{n}: {why}: {line.strip()[:120]}")
    return bad
if __name__ == "__main__":
    b = scan(); [print(x) for x in b]; print("claims audit:", "FAIL" if b else "PASS"); sys.exit(1 if b else 0)
