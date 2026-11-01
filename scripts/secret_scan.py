#!/usr/bin/env python3
"""Repository secret scan (P10-15, partial): high-signal patterns + entropy, with an explicit allowlist for synthetic test fixtures. Exit 1 on findings. ALLOW_PATH lists third-party research corpora (model outputs containing sample keys) and synthetic fixtures; findings elsewhere fail CI."""
import math, os, re, sys
from pathlib import Path
PATTERNS = {"aws_key": r"AKIA[0-9A-Z]{16}", "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "github_token": r"gh[pousr]_[A-Za-z0-9]{36,}", "slack_token": r"xox[abprs]-[A-Za-z0-9-]{10,}", "openai_style": r"sk-[A-Za-z0-9]{32,}", "jwt": r"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}", "generic_assign": r"""(?i)(?:password|secret|api[_-]?key|token)\s*[:=]\s*['"][A-Za-z0-9/+_=-]{20,}['"]"""}
ALLOW_PATH = ("MCPTox/", "MCPWEEK5/", "MCPWEEK6/", "TAMAS/", "data/", "tests/", "results/", "bench/secbench/data/", "research/incident-casebook/", "docs/", "conformance/", "spec/", "package-lock.json", "Cargo.lock", ".git/")


def entropy(s): 
    from collections import Counter
    c = Counter(s); return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


SKIP_DIRS = {".git", "node_modules", "target", "__pycache__", ".venv"}


def tracked_files(root):
    out = []
    for d, dirs, fs in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        out += [os.path.relpath(os.path.join(d, f), root) for f in fs]
    return sorted(out)


def scan(root: str = ".", files=None):
    root_p = Path(root); out = []
    names = files if files is not None else tracked_files(root)
    if not names: raise RuntimeError("secret scan found no files to scan (refusing to report a vacuous pass)")
    for n in names:
        if any(n.startswith(a) or n.endswith(a) for a in ALLOW_PATH): continue
        p = root_p / n
        try: txt = p.read_text(errors="ignore")
        except OSError: continue
        for i, line in enumerate(txt.splitlines(), 1):
            for k, pat in PATTERNS.items():
                if re.search(pat, line): out.append((n, i, k))
            if "secret-scan:ignore" in line or n.endswith(".md"): continue                     # per-line marker; prose files only get the pattern checks above
            for m in re.finditer(r"[A-Za-z0-9+/=_-]{40,}", line):
                if entropy(m.group()) > 4.5 and "sha" not in line.lower() and "hash" not in line.lower() and "integrity" not in line.lower(): out.append((n, i, "high_entropy"))
    return out


if __name__ == "__main__":
    f = scan(sys.argv[1] if len(sys.argv) > 1 else "."); [print(f"{n}:{i}: {k}") for n, i, k in f]; sys.exit(1 if f else 0)
