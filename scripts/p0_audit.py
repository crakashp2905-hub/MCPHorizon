#!/usr/bin/env python3
"""P0 repository audit (read-only). Stdlib only.

Implements the mechanical parts of P0-01..P0-09, P0-14, P0-20 of the master spec:
  environment.json, file_inventory.json, component_classification.json,
  frozen_hashes.json (MCPTox/MCPSecBench/TAMAS), duplicate_reports.json,
  readme_usage_discrepancies.json.
It never modifies tracked files; output goes to --out (default docs/implementation/p0).
Judgement-based items (provenance, licence, private-core approach) are recorded as
documents by humans/reviewers, not inferred here.
"""
from __future__ import annotations
import argparse, hashlib, json, os, platform, re, subprocess, sys
from collections import defaultdict
from pathlib import Path

FROZEN = ["MCPTox", "MCPSecBench", "TAMAS"]
LANG = {".py": "python", ".js": "javascript", ".ts": "typescript", ".json": "json",
        ".jsonl": "jsonl", ".md": "markdown", ".ipynb": "jupyter", ".txt": "text",
        ".toml": "toml", ".bat": "batch", ".sh": "shell", ".yml": "yaml", ".yaml": "yaml"}


def sh(args, cwd):
    try:
        return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception as e:  # noqa
        return f"UNAVAILABLE: {e}"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tracked(root: Path) -> list[str]:
    out = sh(["git", "ls-files", "-z"], root)
    return sorted(p for p in out.split("\0") if p)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--out", type=Path, default=Path("docs/implementation/p0"))
    a = ap.parse_args()
    root = a.root.resolve()
    out = (root / a.out) if not a.out.is_absolute() else a.out
    out.mkdir(parents=True, exist_ok=True)
    files = [p for p in tracked(root) if not p.startswith("docs/implementation/p0/")]

    # P0-01
    env = {
        "branch": sh(["git", "rev-parse", "--abbrev-ref", "HEAD"], root),
        "head_sha": sh(["git", "rev-parse", "HEAD"], root),
        "remotes": sh(["git", "remote", "-v"], root).splitlines(),
        "status_porcelain": sh(["git", "status", "--porcelain"], root).splitlines(),
        "os": platform.platform(), "python": sys.version,
        "toolchains": {t: sh([t, "--version"], root) for t in ("python3", "node", "git")},
    }
    (out / "environment.json").write_text(json.dumps(env, indent=2))

    # P0-02
    inv = []
    for rel in files:
        p = root / rel
        if not p.is_file():
            continue
        top = rel.split("/")[0] if "/" in rel else "(root)"
        inv.append({"path": rel, "bytes": p.stat().st_size, "sha256": sha(p),
                    "language": LANG.get(p.suffix.lower(), "other"), "top_level": top,
                    "ownership": "third_party_or_imported" if top in FROZEN else "project_or_unknown"})
    (out / "file_inventory.json").write_text(json.dumps(inv, indent=1))

    # P0-03 (mechanical heuristic only; reviewer must confirm)
    comp = defaultdict(lambda: {"files": 0, "py": 0})
    for r in inv:
        c = comp[r["top_level"]]
        c["files"] += 1
        c["py"] += r["language"] == "python"
    tag = {"MCPTox": "third_party", "MCPSecBench": "third_party", "TAMAS": "third_party",
           "MCPWEEK5": "documented_only", "results": "documented_only", "data": "third_party",
           "MCPWEEK6": "unknown"}
    cls = {k: {**v, "tag": tag.get(k, "unknown"), "needs_human_review": True} for k, v in comp.items()}
    # MCPWEEK6 package: check whether declared packages actually exist
    pkg = root / "MCPWEEK6" / "mcphorizon"
    declared_engine = (pkg / "engine").exists()
    cls["MCPWEEK6"]["note"] = ("pyproject declares packages mcphorizon, mcphorizon.engine; "
                               f"engine directory present={declared_engine}; "
                               f"python files in package={len(list(pkg.rglob('*.py'))) if pkg.exists() else 0}")
    (out / "component_classification.json").write_text(json.dumps(cls, indent=2))

    # P0-07 frozen hashes
    frozen = {r["path"]: r["sha256"] for r in inv if r["top_level"] in FROZEN}
    manifest_hash = hashlib.sha256(json.dumps(frozen, sort_keys=True).encode()).hexdigest()
    (out / "frozen_hashes.json").write_text(json.dumps(
        {"roots": FROZEN, "file_count": len(frozen), "manifest_sha256": manifest_hash, "files": frozen}, indent=1))

    # P0-06 duplicates by content hash among reports (md/json outside frozen roots)
    by_hash = defaultdict(list)
    for r in inv:
        if r["top_level"] in FROZEN or r["language"] not in ("markdown", "json"):
            continue
        by_hash[r["sha256"]].append(r["path"])
    dups = [{"sha256": h, "paths": sorted(ps)} for h, ps in by_hash.items() if len(ps) > 1]
    by_name = defaultdict(list)
    for r in inv:
        if r["top_level"] not in FROZEN and r["language"] in ("markdown", "json"):
            by_name[os.path.basename(r["path"])].append((r["path"], r["sha256"]))
    divergent = [{"name": n, "variants": v} for n, v in by_name.items()
                 if len(v) > 1 and len({x[1] for x in v}) > 1]
    (out / "duplicate_reports.json").write_text(json.dumps(
        {"identical_content_groups": sorted(dups, key=lambda d: d["paths"]),
         "same_name_different_content": sorted(divergent, key=lambda d: d["name"]),
         "note": "Canonical source selection is a human decision (P0-06); none chosen here."}, indent=1))

    # P0-04/05 README + USAGE command discrepancies
    paths = set(files)
    refs = []
    for doc in ("README.md", "USAGE.md"):
        text = (root / doc).read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"`([^`\n]+)`|^\s{2,}(\S[^\n]*)$|^(?:\$ )?(python3?|mcphorizon|pip|pytest)\s[^\n]*$",
                             text, re.MULTILINE):
            line = next(g for g in m.groups() if g) if any(m.groups()) else m.group(0)
            for tok in re.findall(r"[\w./-]+\.(?:py|json|md|ipynb|js)\b", line):
                refs.append({"doc": doc, "reference": tok, "exists_as_tracked_file":
                             any(p == tok or p.endswith("/" + tok) for p in paths)})
    missing = sorted({(r["doc"], r["reference"]) for r in refs if not r["exists_as_tracked_file"]})
    cmds = []
    for doc in ("README.md", "USAGE.md"):
        for ln in (root / doc).read_text(encoding="utf-8", errors="replace").splitlines():
            s = ln.strip()
            if re.match(r"^(\$ )?(mcphorizon|python3?|pip|pytest)\b", s):
                cmds.append({"doc": doc, "command": s})
    entry = {"console_script_declared": "mcphorizon = mcphorizon.cli:main",
             "cli_module_present": (root / "MCPWEEK6/mcphorizon/cli.py").exists(),
             "engine_present": declared_engine}
    (out / "readme_usage_discrepancies.json").write_text(json.dumps(
        {"entrypoint_check": entry, "documented_commands": cmds,
         "referenced_files_not_in_repo": [{"doc": d, "reference": r} for d, r in missing]}, indent=1))

    # P0-14 non-executable references (docs claim proprietary / not included)
    unavailable = []
    for doc in ("README.md", "USAGE.md"):
        for i, ln in enumerate((root / doc).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if re.search(r"proprietary|not included|not part of this public", ln, re.I):
                unavailable.append({"doc": doc, "line": i, "text": ln.strip()[:240],
                                    "tag": "unavailable_in_public_release"})
    (out / "unavailable_in_public_release.json").write_text(json.dumps(unavailable, indent=2))

    # P0-09 raw licence signals
    lic = {"root_license_first_line": (root / "LICENSE").read_text().splitlines()[0],
           "pyproject_license": "Research prototype (MCPWEEK6/pyproject.toml)",
           "frozen_dirs_with_license_files": [p for p in files if re.search(r"(^|/)(LICEN[SC]E|COPYING)", p)],
           "frozen_dirs_with_readme": [p for p in files if p.split('/')[0] in FROZEN and p.lower().endswith('readme.md')],
           "note": "Legal compatibility is NOT determined here; counsel/maintainer review required."}
    (out / "license_signals.json").write_text(json.dumps(lic, indent=2))

    summary = {"files": len(inv), "frozen_files": len(frozen), "frozen_manifest_sha256": manifest_hash,
               "identical_groups": len(dups), "divergent_same_name": len(divergent),
               "missing_references": len(missing), "head": env["head_sha"]}
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
