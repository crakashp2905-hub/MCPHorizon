"""Integrity + schema validation of third-party datasets (no data vendored).

What "validated" means here (and what it does NOT):
  * provenance : pinned git commit, origin URL matches the registry, license detected
  * integrity  : sha256 tree digest over data files, so a re-clone can be compared byte-for-byte
  * structure  : every JSON/JSONL/CSV/TSV data file parses; record counts; schema signature
  * hygiene    : exact-duplicate rate, credential-like strings, Git-LFS stub files (content missing)
It does NOT validate that third-party LABELS are correct; label semantics are checked per
dataset only where documented in docs/evidence/real/DATASET_NOTES.md.
"""
import csv, glob, hashlib, json, os, re, subprocess, sys

DATA_EXT = (".json", ".jsonl", ".csv", ".tsv")
MAX_BYTES = 200 * 1024 * 1024
LICENSES = [("MIT", r"permission is hereby granted, free of charge"), ("Apache-2.0", r"apache license,? version 2\.0"),
            ("BSD-3-Clause", r"redistribution and use in source and binary forms"), ("CC-BY-4.0", r"creative commons attribution 4\.0"),
            ("CC-BY-NC-4.0", r"attribution-noncommercial 4\.0"), ("CC-BY-SA-4.0", r"attribution-sharealike 4\.0"),
            ("GPL-3.0", r"gnu general public license\s+version 3"), ("MPL-2.0", r"mozilla public license,? version 2\.0"),
            ("Llama-Community (custom, restricted)", r"llama \d(\.\d)? community license"),
            ("CC0-1.0", r"cc0 1\.0 universal")]
SECRET = re.compile(r"(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{32,})")


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git(d, *args):
    r = subprocess.run(["git", "-C", d, *args], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def detect_license(d):
    for p in sorted(glob.glob(os.path.join(d, "LICEN[SC]E*")) + glob.glob(os.path.join(d, "COPYING*"))):
        try:
            txt = open(p, encoding="utf-8", errors="replace").read().lower()
        except OSError:
            continue
        for name, pat in LICENSES:
            if re.search(pat, txt):
                return name
        return "UNRECOGNISED"
    return "NONE"


NON_DATA = re.compile(r"^(tsconfig.*|package(-lock)?|\.eslintrc.*|composer|\.prettierrc.*)\.json$", re.I)


def data_files(d):
    out = []
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x not in (".git", "node_modules")]
        for fn in files:
            if fn.lower().endswith(DATA_EXT) and not NON_DATA.match(fn):
                out.append(os.path.join(root, fn))
    return sorted(out)


def _records(p):
    """Return (records, kind). records is a list of items; raises on parse failure."""
    low = p.lower()
    if low.endswith(".jsonl"):
        with open(p, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()], "jsonl"
    if low.endswith(".json"):
        with open(p, encoding="utf-8") as f:
            o = json.load(f)
        if isinstance(o, list):
            return o, "json-list"
        if isinstance(o, dict):
            return [o], "json-object"
        return [o], "json-scalar"
    delim = "\t" if low.endswith(".tsv") else ","
    with open(p, encoding="utf-8", newline="") as f:
        csv.field_size_limit(1 << 27)
        return list(csv.DictReader(f, delimiter=delim)), "csv"


def _text_key(rec):
    if isinstance(rec, dict):
        s = [v for v in rec.values() if isinstance(v, str)]
        return max(s, key=len) if s else json.dumps(rec, sort_keys=True)
    return json.dumps(rec, sort_keys=True) if not isinstance(rec, str) else rec


def validate(d, expect_url=None, skip_dirs=()):
    rep = {"path": os.path.basename(d.rstrip("/")), "commit": git(d, "rev-parse", "HEAD"),
           "origin": git(d, "remote", "get-url", "origin"), "license": detect_license(d)}
    rep["origin_matches"] = (expect_url is None or (rep["origin"] or "").lower().rstrip("/").removesuffix(".git") == expect_url.lower().rstrip("/"))
    files, tree = [], hashlib.sha256()
    n_records = n_fail = n_lfs = n_secret = n_dups = n_skipped = 0
    seen = set()
    schemas = {}
    failures = []
    for p in data_files(d):
        rel = os.path.relpath(p, d)
        if any(rel.startswith(s) for s in skip_dirs):
            continue
        size = os.path.getsize(p)
        if size > MAX_BYTES:
            n_skipped += 1
            continue
        with open(p, "rb") as f:
            head = f.read(64)
        if head.startswith(b"version https://git-lfs"):
            n_lfs += 1
            continue
        tree.update(rel.encode()); tree.update(bytes.fromhex(sha256_file(p)))
        try:
            recs, kind = _records(p)
        except Exception as e:                       # noqa: BLE001 - report every parse failure
            n_fail += 1
            failures.append(f"{rel}: {type(e).__name__}")
            continue
        files.append(rel)
        n_records += len(recs)
        for r in recs:
            k = _text_key(r)
            if k in seen:
                n_dups += 1
            elif len(seen) < 2_000_000:
                seen.add(k)
            if SECRET.search(k if isinstance(k, str) else ""):
                n_secret += 1
        if recs and isinstance(recs[0], dict):
            schemas.setdefault(",".join(sorted(map(str, recs[0].keys())))[:300], 0)
            schemas[",".join(sorted(map(str, recs[0].keys())))[:300]] += 1
    rep.update({"data_files_parsed": len(files), "parse_failures": n_fail, "parse_failure_examples": failures[:5],
                "lfs_stub_files": n_lfs, "skipped_too_large": n_skipped, "records": n_records,
                "exact_duplicate_records": n_dups, "credential_like_strings": n_secret,
                "tree_sha256": tree.hexdigest(), "distinct_schemas": len(schemas)})
    reasons = []
    if not rep["commit"]:
        reasons.append("no git commit")
    if not rep["origin_matches"]:
        reasons.append("origin URL mismatch")
    if rep["license"] in ("NONE", "UNRECOGNISED"):
        reasons.append("license " + rep["license"])
    if not files:
        reasons.append("no parsable data files")
    if n_fail:
        reasons.append(f"{n_fail} parse failures")
    if n_lfs:
        reasons.append(f"{n_lfs} LFS stubs (content missing)")
    lic = rep["license"]
    rep["license_restrictions"] = ("non-commercial" if "NC" in lic else "custom/restricted" if "custom" in lic else "none-known" if lic not in ("NONE", "UNRECOGNISED") else "unknown (no/unrecognised license: all rights reserved by default)")
    rep["status"] = "PASS" if not reasons else "WARN"
    rep["reasons"] = reasons
    return rep


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--registry", default="bench/real/REGISTRY.json")
    ap.add_argument("--out", default="bench/real/results/dataset_validation.json")
    a = ap.parse_args(argv)
    with open(a.registry) as f:
        reg = json.load(f)
    out = []
    for e in reg:
        d = os.path.join(a.base, e["dir"])
        if not os.path.isdir(os.path.join(d, ".git")):
            out.append({"id": e["id"], "status": "MISSING"}); continue
        if e["id"] == "agentdojo":                    # 36k run files: validated by scripts/real_manifest.py
            r = validate(d, e["url"], skip_dirs=("runs/",))
        else:
            r = validate(d, e["url"])
        r.update({k: e[k] for k in ("id", "category", "role")})
        out.append(r)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
    for r in out:
        print(f"{r['id']:22s} {r['status']:7s} lic={r.get('license','-'):13s} recs={r.get('records','-')} files={r.get('data_files_parsed','-')} fail={r.get('parse_failures','-')} dup={r.get('exact_duplicate_records','-')} {r.get('reasons','')}")


if __name__ == "__main__":
    main()
