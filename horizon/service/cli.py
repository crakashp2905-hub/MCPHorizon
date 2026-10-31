"""CLI (P3-10): horizon policy validate|simulate, horizon audit verify. Exit codes: 0 ok, 1 invalid/failed, 2 usage."""
from __future__ import annotations
import argparse, json, sys
from .. import schemas
from .audit import verify_audit


def S_ALL():
    from ..schemas import ALL
    return ALL


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="horizon"); sub = ap.add_subparsers(dest="cmd", required=True)
    pv = sub.add_parser("policy-validate"); pv.add_argument("file")
    av = sub.add_parser("audit-verify"); av.add_argument("file")
    sub.add_parser("version"); dr = sub.add_parser("doctor"); dr.add_argument("--audit")
    sv = sub.add_parser("schema-validate"); sv.add_argument("kind"); sv.add_argument("file")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "version":
            from .. import schemas as S
            print(json.dumps({"cli": "0.1.0-candidate", "schema_major": S.SCHEMA_MAJOR, "api": "v2"})); return 0
        if a.cmd == "doctor":
            import os, platform
            checks = {"python>=3.11": sys.version_info >= (3, 11), "schemas_load": bool(S_ALL())}
            if a.audit: checks["audit_chain_valid"] = verify_audit(a.audit)[0]
            print(json.dumps({"checks": checks, "platform": platform.system()})); return 0 if all(checks.values()) else 1
        if a.cmd == "policy-validate":
            errs = schemas.validate("policy", json.load(open(a.file)))
            print(json.dumps({"valid": not errs, "errors": errs})); return 1 if errs else 0
        if a.cmd == "schema-validate":
            errs = schemas.validate(a.kind, json.load(open(a.file)))
            print(json.dumps({"valid": not errs, "errors": errs})); return 1 if errs else 0
        ok, msg = verify_audit(a.file); print(json.dumps({"ok": ok, "detail": msg})); return 0 if ok else 1
    except (OSError, ValueError) as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr); return 2


if __name__ == "__main__": raise SystemExit(main())
