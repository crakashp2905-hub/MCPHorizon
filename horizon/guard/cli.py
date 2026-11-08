"""`python -m horizon.guard scan <tools.json>` : flag MCP tool descriptions that try to instruct the model. Exit 0 = nothing flagged, 1 = at least one tool flagged, 2 = usage/input error.
Input: a JSON list of tools, or an object with a `tools` list (the shape of an MCP tools/list result). A clean exit is NOT a safety certificate (see horizon.guard.scan)."""
from __future__ import annotations
import argparse, json, sys
from . import scan as S


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="horizon.guard"); sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan"); sc.add_argument("file"); sc.add_argument("--threshold", type=float, default=None); sc.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        d = json.load(open(a.file)); tools = d.get("tools") if isinstance(d, dict) else d
        if not isinstance(tools, list) or not all(isinstance(t, dict) for t in tools): raise ValueError("expected a list of tool objects")
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr); return 2
    r = S.scan_manifest(tools, a.threshold)
    if a.json: print(json.dumps(r, indent=1, sort_keys=True))
    else:
        print(f"{r['flagged']} of {r['tools']} tools flagged (heuristic; no flag is not evidence of safety)")
        for f in r["findings"]: print(f"  FLAG {f['tool']}: score {f['score']} in {f['where']} signals={','.join(f['signals'])}")
    return 1 if r["flagged"] else 0


if __name__ == "__main__": sys.exit(main())
