#!/usr/bin/env bash
# P1-20: run Python (lite), TypeScript (Ajv) and Rust (jsonschema crate) over the same corpus; fail on any disagreement.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; OUT="$(mktemp -d)"
python3 "$ROOT/scripts/schema_level.py" > "$OUT/py.json"
( cd "$ROOT/conformance/ts" && npm ci --ignore-scripts --silent && node run.mjs > "$OUT/ts.json" )
( cd "$ROOT/conformance/rust" && cargo run --quiet --release --bin horizon-conformance-rs -- "$ROOT" > "$OUT/rs.json" )
python3 - "$OUT" <<'PY'
import json, sys
o = sys.argv[1]; r = {k: json.load(open(f"{o}/{k}.json")) for k in ("py", "ts", "rs")}
keys = set(r["py"]); bad = [(k, {n: r[n].get(k) for n in r}) for k in sorted(keys) if len({r[n].get(k) for n in r}) != 1]
bad_valid = [k for k in keys if k.startswith("valid/") and not r["py"][k]]
print(f"fixtures={len(keys)} engines={list(r)} disagreements={len(bad)} valid_rejected={len(bad_valid)}")
for b in bad: print("DISAGREE", b)
raise SystemExit(1 if bad or bad_valid or any(set(v) != keys for v in r.values()) else 0)
PY
# P1-13/14: generated types must be current and compile in every language
python3 "$ROOT/scripts/gen_types.py" --check
python3 -c "import sys; sys.path.insert(0, '$ROOT/types/python'); import horizon_types"
( cd "$ROOT/conformance/ts" && npx tsc --noEmit --strict --target es2022 --skipLibCheck "$ROOT/types/typescript/horizon_types.ts" )
( cd "$ROOT/conformance/rust" && cargo run --quiet --release --bin types -- "$ROOT" )
echo "conformance OK"
