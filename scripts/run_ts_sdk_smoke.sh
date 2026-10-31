#!/usr/bin/env bash
# Typecheck the TS SDK and run its smoke test against a live synthetic service. Exit non-zero on any failure.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; D="$(mktemp -d)"
(cd "$ROOT/sdk-ts" && npm ci --silent --no-audit --no-fund --ignore-scripts && npx tsc -p .)
python3 "$ROOT/scripts/serve_p3_demo.py" "$D" > "$D/out" 2>&1 & PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do grep -q READY "$D/out" 2>/dev/null && break; sleep 0.1; done
node --experimental-strip-types --no-warnings "$ROOT/sdk-ts/smoke.mjs" "$D/h.sock" ta
