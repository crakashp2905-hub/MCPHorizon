#!/bin/sh
# Reproduce P9 from a clean checkout: needs python3 and (for Code Mode scenarios) node 22 + `cd codemode && npm ci`.
set -e
cd "$(dirname "$0")/.."
python3 bench/secbench/freeze.py verify
python3 -W ignore bench/p9/study.py --out results/v2/p9_comparative.json
python3 bench/p9/manifest.py write
python3 bench/p9/manifest.py verify
