#!/usr/bin/env python3
"""Thin wrapper: python scripts/validate_plan.py [--spec ...] [--out spec]  (== compile_plan.py validate)."""
import sys
from compile_plan import main
raise SystemExit(main(["validate", *sys.argv[1:]]))
