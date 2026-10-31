#!/usr/bin/env python3
"""Allowlist-friendly wrapper so the verifier can run the cross-language conformance suite."""
import subprocess, sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
subprocess.run(["npm", "ci", "--ignore-scripts", "--silent"], cwd=root / "conformance/ts", check=True)
raise SystemExit(subprocess.run(["bash", str(root / "scripts/run_conformance.sh")]).returncode)
