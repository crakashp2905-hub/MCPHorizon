#!/usr/bin/env python3
"""P2 acceptance wrapper: locked Rust build + unit tests, then Python-oracle vs Rust differential on 5 seeds."""
import subprocess, sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
for cmd, cwd in ((["cargo", "build", "--locked", "--release"], root / "core"), (["cargo", "test", "--locked"], root / "core")):
    if subprocess.run(cmd, cwd=cwd).returncode: raise SystemExit(f"failed: {' '.join(cmd)}")
for seed in (7, 8, 9, 10, 11):
    if subprocess.run([sys.executable, str(root / "scripts/run_diff.py"), "--seed", str(seed)], cwd=root).returncode:
        raise SystemExit(f"differential mismatch at seed {seed}")
print("core OK")
