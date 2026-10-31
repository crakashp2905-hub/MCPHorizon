#!/usr/bin/env python3
"""python3 entry point for the TS SDK check, because the CI verifier only permits python3 commands."""
import subprocess, sys, os
sys.exit(subprocess.run([os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_ts_sdk_smoke.sh")]).returncode)
