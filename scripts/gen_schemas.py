#!/usr/bin/env python3
"""Write schemas/*.schema.json from horizon/schema_defs.py. `--check` fails if files drifted."""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from horizon.schema_defs import ALL
drift = 0
for name, sch in ALL.items():
    p = ROOT / "schemas" / f"{name}.schema.json"; text = json.dumps(sch, indent=2, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        if not p.exists() or p.read_text() != text: print("DRIFT", p); drift += 1
    else: p.write_text(text)
raise SystemExit(1 if drift else 0)
