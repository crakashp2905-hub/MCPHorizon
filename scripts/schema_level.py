#!/usr/bin/env python3
"""Schema-level (no semantic checks) verdict for every fixture -> JSON {relpath: bool}. Used for cross-language conformance."""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from horizon.jsonschema_lite import validate
from horizon.schema_defs import ALL
out = {}
for f in sorted((ROOT / "tests/fixtures").rglob("*.json")):
    doc = json.loads(f.read_text())
    out[str(f.relative_to(ROOT / "tests/fixtures"))] = not validate(doc, ALL[f.parent.name])
print(json.dumps(out, indent=1, sort_keys=True))
