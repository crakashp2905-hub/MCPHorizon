#!/usr/bin/env python3
"""Generate the least-privilege sample packet (P84-17). Synthetic key and lease; deterministic output."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestrator import packet2 as P
spec = open("docs/MCPHORIZON_2_0_MASTER_SPEC.md").read()
row = next(json.loads(l) for l in open("spec/task_compiled.jsonl") if json.loads(l)["task_id"] == "P84-05")
pk = P.build(b"demo-supervisor-key-not-secret", task=row, spec_text=spec, spec_sha256=P.sha(spec), plan_digest="0" * 64, base_git_sha="a" * 40, epoch=1,
             lease_owner="worker-1", issued_at=1000.0, ttl_s=3600, attempt_no=1, attempts_allowed=2, allowlist=["orchestrator/packet2.py", "tests/supervisor/test_packets2.py"],
             policies={"network": "none", "filesystem": "worktree-only, no writes outside allowlist", "credentials": "none", "providers": ["local"], "tools": ["git", "python3"]},
             acceptance=[["python3", "-m", "unittest", "discover", "-s", "tests/supervisor", "-p", "test_packets2.py"]], dep_receipts={}, budget={"max_seconds": 3600, "max_spend_usd": 0})
for i in pk["context"]:
    if i["id"] != "task:description": i["text"] = i["text"]            # spec text is included verbatim; large but deterministic
print(json.dumps(pk, indent=1, sort_keys=True))
