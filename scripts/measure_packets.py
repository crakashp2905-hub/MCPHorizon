#!/usr/bin/env python3
"""P84-16 (partial): MEASURE packet context size over every task in the compiled plan. Cost, result validity and missing-critical-
instruction rate need live provider runs and are NOT measured here."""
import json, os, statistics, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestrator import packet2 as P
spec = open("docs/MCPHORIZON_2_0_MASTER_SPEC.md").read(); sh = P.sha(spec)
rows = [json.loads(l) for l in open("spec/task_compiled.jsonl")]
pol = {"network": "none", "filesystem": "worktree-only", "credentials": "none", "providers": ["local"], "tools": ["git"]}
tok, fail = [], []
for r in rows:
    try:
        pk = P.build(b"k", task=r, spec_text=spec, spec_sha256=sh, plan_digest="d" * 64, base_git_sha="a" * 40, epoch=1, lease_owner="w", issued_at=0.0, ttl_s=1,
                     attempt_no=1, attempts_allowed=1, allowlist=["x/*"], policies=pol, acceptance=[["true"]], dep_receipts={}, token_cap=10**9)
        tok.append(sum(i["tokens"] for i in pk["context"]))
    except P.PacketError as e: fail.append((r["task_id"], str(e)))
tok.sort()
print(json.dumps({"tasks": len(rows), "built": len(tok), "failed": fail[:10], "failed_count": len(fail), "tokens_estimate_bytes_div_4": {"min": tok[0], "median": int(statistics.median(tok)),
      "p95": tok[int(.95 * len(tok))], "max": tok[-1]}, "note": "mandatory context only (spec s0, s3, phase section, task text); coarse bytes/4 estimate, not a model tokenizer; excludes optional items"}, indent=1))
