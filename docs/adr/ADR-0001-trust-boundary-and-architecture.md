# ADR-0001: Trust boundary and architecture baseline (P0-19)

Status: **Proposed — requires maintainer review (not accepted).**
Date: 2026-10-31

## Context
P0 audit (`docs/implementation/p0/`) found the public repo is a research-artifact release: datasets, benchmarks, result files and TAMAS evaluation scripts. The `mcphorizon` Python package declared in `MCPWEEK6/pyproject.toml` (`mcphorizon.cli:main`, `mcphorizon.engine`) contains **no source** in the public tree; README states the lattice engine, Datalog compiler, predictor and proposer are proprietary and not released.

## Decision (proposed, per master spec §§3–4, 8)
- Untrusted: agent/LLM output, generated programs, tool descriptions/manuals, MCP/UTCP responses, any file the agent can write.
- Trusted-but-separate: policy engine, principal identity, event transport and enforcement wrappers, running **outside** the agent-writable context; fail closed.
- v2 code is developed greenfield in new directories; legacy and frozen directories are read-only inputs (integration approach "B": do not depend on the private core; see DEVIATIONS D-002).
- Task execution is governed by the compiled plan (`spec/`), whose dependency edges remain unsigned until a maintainer reviews them.

## Consequences
No v2 security claim may rest on the private engine until it is supplied and audited. Open: confirm approach A vs B (P0-10).
