# P83 assumptions and limits
- Extends, does not replace, `scripts/compile_plan.py` (P83-03/04/05/07/14/15 already existed there).
- Source spans are line ranges ending at the next task or heading; gate spans start at headings naming a Gate/RC-R/CG/PG/ES-G id.
- Invalidation follows task-level `depends_on` edges plus explicit edges; the compiled plan only has gate-level edges, so downstream reach through phases is NOT computed here.
- Work-class profiles are authored policy, not externally reviewed. Class assignment is a low-confidence heuristic.
- NOT done: P83-05 task-level prerequisites (only gate edges exist), P83-06 cryptographic signed review (the existing approval is a non-cryptographic chat instruction), P83-13 named effect oracles for the 302 high-risk tasks (0 have one), P83-14 export-plan is a summary only, P83-16 independent review, P83-17 publication/visualization, P83-18 CG-01–04 sign-off.
- Nothing here marks any task VERIFIED.
