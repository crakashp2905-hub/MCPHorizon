# Module-completion gates: inventory + admission — ASSUMPTIONS AND LIMITS

Status: CANDIDATE.  Source document: `docs/hardening/MODULE_COMPLETION_GATES.md` (user-supplied, frozen copy).

## What exists
1. `scripts/hardening_inventory.py` renders `security_hardening/inventory.json` from the document: 47 modules, 282 tasks,
   6 stage gates.  `--check` fails if the file is stale or any integrity rule is broken:
   no status above CANDIDATE without an attestation + reviewer identity; no task `done` without evidence files whose
   sha256 digests match; no `*-GATE` task done without an attestation; no duplicate task ids.  A `[x]` in the prose
   document never counts as completion.
2. `security_hardening/admission.py`: versioned (contract v1) module manifest and DEFAULT-DENY admission (Gate G5
   mechanism) — see the module docstring for the rules.  Unit tests 39+, mutants 23/23.

## What this is NOT
- No module is marked done, verified or hardened.  0 of 282 tasks are closed.  Completion percentages are not computed.
- The task `class_heuristic` (DOABLE_HERE / NEEDS_LIVE_ENV / EXTERNAL) is a keyword triage, not a feasibility proof.
- The admission validator is a candidate mechanism with author-written tests.  It is not wired into any real loader,
  gateway or kernel, is not independently reviewed, and does not make any admitted module secure.  `protected` in a
  manifest is the module author's claim until an independent attestation exists.
- The trust store in tests uses locally generated fixture keys; production review keys, custody and rotation (A03) are
  not established here.
- Admission checks file digests at admit time only (no TOCTOU protection after admit).
- Revocation is in-memory; no durable or distributed revocation (see A05-03, F01-02).

## Items that need the owner / third parties (BLOCKED, not forged)
Independent reviewer sign-off for every `*-GATE`, reviewer-owned fixtures, independent sandbox-escape evaluation,
usability study, licence/provenance audit, external key-management review, official protocol conformance on real
servers, multi-host failover, pinned-hardware performance.  See `security_hardening/BLOCKED.md`.
