# ENG-PR05 — one protected file-write effect with sink-side journal (E05; HARD-D/F subset) — CANDIDATE

Stacked on ENG-PR04 (#45). Code: `horizon/effects/filesink.py`; tests `tests/e05` (15); `scripts/e05_mutants.py` (13/13 killed, 1 equivalent mutant removed).
Flow: duplicate effect_id check -> commit-time permit verification (ENG-PR03) -> ledger authorize/begin (ENG-PR04) -> FileSink write (realpath containment, atomic replace, fsync) -> sink-owned journal -> ledger outcome.
Tested: ALLOW (file + sink receipt + ledger COMMITTED) vs BLOCKED (no/garbage permit, tampered target, data not bound to permit, replay, traversal, symlink escape, directory, unsupported effect type, no tmp files);
upstream failure after start -> UNKNOWN; reconcile only from the sink journal and current file digest (tampered file -> RECONCILED_BLOCKED).
Limits (honest): in-process library in a tempdir, localhost only. An agent running as the same OS user could write the file directly — mandatory mediation needs the sandbox/broker boundary (P-series) and was NOT demonstrated end to end here.
No real MCP adapter and no HTTP sink yet (so HARD-D HTTP and the MCP wiring remain OPEN). Sink journal is owned by the same process/author, so "independent" means separate object/file, not a separate trust domain; no independent review.
Reproduce: `python3 -B -m unittest discover -s tests/e05 && python3 -B scripts/e05_mutants.py`
