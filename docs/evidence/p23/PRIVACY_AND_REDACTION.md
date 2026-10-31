# Privacy & redaction requirements (P23-13) — CANDIDATE
1. Incident/process traces are stored only after `schema.redact` and `importer.Sanitizer`; events containing secret-shaped strings fail validation (`UNREDACTED_SECRET_SHAPE`).
2. Only synthetic canaries (`TEST_CANARY_NOT_SECRET:<label>:<tag>`) may appear as "secrets". Real credentials must never be used in any test.
3. Correspondence maps hold keyed digests + lengths, never original hosts/tokens.
4. Process traces hold pids/ppids/profile bits and policy digests; no environment dumps, no file contents.
5. Chain-of-thought is not stored; visible claims only as advisory `model_declared_intent`.
6. Redaction is *pattern-based* and incomplete by nature: unknown secret formats pass. This is a stated limitation, not a guarantee.
