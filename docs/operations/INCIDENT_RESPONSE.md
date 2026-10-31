# Incident response runbook (P10-19)

Sequence: **block → isolate → reconstruct → notify → remediate → rotate**.

1. **Block (minutes).** Engage emergency mode (`FailClosed.engage()`): every protected effect is denied; only allowlisted reads pass. If the service is unreachable the gates already fail closed. Revoke suspect tokens (`Validator.revoked`) and remove their `kid` from the key set.
2. **Isolate.** Stop the affected worker/Code Mode processes; disable the suspect manual (do not re-approve its new digest); freeze policy changes (no approvals except `admin` with two-person rule).
3. **Reconstruct.** Copy the audit log and traces read-only. Verify the chain (`verify_audit`) and the latest signed stamp (`ops.keys.verify_stamp`): a failure means truncation or rewrite and the log is evidence of tampering, not of history. Use decision ids, event ids and artifact lineage to list what left, to where, and with which labels. Use the byte oracle approach from `bench/p7` to check payloads against known sensitive values.
4. **Notify.** Tenant owners and the data owner; legal/compliance if regulated data may have left. State only what the evidence supports (POSSIBLE_FLOW vs VERIFIED_OUTBOUND_LEAK).
5. **Remediate.** Fix the root cause (policy gap, mislabelled source, missing mapping), add the incident as a SecBench scenario, re-run `scripts/repro_p9.sh`, ship via the normal release gate.
6. **Rotate.** Rotate broker credentials for affected tenants, rotate service tokens, `KeyRing.rotate()` then revoke the old key after consumers move, issue a fresh audit stamp.

Drills: the outage drill in `tests/p10/test_ops.py::FailClosedDrills` must pass before release. A human exercise has **not** been run.
