# P17–P22 — supported boundaries, failure modes and negative findings

Everything here is **candidate**: in-process synthetic fixtures, author-written baselines, no live services, no independent reviewer. No GX gate is claimed met except as "candidate" (see `docs/evidence/GO_NO_GO.md`).

## P17 transactions — exact boundaries (P17-14)
Supported: a versioned key-value fixture with CAS, idempotency tokens, prepare/commit with re-checked policy version + authorization at commit, outcome read back from the resource's own hash-chained ledger, verified compensation, approval-gated irreversible effects.
Failure modes shown: resource-level double-apply leaves two ledger rows (append-only; detected as DUPLICATED, not erasable); non-idempotent operations are never retried after an unknown outcome (the task may stay incomplete — 3/119 legit tasks in the run); a COMPENSABLE effect whose compensation silently fails is reported RESTORE_FAILED. External publish cannot be undone (`CANNOT_COMPENSATE`). **Not modelled:** real databases/filesystems, distributed commit, clock skew, delayed callbacks beyond the fault flag. "Prevention" counts only refusals with the prohibited effect verifiably absent from the ledger.

## P18 memory — boundaries (P18-13)
Labels (trust, confidentiality, tenant, taints) survive put/update/summarize/retrieve; joins are conservative; authority never comes from content or similarity score; invalidation quarantines transitive descendants. **Residual risk:** deleting a source erases its content and logs only a hash, but any *summary already derived from it* still contains the content until it is deleted too (it is quarantined, not erased). Cryptographic erase is modelled as content removal, not key destruction of an encrypted store. Embedding indexes are a tenant-filtered lexical stand-in; real vector indexes may leak through shared nearest-neighbour structure. Baselines (no-provenance, session-only taint) are definitional, so their 100% miss rate is by construction.

## P19 attestation — boundaries (P19-14)
Contract metadata is signed (Ed25519), behaviour is probed in a mock, actual effects are compared against declared ones — three separate questions. **Opaque services (no implementation attestation) are reported `UNVERIFIED`/`UNKNOWN`, never compatible or safe.** Probes can miss trigger-conditioned behaviour (shown: a sleeper tool passes the pre-deploy probe and is only caught by runtime comparison). "Audited effects" here come from the mock network, not from OS/network/DB audit logs (P19-11 partially done); container-image attestation is a string identity (P19-07 not implemented beyond that).

## P20 least privilege — boundaries (P20-14)
Plans are typed requests; free text is never parsed (tested with a smuggling description). Missing capability → human-review ticket; the broker never expands scope. **Tasks that need delete or exceed contract argument limits are refused by policy; they are not "detections".** A real finding: omitting a constrained argument from a child grant reads as unbounded and fails attenuation, so unused constrained args are bound to 0 (otherwise 47 of 239 feasible tasks, about 20%, were falsely denied in the first run). The heuristic least-privilege baseline generalised to 0 of 131 held-out feasible tasks. The "issuer approver" in the benchmark auto-approves in-policy requests, so approval burden is not realistically measured.

## P21 arena — boundaries
Air-gapped, in-process; objective is a ledger fact (canary reconstructable by a stronger oracle, or a protected write backed by false evidence). The red team is a seeded random search by the same author: it is **not** an independent red team and the arena composes my own modules, so a low success rate on `full` is weak evidence. Findings: layers are largely redundant for exfiltration (grants and contracts add nothing once taint is on); mediation and taint are individually necessary; the only attack class that wins against `full` is two independent forged evidence records (`UNBLOCKABLE_BY_CURRENT_LAYERS`, same as P16). Success rates on the held-out (secret-path × channel) combinations were similar to or higher than on development combinations (e.g. `full`: 0.085 dev vs 0.138 holdout, driven by the sampling mix); the missing layer, not the combination, explains outcomes. This is not a statistically tested transfer result.

## P22 selective verification — boundaries
The verifier and the human reviewer are **simulated** (no model/human). The verifier is restrict-only by construction (cannot allow, cannot override a hard deny). Result: at a 2% actual-harm target, never-verify already meets it; at 1%, selective verification needs ≈1200 verifier calls vs 1346 for always-verify, i.e. little saving. ECE is a misleading drift signal for this score (moved 0.138→0.094 while AUC fell 0.97→0.87); AUC drop is used as the alarm. Do not cite any dollar/latency figure as real.

## Negative findings (P22-17)
1. Earlier: a simple "block any send after SECRET read" baseline ties the full system on attack success (P9).
2. Independent collusion of forged evidence defeats P16 and the epistemic layer in P21.
3. In P21, grants and contracts were redundant for exfiltration once taint was on.
4. Selective verification gives little saving over always-verify at the tighter security target in the simulation.
5. P14 found a real UTCP-vs-MCP payload-encoding discrepancy (not fixed).

## P22 items not done
P22-09 re-run of ablations against D0 and *other strong baselines* (only the P21 layer ablation and earlier P9); P22-11 prior-art matrix is a template with every row NOT CHECKED (`PRIOR_ART_CLAIMS_MATRIX.md`); P22-12/13/14 papers are NO-GO by the gates; P22-16 independent reproduction/licensing audit requires an external reviewer.
