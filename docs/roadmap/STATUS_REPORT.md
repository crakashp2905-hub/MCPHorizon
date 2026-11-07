# Blueprint roadmap status (generated; do not edit)

Tasks: 74 | OPEN 28 | CANDIDATE 25 | BLOCKED 21 | INDEPENDENTLY_VERIFIED 0 (no reviewer attestation exists; not claimable by the author)

CANDIDATE = author-run implementation/evidence with stated limits. It is NOT integrated, adversarially tested by others, or independently verified.

| Task | Status | Basis |
|---|---|---|
| S0-01 Freeze exact commit, tool versions, model, platform, threat scope and  | OPEN |  |
| S0-02 Add cross-module assurance dependency graph (policy, signer, sink, ada | OPEN |  |
| S0-03 Build independently controlled reviewer signing and rotation workflow. | BLOCKED | Needs a named independent reviewer/key custodian and an operator-owned rotation process (user is custodian per OWNER_SIGNOFF_CHECKLIST). |
| S0-04 Ensure candidate implementations cannot mark themselves verified. | CANDIDATE | Admission requires a reviewer signer != author; roadmap checker rejects self-promotion. Author-run; no independent review; not wired into any release flow. |
| S0-05 Preserve all historical negative results and post-hoc changes. | CANDIDATE | Append-only register of 13 negative results/post-hoc changes; manual curation, no tooling enforces completeness. |
| S0-06 Add dashboard/report distinguishing IMPLEMENTED, INTEGRATED, ADVERSARI | CANDIDATE | Generated report uses OPEN/CANDIDATE/BLOCKED and a fixed INDEPENDENTLY_VERIFIED 0; it does not yet render IMPLEMENTED/INTEGRATED/ADVERSARIAL_TESTED per module. |
| S0-GATE Reviewer verifies that no incomplete module has been promoted. | BLOCKED | Gate = independent reviewer attestation; the author cannot grant it. |
| S1-01 Canonicalize every supported effect and bind exact arguments/targets t | OPEN |  |
| S1-02 Make permit issuance and commit verification use the same domain-separ | CANDIDATE | Issue (sign) and verify (parse) use one canonical JSON + strictly canonical base64url; the 16 padding-bit signature spellings and non-canonical header/body spel |
| S1-03 Carry principal, tenant, tool server, session, delegated authority, ep | OPEN |  |
| S1-04 Ensure at-most-once dispatch and explicit uncertainty under crash/reco | CANDIDATE | Bounded model (1 effect, 3-6 workers) + 576-transition conformance on SQLite ledger and file sink; single host; UNKNOWN never retried; no independent review. |
| S1-05 Test separate-process and cross-process writer races, including a fenc | CANDIDATE | Separate-process writer races and fenced late writer tested locally as root with uid separation; one host; no independent bypass red-team. |
| S1-06 Enforce real OS-level separation so agent cannot directly write protec | OPEN |  |
| S1-07 Implement real HTTPS/redirect/DNS egress control; prevent socket bypas | OPEN |  |
| S1-08 Keep sink journals independently owned and tamper-evident. | OPEN |  |
| S1-09 Execute a real MCP agent request through the authorization/ledger/sink | OPEN |  |
| S1-10 Measure clean and attacked task utility, not just refused calls. | OPEN |  |
| S1-GATE Independent real-effect test and no known bypass within supported scop | BLOCKED | Gate = independent reviewer attestation; the author cannot grant it. |
| S2-01 Define `EffectEdge`, `TrustZone`, `Witness`, `Probe`, `Observation`, ` | CANDIDATE | Schemas only (validation, canonical digest, evidence grading); not yet consumed by Spectra or Coverage engines. |
| S2-02 Define explicit instrumented vs uninstrumented effect classes. | CANDIDATE | Instrumented vs uninstrumented is explicit; not_seen/unobservable never yields absence evidence (tested). Finite toy, no real services. |
| S2-03 Connect the existing Spectra finite hypothesis engine to isolated rece | OPEN |  |
| S2-04 Add uncontrolled-probe effect ceilings and canned synthetic data only. | OPEN |  |
| S2-05 Add hidden file/HTTP/child-process/delegated-effect tests not derived  | BLOCKED | Needs hidden-effect fixtures authored by someone other than the detector's author. |
| S2-06 Preserve UNKNOWN on hypothesis indistinguishability, exhausted probe b | CANDIDATE | Toy hypothesis engine returns UNKNOWN/UNIDENTIFIABLE on exhausted budget, wrong hypothesis class, or hidden uninstrumented effects. Fixture-only. (tomography.py |
| S2-07 Compare active probe selection against random, static graph and expert | CANDIDATE | NEGATIVE: on 217 self-authored toy worlds, active selection saved 0.0-0.6 probes on average vs random/static/expert and every paired 95% CI includes 0 (see resu |
| S2-08 Add adaptive probes only if they cannot cause unauthorized production  | OPEN |  |
| S2-09 Freeze independent outcome traces and per-path ground truth. | BLOCKED | Needs an independent party to freeze outcome traces and ground truth. |
| S2-GATE Demonstrate a new effect edge detected where static manifests miss it, | BLOCKED | Gate = independent reviewer attestation; the author cannot grant it. |
| S3-01 Extend Forge IR beyond toy placements into real file/network/process/r | OPEN |  |
| S3-02 Represent available broker/sandbox/relocation/declassification mechani | OPEN |  |
| S3-03 Make utility floor explicit per task; a blanket denial must not be cal | CANDIDATE | Floor on a BINARY utility loss only; DENY_ALL is reported as not-a-solution. Real per-task utility oracle does not exist. |
| S3-04 Implement exhaustive finite solver first; compare against SMT/optimiza | CANDIDATE | Exhaustive finite enumeration with independent checker; no SMT/optimizer comparison; toy IR (3 placements, 2 forms). |
| S3-05 Separate untrusted candidate synthesizer from trusted checker and effe | OPEN |  |
| S3-06 Verify minimal-cost and Pareto-optimal alternatives under declared mod | CANDIDATE | Pareto frontier over (cost, binary loss) with a separate exhaustive verifier; optimality is relative to the enumerated portfolio only. |
| S3-07 Generate machine-readable negative certificates for every portfolio-ex | CANDIDATE | Negative certificate lists every enumerated plan's checker violations and is independently re-verified; claims nothing outside the finite portfolio. |
| S3-08 Make plan deployment transactional, reviewable, and reversible; previe | OPEN |  |
| S3-09 Run counterexample-guided refinement to close gaps discovered by indep | OPEN |  |
| S3-10 Retest policies after relocation, upgrade and adaptive attack. | OPEN |  |
| S3-GATE Independent validation of synthesized boundary and workload utility on | BLOCKED | Gate = independent reviewer attestation; the author cannot grant it. |
| S4-01 Turn HorizonZero registry entries into signed, durable, scoped depende | CANDIDATE | Signed (Ed25519, operator TrustStore) claims in a hash-chained SQLite event log; replay rebuilds state; survives restart. Single host SQLite; keys are test keys |
| S4-02 Bind certificate to exact agent, runtime, policy, tool, witness, artif | CANDIDATE | Claim signature covers a binding with exactly agent/runtime/policy/tool/witness/artifact/issuer/verifier; binding values are the dependency digests, so a change |
| S4-03 Invalidate on adapter/tool/agent changes, revoked consent, lost journa | CANDIDATE | Closed reason set (adapter/tool/agent change, consent revoked, journal lost, proof expired, policy changed, witness unhealthy, operator revoked) plus digest cha |
| S4-04 Make dependent future effects refuse automatically until restored. | CANDIDATE | ProtectedFileWriter(gate=...) denies at commit time, fail-closed on error; a denied effect burns its permit (verifier consumes the nonce first). Wired for the f |
| S4-05 Crash-test claim revocation and approval races across independent proc | CANDIDATE | 4 worker processes race a revoke: no PERMIT logged after REVOKE and returned-True count equals logged PERMITs; 3 SIGKILL rounds leave a valid chain. One host, S |
| S4-06 Preserve old receipts and event histories without rewriting failed cla | CANDIDATE | Append-only log: invalidation/restoration/revocation are new events, PERMITs and failed claims stay in history; mid-log edits/deletes fail closed. LIMIT (tested |
| S4-07 Distinguish SOURCE-VERIFIED from independently reproduced or externall | CANDIDATE | Grade is SOURCE_VERIFIED unless an attestation signed by a DIFFERENT key under the reproducer/auditor role issuer verifies; self-attest, wrong role, wrong claim |
| S4-08 Test two observationally equivalent worlds with conflicting safety out | CANDIDATE | Finite indistinguishability certificate with independent re-verification and missing-witness suggestion; toy worlds authored by the same author. |
| S4-GATE A reviewer can reproduce certificate issuance, revocation and UNKNOWN  | BLOCKED | Gate = independent reviewer attestation; the author cannot grant it. |
| S5-01 Build new independently authored, split-heldout threat worlds. | BLOCKED | Needs independently authored held-out worlds (author-written worlds are not held-out). |
| S5-02 Use live real-model agents rather than only offline trajectory replay. | CANDIDATE | One 0.5B model, mock tools, n=24/cell, templated attacks, gate tuned post hoc; attacked-task utility 0/24 (see NEGATIVE_RESULTS N3). Not a hard-baseline compari |
| S5-03 Implement and run coarse read/send, static gateway, capability and Ope | OPEN |  |
| S5-04 Retain scenarios where baselines outperform MCPHorizon. | OPEN |  |
| S5-05 Demonstrate nontrivial boundary changes instead of policy-template sel | OPEN |  |
| S5-06 Establish formal claims plus code-level conformance, with proof of ass | CANDIDATE | Formal claim + code conformance exists for the commit protocol ONLY; not for synthesis claims C1-C6. |
| S5-07 Run leave-one-family-out, unseen tools, deception and adaptive adversa | OPEN |  |
| S5-08 Quantify task success under attack, false blocks, UNKNOWN burden and p | OPEN |  |
| S5-09 Independently validate source and ground-truth labels; analyze dataset | BLOCKED | Needs independent validation of dataset sources/labels. |
| S5-10 Reproduce headline result in clean environment with another operator. | BLOCKED | Needs a second operator and clean environment to reproduce. |
| S5-GATE Paper candidate must beat a strong relevant baseline on a preregistere | BLOCKED | Gate = independent reviewer attestation; the author cannot grant it. |
| S6-01 Select one *supported integration class* and publish capability covera | BLOCKED | Doc rule: product pilot only after S5-GATE passes; also needs real customers/infrastructure. |
| S6-02 Provide CLI, versioned contract, evidence export and fail-closed error | BLOCKED | Doc rule: product pilot only after S5-GATE passes; also needs real customers/infrastructure. |
| S6-03 Run private trials with synthetic data first, without blanket security | BLOCKED | Doc rule: product pilot only after S5-GATE passes; also needs real customers/infrastructure. |
| S6-04 Measure onboarding time, total infrastructure cost, task completion an | BLOCKED | Doc rule: product pilot only after S5-GATE passes; also needs real customers/infrastructure. |
| S6-05 Conduct key, identity, supply-chain, incident and secrets review. | BLOCKED | Doc rule: product pilot only after S5-GATE passes; also needs real customers/infrastructure. |
| S6-06 Add staged rollout, rollback, emergency kill switch and backup/restore | BLOCKED | Doc rule: product pilot only after S5-GATE passes; also needs real customers/infrastructure. |
| S6-07 Integrate customer feedback with module gate process; never let produc | BLOCKED | Doc rule: product pilot only after S5-GATE passes; also needs real customers/infrastructure. |
| S6-08 Test willingness-to-pay and adoption friction; build bottom-up segment | BLOCKED | Doc rule: product pilot only after S5-GATE passes; also needs real customers/infrastructure. |
| S6-GATE Only promote claims directly supported by independently validated prot | BLOCKED | Gate = independent reviewer attestation; the author cannot grant it. |
| S7-01 HorizonReflex: learn fast System 1 rankings for safe diagnostic probe  | OPEN |  |
| S7-02 Compare against strong non-ML and active-learning baselines with fixed | OPEN |  |
| S7-03 HorizonPatch: test sparse weight repair of agent authority confusion w | OPEN |  |
| S7-04 HorizonSentinel: gate any candidate model patch against utility, tampe | OPEN |  |
| S7-05 HorizonTransfer: assess translation of causal safety edits across arch | OPEN |  |
| S7-06 Prevent experimental model changes from granting new privileges or bec | CANDIDATE | Admission keeps research-track modules off mandatory enforcement and forbids self-verification via reviewer!=author; mechanism only, not wired into a loader. |
