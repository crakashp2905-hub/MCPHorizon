# Open tasks that need something this workspace cannot supply (generated; do not edit)

`EXTERNAL` = needs an independent reviewer, owner decision, legal/licence review, user study or third-party resource.
`NEEDS_LIVE_ENV` = needs a real service, kernel, host or provider not available in the sandbox.

Classes are keyword triage (`class_heuristic`), not proof.  Nothing here is marked done.

## A01 — Schemas, parsing and normalization
- `A01-04` [EXTERNAL] Pin live MCP/UTCP/A2A/AG-UI versions and run official protocol compatibility suites where available.
- `A01-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## A02 — Core capability policy engine
- `A02-05` [EXTERNAL] Commission independent review of proof statements, threat assumptions and implementation correspondence.
- `A02-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## A03 — Policy authority and signed evidence
- `A03-01` [NEEDS_LIVE_ENV] Inventory every signer and issuer; separate fixture-only cryptography from production approval authority.
- `A03-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## A04 — CanonicalEffect and commit-time verification
- `A04-05` [NEEDS_LIVE_ENV] Wire the canonical effect contract to each supported protected sink and actual gateway path.
- `A04-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## A05 — Capability delegation
- `A05-05` [NEEDS_LIVE_ENV] Test live A2A delegation and explicit unsupported transfer forms.
- `A05-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## A06 — Least privilege and downgrade control
- `A06-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## B01 — Decision service and local API
- `B01-04` [NEEDS_LIVE_ENV] Add documented gRPC/HTTP or Unix domain deployment contract with TLS where applicable.
- `B01-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## B02 — Effect ledger and replay protection
- `B02-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## B03 — Protected file sink
- `B03-05` [NEEDS_LIVE_ENV] Run real MCP tool through file sink with blocked and legitimate actions and an independent observer.
- `B03-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## B04 — Network egress broker and remote effects
- `B04-01` [NEEDS_LIVE_ENV] Implement TLS 1.2+/1.3 validation, certificate hostname binding, controlled redirects, DNS pinning and peer verification.
- `B04-02` [NEEDS_LIVE_ENV] Provide forced egress mediation using network namespace/firewall/proxy, preventing raw socket bypass.
- `B04-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## B05 — Kernel sandbox and managed execution
- `B05-03` [NEEDS_LIVE_ENV] Test bypass via descriptor inheritance, abstract sockets, procfs, unix sockets, IPv6, child processes and namespace handles.
- `B05-04` [EXTERNAL] Conduct independent sandbox escape evaluation on supported kernel/architecture variants.
- `B05-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## B06 — Code Mode / generated-code execution
- `B06-01` [NEEDS_LIVE_ENV] Execute Code Mode under mandatory kernel/microVM containment and brokered tool access.
- `B06-05` [NEEDS_LIVE_ENV] Run actual supported code-mode runtimes and execute V8/Node escape and tool-bypass tests.
- `B06-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## B07 — Transactions, obligations and counterfactuals
- `B07-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## B08 — Credential and secret broker
- `B08-02` [EXTERNAL] Add cloud/KMS or local HSM-backed secrets adapter and documented rotation procedure.
- `B08-05` [EXTERNAL] Complete independent key-management review and incident response checklist.
- `B08-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## C01 — MCP gateway
- `C01-01` [EXTERNAL] Exercise latest supported MCP versions and official conformance tests with real servers.
- `C01-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## C02 — UTCP gateway
- `C02-01` [EXTERNAL] Integrate with an unmodified supported UTCP SDK and capture real transport traffic.
- `C02-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## C03 — A2A, framework and skill adapters
- `C03-02` [EXTERNAL] Run at least two real agent frameworks through a standardized conformance suite.
- `C03-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## C04 — Lineage and data-flow tracking
- `C04-04` [NEEDS_LIVE_ENV] Require actual sink-byte observation for claimed prevented exfiltration.
- `C04-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## C05 — Multi-agent isolation and coordination
- `C05-05` [NEEDS_LIVE_ENV] Demonstrate a real multi-agent workflow with independent effect journals.
- `C05-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## C06 — Memory, retention and epistemic evidence
- `C06-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## C07 — Temporal invariants and continuity
- `C07-05` [NEEDS_LIVE_ENV] Exercise causal traces across real services, not just synthetic event lists.
- `C07-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## D01 — Privacy and shared data budgets
- `D01-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## D02 — Consent and approval UX
- `D02-05` [EXTERNAL] Conduct usability study, error-rate analysis and accessibility testing.
- `D02-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## D03 — Incentive-robust enforcement
- `D03-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## D04 — Evaluation integrity
- `D04-04` [EXTERNAL] Externalize challenge tests and make oracle-mutation tests independent of system-under-test code.
- `D04-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## D05 — Browser and vision-effect security
- `D05-05` [NEEDS_LIVE_ENV] Run live browser with independent receiver/origin journal and realistic agent-generated actions.
- `D05-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## D06 — Downgrade/fallback and model policy
- `D06-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## E01 — HorizonEmergence
- `E01-02` [NEEDS_LIVE_ENV] Use real agents, tool servers, delegation and complex transform sequences.
- `E01-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## E02 — HorizonCoverage
- `E02-05` [EXTERNAL] Use independent review to certify monitored versus unmonitored operation classes.
- `E02-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## E03 — HorizonMutation
- `E03-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## E04 — HorizonReach
- `E04-03` [NEEDS_LIVE_ENV] Retest DNS rebinding, nested redirects, misleading attestation and partial response omission.
- `E04-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## E05 — HorizonCounterfactual
- `E05-02` [NEEDS_LIVE_ENV] Prove preview is isolated from real production credentials and effect sinks.
- `E05-05` [EXTERNAL] Use formal limitation statements for externally unobservable consequences.
- `E05-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## E06 — Security telemetry and forensic attribution
- `E06-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## E07 — Static code and infrastructure assurance
- `E07-01` [NEEDS_LIVE_ENV] Run real source projects and real generated code through functional and exploitability oracles.
- `E07-03` [NEEDS_LIVE_ENV] Test model artifact trigger behaviors against actual model checkpoints if claimed.
- `E07-04` [EXTERNAL] Separate static warning, exploitable vulnerability and observed external effect in output.
- `E07-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## F01 — HorizonZero assurance registry
- `F01-05` [EXTERNAL] Independently establish novelty beyond existing runtime contracts and formal monitorability research.
- `F01-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## F02 — HorizonForge boundary synthesis
- `F02-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## F03 — HorizonSpectra tomography
- `F03-05` [EXTERNAL] Validate probe safety, cost and discoveries with an external fixture author.
- `F03-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## F04 — HorizonPatch weight-space editing
- `F04-01` [EXTERNAL] Pin open-weight checkpoints, tokenizers and licenses, and reproduce a documented non-security weight edit.
- `F04-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## F05 — HorizonSentinel weight integrity
- `F05-05` [EXTERNAL] Sign checkpoint and patch provenance; make any promotion require external verification.
- `F05-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## F06 — HorizonTransfer cross-model safety patch
- `F06-05` [NEEDS_LIVE_ENV] Publish null results and disallow transplanting patches into protected production models.
- `F06-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## F07 — HorizonReflex System 1 probe selection
- `F07-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## F08 — Seven research novelty helpers
- `F08-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## G01 — Synthetic SecBench and study pipelines
- `G01-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## G02 — External datasets and replay studies
- `G02-01` [EXTERNAL] Validate provenance, licenses, dataset overlap and label semantics; ensure no hidden leakage into held-out test.
- `G02-02` [NEEDS_LIVE_ENV] Make offline replay metrics distinct from live attack prevention and counterfactual utility.
- `G02-04` [NEEDS_LIVE_ENV] Run compatible live benchmarks with independently observed outcomes; include per-suite/model robustness.
- `G02-05` [EXTERNAL] Fix dataset v0 saturation with blinded external authoring, adaptive attackers and harder controls.
- `G02-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## G03 — Supervisor and autonomous development
- `G03-01` [EXTERNAL] Keep worker, reviewer, signers and evaluation data under separate identities and filesystem permissions.
- `G03-04` [EXTERNAL] Test worker compromise, reviewer compromise, tool-output injection, collusion and altered benchmarks.
- `G03-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## G04 — Release engineering and supply chain
- `G04-02` [EXTERNAL] Resolve licenses, older proprietary component provenance and release rights before publication.
- `G04-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## G05 — Operations, audits and disaster recovery
- `G05-05` [EXTERNAL] Conduct independent security and operational readiness review prior to product claims.
- `G05-GATE` [EXTERNAL] Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

