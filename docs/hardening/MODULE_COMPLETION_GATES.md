# MCPHorizon — Module Completion & Universal Agent Security Platform Readiness

**Repository:** https://github.com/crakashp2905-hub/MCPHorizon  
**Inspected HEAD:** `8c4d0cc5c1c8dd6a77aa5d198ffd79f0ef4e1dab` (as of 2026-11-04)  
**Document type:** Engineering execution and assurance checklist — **not** a declaration of completion or security certification.  
**Project intent:** First finish and validate existing modules; *only then* assemble a modular agent-onboarding platform capable of enforcing a defined security contract for any **supported** agent/runtime/effect type.

## Executive decisions and non-negotiable safety claims

1. **No universal safety guarantee exists for arbitrary agents.** Without controlling their tools, processes, credentials, network, memory, or effects, a platform cannot certify every possible behavior. Onboarding must reject unsupported effect paths or isolate them before asserting protection.
2. **Separate three measures:** (i) candidate implementation, (ii) author/test-harness result, (iii) independent evidence of real-world effect enforcement. They must never be conflated.
3. **No feature proliferation until foundational modules pass their stage gate.** Research modules remain optional/sandboxed, never silently added to the mandatory security kernel.
4. **No autonomous self-certification:** implementation workers cannot hold approval or verifier trust roots, cannot change benchmark labels invisibly, and cannot mark their own work `INDEPENDENTLY_VERIFIED`.
5. **All evidence must refer to an exact commit, environment, threat model, executable acceptance commands, independently controlled oracle, attack/benign denominators, performance budget, and observed failures.**
6. **Correctness before product packaging.** Customer discovery, commercial licensing, multi-tenant SaaS, dashboards, pricing and GA are explicitly outside this module-completion effort. Legal/provenance review is still required before distributing artifacts.

### Verified repo facts used in triage

- Main branch HEAD recorded above; newest `tests` and `verify` workflows were green at inspection, but passing CI is not the same as independent assurance.
- P54 frozen integration record: **13 PASS, 2 FAIL, 1 SKIP**; later source fixes/reclassifications are not independent re-verification of the old report.
- P55–P94 roadmap: **142/720 task IDs mapped to candidate commands**, **578 unmapped** in the repository's generated status; these figures do not measure feature completion.
- Original project status records **0/1,686 formally VERIFIED** by independent authority. Recount when a new signed independent ledger exists.
- **P44 HorizonReach** first-call effect through deceptive attested external service: **3/45 attack effects occurred**; subsequent revocation does not reverse the first disclosure.
- **P51 VisionGuard** benign completion **9/11** in its controlled suite.
- Main SecBench 0.2: full policy **2/30 attacks succeeded, 26/30 benign succeeded**, tied with coarse read/send baseline B3. Additional separating benign cases were post hoc, not confirmatory.
- Latest datasets: 24 registered sources; 22 parsed, but many are not evaluated; AgentDojo/AgentDyn analyses use **offline replay**, not live defense deployment.
- Weight-space API currently contains patch validation/versioning utilities; **no actual model-weight safety-repair experiment is demonstrated**.

## Target product-independent security contract (future integration entry condition)

For every supported consequential effect `e` of an onboarded agent, require:

```
TrustedIdentity(e)
AND EffectContractKnown(e)
AND CanonicalTarget(e)
AND PermitBoundToExactEffect(e)
AND CommitTimePolicyValid(e)
AND MandatorySinkMediation(e)
AND DurableReplayPrevention(e)
AND ObservableOutcomeOrExplicitUNKNOWN(e)
```

The platform shall not silently map `UNKNOWN` to `SAFE`, `ALLOW`, or `COMMITTED`. A module can be complete for a **defined, narrow scope** while other effect classes remain unsupported. Do not require theoretically impossible proof of all agent behaviors before progressing on a limited supported scope.

## Completion vocabulary

- `UNMAPPED` — source/owner/acceptance unknown.
- `CANDIDATE` — implemented with developer-run tests.
- `INTEGRATED` — wired into an actual supported agent/protocol/OS effect path.
- `ADVERSARIAL_TESTED` — independent fixtures, attacks and benign controls against real outcome oracles.
- `INDEPENDENTLY_VERIFIED` — an external authorized reviewer signed the exact scope and immutable evidence.
- `HARDENED_FOR_SCOPE` — above evidence plus required operational and security exit gates; **not** a promise of universal safety.
- `BLOCKED` — prerequisite, reviewer, realistic environment or evidence missing.

**Module-specific tasks below are *proposed work*, not completed items.** Every checkbox begins unchecked even when partial code/tests exist. A work item closes only after evidence demonstrating the stated result is linked.

## Universal exit checklist — apply to every module

- [ ] **U-01** Freeze exact source commit, module version, declared API and threat model.
- [ ] **U-02** Enumerate all trusted/untrusted actors, inputs, outputs, side effects and failure modes.
- [ ] **U-03** Specify invariant and what is *not* guaranteed; provide explicit `UNKNOWN`/unsupported handling.
- [ ] **U-04** Add property tests, generated edge cases, concurrency/retry/crash tests as applicable.
- [ ] **U-05** Add at least one independent attack fixture, one matched benign control and one falsifiable acceptance test.
- [ ] **U-06** Verify observation at the real enforcement/receiver boundary, never only in model-written logs.
- [ ] **U-07** Compare with a strongest practical baseline; quantify safety **and** legitimate-task utility.
- [ ] **U-08** Measure resource use and performance on pinned hardware/workload; regression alert.
- [ ] **U-09** Eliminate ambient authority, hidden singletons, secret exposure and undocumented global state.
- [ ] **U-10** Publish versioned schemas/API, compatibility support matrix, backward-change migration and error behavior.
- [ ] **U-11** Maintain a negative-findings ledger, residual risks and tests for known bypass cases.
- [ ] **U-12** Obtain independent verification of a frozen result before promoting out of CANDIDATE.

## Dependency ordering (not a new phase count)

**Stage 0:** Inventory, evidence, independent roles, baseline correctness.  
**Stage 1:** Contracts/core/authority → canonical effects → nonce/ledger → file/network sink → sandbox.  
**Stage 2:** MCP/UTCP/Code Mode/A2A live binding → lineage, delegation, privacy, approvals, continuity.  
**Stage 3:** Coverage, independent oracles, attack suites, formal claims → real-agent and cross-protocol evaluation.  
**Stage 4:** Mature candidate research tracks independently; promote selectively if they improve evidence over strong baselines.  
**Stage 5:** Integrate modules into a narrow, enforceable agent-onboarding system **only after** dependencies meet gates.  
**Stage 6:** Operations/deployment/productization with separate approvals.

**Critical path:** Policy authority → effect schema → commit authorization → durable ledger → mandatory protected sink → independently observed side effect → real agent → evidence ledger → reviewer sign-off.


## Workstream A — Contracts, policy and security foundations

### A01 — Schemas, parsing and normalization

**Current implementation:** `horizon/schemas.py; horizon/normalize.py; schemas/; core/`  
**Associated work:** P1  
**Known completion blocker:** Different language runtimes cover different semantic validations.  

- [ ] **A01-01** Freeze and version schemas for event, effect, authorization, permit, evidence and plugin contracts; reject unknown security-critical fields.
- [ ] **A01-02** Implement full Python/Rust/TS *semantic* parity, not merely JSON-schema parity, on generated and malicious fixtures.
- [ ] **A01-03** Define canonical URL, path, Unicode, numeric, JSON-RPC typed-ID and argument-digest rules; fuzz differential normalization.
- [ ] **A01-04** Pin live MCP/UTCP/A2A/AG-UI versions and run official protocol compatibility suites where available.
- [ ] **A01-05** Prove ambiguous input and unsupported protocol versions fail closed without changing protected state.
- [ ] **A01-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### A02 — Core capability policy engine

**Current implementation:** `horizon/core/; core/crates/horizon-core/`  
**Associated work:** P2  
**Known completion blocker:** Rust covers a subset of the Python policy semantics.  

- [ ] **A02-01** Write precise policy algebra for scopes, ownership, purpose, label join, effect class and policy precedence.
- [ ] **A02-02** Finish Rust parity for all claimed Python core operations or mark unsupported and force verified fallback.
- [ ] **A02-03** Property-test monotonic restriction, non-escalating delegation, deny precedence, transitivity and canonical equivalence.
- [ ] **A02-04** Use model checking or exhaustive finite-state exploration for revocation and capability composition.
- [ ] **A02-05** Commission independent review of proof statements, threat assumptions and implementation correspondence.
- [ ] **A02-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### A03 — Policy authority and signed evidence

**Current implementation:** `horizon/hpolicy/; horizon/authz/; horizon/authn.py`  
**Associated work:** P13/P19  
**Known completion blocker:** Separate signers still appear in evidence/fixtures; trust-root consolidation needs external judgment.  

- [ ] **A03-01** Inventory every signer and issuer; separate fixture-only cryptography from production approval authority.
- [ ] **A03-02** Use asymmetric role-scoped keys for evidence and permits; enforce key revocation and rotation.
- [ ] **A03-03** Bind exact principal, tenant, session, target, arguments, effect, policy epoch and expiry to permits.
- [ ] **A03-04** Eliminate approval issuance from untrusted plugins; verifier accepts explicit trusted roots only.
- [ ] **A03-05** Test replay, clock skew, forged issuer, stale policy, downgrade, revoked role and tampered certificate cases.
- [ ] **A03-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### A04 — CanonicalEffect and commit-time verification

**Current implementation:** `horizon/effects/canonical.py`  
**Associated work:** E03  
**Known completion blocker:** Candidate not fully wired through all protocol adapters.  

- [ ] **A04-01** Provide one canonical effect representation used by all gateways and sinks.
- [ ] **A04-02** Make issuance and verification derive identical domain-separated digests without duplicated logic.
- [ ] **A04-03** Test TOCTOU policy revocation between request, allow, commit and sink observation.
- [ ] **A04-04** Exercise payload mutation, path alias, Unicode, target substitution and server/session substitution attacks.
- [ ] **A04-05** Wire the canonical effect contract to each supported protected sink and actual gateway path.
- [ ] **A04-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### A05 — Capability delegation

**Current implementation:** `horizon/deleg/; horizon/a2a/`  
**Associated work:** P15/P87  
**Known completion blocker:** Cross-protocol delegated identity needs real interop and revocation proof.  

- [ ] **A05-01** Express grants as attenuating, time-bounded, purpose-bounded capabilities.
- [ ] **A05-02** Enforce non-escalation through nested delegation, cycles, delegation-depth and mixed protocols.
- [ ] **A05-03** Propagate revocation epochs across asynchronous agents and durable queues.
- [ ] **A05-04** Bind every sub-agent effect to its originating authority and independent trace.
- [ ] **A05-05** Test live A2A delegation and explicit unsupported transfer forms.
- [ ] **A05-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### A06 — Least privilege and downgrade control

**Current implementation:** `horizon/lp/; horizon/downgrade/`  
**Associated work:** P20/P46  
**Known completion blocker:** Some attacks are stopped by denying tasks; utility cost must be quantified.  

- [ ] **A06-01** Define a task floor and allowed capability lattice before fallback selection.
- [ ] **A06-02** Prevent fallback profiles from gaining new effects, destinations or evidence powers.
- [ ] **A06-03** Benchmark successful benign task completion versus denial-heavy policies.
- [ ] **A06-04** Test revoked permissions, unexpected adapter changes and permissive fallback defaults.
- [ ] **A06-05** Expose explainable, policy-backed least-privilege recommendations without auto-applying them.
- [ ] **A06-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## Workstream B — Execution, effects, containment and integrity

### B01 — Decision service and local API

**Current implementation:** `horizon/service/; horizon/sdk/; sdk-ts/`  
**Associated work:** P3  
**Known completion blocker:** Core service still has in-memory tenant state and local transport assumptions.  

- [ ] **B01-01** Replace in-memory approval, idempotency and decision authority with durable transactional storage.
- [ ] **B01-02** Implement actual preemptive evaluation timeouts and bounded resource budgets.
- [ ] **B01-03** Provide strict authN/authZ, secret rotation, scoped principals, audit-write fail-close.
- [ ] **B01-04** Add documented gRPC/HTTP or Unix domain deployment contract with TLS where applicable.
- [ ] **B01-05** Measure end-to-end p50/p95/p99, under congestion and dependency failures; document SLOs.
- [ ] **B01-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### B02 — Effect ledger and replay protection

**Current implementation:** `horizon/effects/ledger.py`  
**Associated work:** E04  
**Known completion blocker:** SQLite single-node tests, not cross-process failover or a full gateway.  

- [ ] **B02-01** Wire all permit redemptions and protected dispatches to one transactional ledger.
- [ ] **B02-02** Prove atomic nonce consumption across multiple processes and separate hosts.
- [ ] **B02-03** Implement fenced leadership, exactly identified effect IDs, idempotent reconciliation and backup/restore.
- [ ] **B02-04** Crash-inject before/after permit consumption, sink commit, receipt persistence and response transmission.
- [ ] **B02-05** Distinguish at-most-once dispatch from exactly-once external effects; report irreducible UNKNOWN honestly.
- [ ] **B02-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### B03 — Protected file sink

**Current implementation:** `horizon/effects/filesink.py`  
**Associated work:** E05/E06  
**Known completion blocker:** Library enforcement can be bypassed if agent shares OS authority with sink.  

- [ ] **B03-01** Place file operations behind a separate OS principal and protected broker endpoint.
- [ ] **B03-02** Test bypass attempts through direct open, symlinks, hardlinks, proc fd, mount aliases, race renames and child processes.
- [ ] **B03-03** Enforce realpath/inode containment and exact byte/hash binding at the actual write boundary.
- [ ] **B03-04** Own sink journal and signing keys in a distinct trust domain from agent and gateway.
- [ ] **B03-05** Run real MCP tool through file sink with blocked and legitimate actions and an independent observer.
- [ ] **B03-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### B04 — Network egress broker and remote effects

**Current implementation:** `horizon/runtime/broker.py; horizon/reach/`  
**Associated work:** P25/P44  
**Known completion blocker:** Research egress HTTP-only; deceptive attested service leaks on first use.  

- [ ] **B04-01** Implement TLS 1.2+/1.3 validation, certificate hostname binding, controlled redirects, DNS pinning and peer verification.
- [ ] **B04-02** Provide forced egress mediation using network namespace/firewall/proxy, preventing raw socket bypass.
- [ ] **B04-03** Make nonce use atomic across processes and bind permits to method, destination, headers and exact body.
- [ ] **B04-04** Re-test deceptive remote services: never claim first-call secrecy against a service receiving raw secrets.
- [ ] **B04-05** Explore data minimization, secure local computation, encryption or refusal for untrusted services; record residual impossibility.
- [ ] **B04-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### B05 — Kernel sandbox and managed execution

**Current implementation:** `horizon/runtime/sandbox.py; horizon/runtime/managed.py`  
**Associated work:** P24/P27/P30  
**Known completion blocker:** Single-kernel/architecture test; no full sandbox bypass assurance.  

- [ ] **B05-01** Define supported Linux kernel/container matrix, Landlock/seccomp/ns and cgroup requirements.
- [ ] **B05-02** Ensure every untrusted execution path is launched without host-equivalent privileges or inherited capabilities.
- [ ] **B05-03** Test bypass via descriptor inheritance, abstract sockets, procfs, unix sockets, IPv6, child processes and namespace handles.
- [ ] **B05-04** Conduct independent sandbox escape evaluation on supported kernel/architecture variants.
- [ ] **B05-05** Fail closed with explicit unsupported status when controls cannot be installed.
- [ ] **B05-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### B06 — Code Mode / generated-code execution

**Current implementation:** `horizon/codemode/; codemode/`  
**Associated work:** P6  
**Known completion blocker:** isolated-vm not equivalent to OS sandbox; partial cancellation guarantees.  

- [ ] **B06-01** Execute Code Mode under mandatory kernel/microVM containment and brokered tool access.
- [ ] **B06-02** Use strict instruction/runtime resource limits, no ambient secrets and no unmediated network/filesystem access.
- [ ] **B06-03** Prove tool-call provenance and retained authority across generated scripts and chained tools.
- [ ] **B06-04** Distinguish cancellation-before-dispatch from cancellation-after-possible-execution; reconcile uncertain effects.
- [ ] **B06-05** Run actual supported code-mode runtimes and execute V8/Node escape and tool-bypass tests.
- [ ] **B06-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### B07 — Transactions, obligations and counterfactuals

**Current implementation:** `horizon/txn/; horizon/obligation/; horizon/counterfactual/`  
**Associated work:** P17/P40/P41  
**Known completion blocker:** Synthetic state transitions and previews do not guarantee real-world rollback.  

- [ ] **B07-01** Model prerequisite obligations as typed, durable and consumable dependencies.
- [ ] **B07-02** Verify before/after effects, policy drift, rollback capability and side-effect-free previews.
- [ ] **B07-03** Define non-rollbackable effect handling, compensation plans and safe explicit refusal.
- [ ] **B07-04** Check transaction outcomes against sink-observed side effects under crashes and races.
- [ ] **B07-05** Benchmark utility and false denials for strict obligation enforcement.
- [ ] **B07-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### B08 — Credential and secret broker

**Current implementation:** `horizon/ops/secrets.py; horizon/ops/keys.py; horizon/ops/approvals.py`  
**Associated work:** P10/P26  
**Known completion blocker:** No managed production secret store and rotation exercise.  

- [ ] **B08-01** Use least-privilege per-agent short-lived credentials with trusted custody.
- [ ] **B08-02** Add cloud/KMS or local HSM-backed secrets adapter and documented rotation procedure.
- [ ] **B08-03** Prevent credential presence in untrusted logs, tool responses, child environment or crash dumps.
- [ ] **B08-04** Run revocation races, leaked-token replay, cross-tenant credential substitution and host failure drills.
- [ ] **B08-05** Complete independent key-management review and incident response checklist.
- [ ] **B08-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## Workstream C — Protocol, identity, information-flow and multi-agent modules

### C01 — MCP gateway

**Current implementation:** `horizon/adapters/mcp/`  
**Associated work:** P4/E02  
**Known completion blocker:** Request scoping fixed; real server interop and mandatory sink path remain open.  

- [ ] **C01-01** Exercise latest supported MCP versions and official conformance tests with real servers.
- [ ] **C01-02** Bind session/server/tenant/principal/typed request ID through cache, cancellation, permit and effect receipt.
- [ ] **C01-03** Enforce trusted tool mapping/manifest pinning; reject unreviewed schema updates.
- [ ] **C01-04** Prevent direct tool invocation and downstream effects outside the MCP gateway.
- [ ] **C01-05** Measure throughput, cancellation races, server restart, streaming, auth and read-versus-effect handling.
- [ ] **C01-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### C02 — UTCP gateway

**Current implementation:** `horizon/adapters/utcp/`  
**Associated work:** P5  
**Known completion blocker:** Host HTTP client can bypass checks, real SDK/transport parity not established.  

- [ ] **C02-01** Integrate with an unmodified supported UTCP SDK and capture real transport traffic.
- [ ] **C02-02** Prevent SDK direct-call bypass, malicious manuals, URLs, path normalization and SSRF.
- [ ] **C02-03** Enforce exact request payload and credential scoping at outbound transport boundary.
- [ ] **C02-04** Complete conformance for supported HTTP/CLI transports; mark WS/gRPC unsupported until implemented.
- [ ] **C02-05** Compare equivalent logical effects across MCP and UTCP with independent outcomes.
- [ ] **C02-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### C03 — A2A, framework and skill adapters

**Current implementation:** `horizon/a2a/; horizon/frameworks/; horizon/skillpolicy/`  
**Associated work:** P87/P90  
**Known completion blocker:** Mostly candidate contracts rather than live framework deployment.  

- [ ] **C03-01** Define versioned adapter ABI with typed effect, trusted identity and capability evidence.
- [ ] **C03-02** Run at least two real agent frameworks through a standardized conformance suite.
- [ ] **C03-03** Prove trust and revocation survive handoffs, remote agent response spoofing and reentrancy.
- [ ] **C03-04** Validate skill/tool package provenance, signatures, updates and prompt-content trust separation.
- [ ] **C03-05** Ensure unsupported methods cannot implicitly bypass authorization.
- [ ] **C03-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### C04 — Lineage and data-flow tracking

**Current implementation:** `horizon/lineage/`  
**Associated work:** P7  
**Known completion blocker:** Known paraphrase/encoding misses; finite label coverage.  

- [ ] **C04-01** Formalize tracked values, derived artifacts, implicit flows and declassification authority.
- [ ] **C04-02** Test transformed secrets: reverse, chunks, paraphrase, compression, base64, embeddings and summarization.
- [ ] **C04-03** Report detection coverage and UNKNOWN for untracked transformations instead of false negatives hidden as safe.
- [ ] **C04-04** Require actual sink-byte observation for claimed prevented exfiltration.
- [ ] **C04-05** Compare with CaMeL, tracked-capability systems and coarse run-level rules on identical tasks.
- [ ] **C04-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### C05 — Multi-agent isolation and coordination

**Current implementation:** `horizon/agents/; horizon/continuity/`  
**Associated work:** P34/P53  
**Known completion blocker:** Deceived attestation and unknown cross-agent transfer remain.  

- [ ] **C05-01** Isolate principals, memory, working directories, tool tokens and durable state between collaborating agents.
- [ ] **C05-02** Implement durable delegation lineage and revocation epochs across reboots and migration.
- [ ] **C05-03** Test cross-agent collusion, hidden channels, replayed messages and forged role transitions.
- [ ] **C05-04** Address P53 U02 deceived attestor with an independent trust source or declare impossibility.
- [ ] **C05-05** Demonstrate a real multi-agent workflow with independent effect journals.
- [ ] **C05-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### C06 — Memory, retention and epistemic evidence

**Current implementation:** `horizon/memory/; horizon/epist/`  
**Associated work:** P16/P18  
**Known completion blocker:** No proof of correctness for unknown world facts, and narrow controlled tests.  

- [ ] **C06-01** Specify provenance, confidence, staleness, expiration and ownership for memory-derived facts.
- [ ] **C06-02** Define evidence independence and non-circular promotion of asserted facts into authorization premises.
- [ ] **C06-03** Prevent malicious memory writes or retrievals from expanding capabilities.
- [ ] **C06-04** Test poisoning across sessions, deletion/retention and tenant isolation.
- [ ] **C06-05** Explicitly separate truth uncertainty from effect authorization confidence.
- [ ] **C06-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### C07 — Temporal invariants and continuity

**Current implementation:** `horizon/temporal/; horizon/continuity/`  
**Associated work:** P52/P53  
**Known completion blocker:** Unsupported paths and deceived attestations are marked UNKNOWN.  

- [ ] **C07-01** Model event ordering, wall-clock skew and revocation epochs under distributed execution.
- [ ] **C07-02** Test delayed effects, cancellations, replay and out-of-order callback completion.
- [ ] **C07-03** Prove no mandatory protection silently weakens after migration/fallback/restart.
- [ ] **C07-04** Monitor clock drift, missing events and invalidated evidence as security events.
- [ ] **C07-05** Exercise causal traces across real services, not just synthetic event lists.
- [ ] **C07-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## Workstream D — Privacy, consent, misuse, integrity and human safeguards

### D01 — Privacy and shared data budgets

**Current implementation:** `horizon/privacy/; horizon/budget/`  
**Associated work:** P45/P50  
**Known completion blocker:** UNKNOWN reservation remains charged and may never reconcile.  

- [ ] **D01-01** Define privacy labels, dataset scopes, per-principal budget accounting and tenant boundaries.
- [ ] **D01-02** Atomically reserve/commit/release budgets across workers and service restarts.
- [ ] **D01-03** Design verifiable resolution or bounded expiration policy for UNKNOWN budget reservations.
- [ ] **D01-04** Test concurrency, cancellation, duplicated requests and indirect re-identification transformations.
- [ ] **D01-05** Quantify legitimate workflow impact and privacy leakage limitations.
- [ ] **D01-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### D02 — Consent and approval UX

**Current implementation:** `horizon/consent/; horizon/approvalui/`  
**Associated work:** P48/P46  
**Known completion blocker:** Synthetic approvals and adversarial cases need real user-study evidence.  

- [ ] **D02-01** Bind consent to exact effects, recipients, purpose, scope, expiry and data sensitivity.
- [ ] **D02-02** Prevent dark patterns, confusing fallback, approval phishing and authority spoofing.
- [ ] **D02-03** Provide reviewable diff of intended action and irreversible downstream consequences.
- [ ] **D02-04** Test revoke-after-approve race with actual effect ledger and trusted UI identity.
- [ ] **D02-05** Conduct usability study, error-rate analysis and accessibility testing.
- [ ] **D02-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### D03 — Incentive-robust enforcement

**Current implementation:** `horizon/incentive/`  
**Associated work:** P47  
**Known completion blocker:** Controlled adversarial incentive scenarios only.  

- [ ] **D03-01** Demonstrate policy enforcement independent of model reward, planning heuristics or instruction pressure.
- [ ] **D03-02** Test cross-agent reward hacking, self-modification attempts and audit-avoidance behavior.
- [ ] **D03-03** Compare hard reference monitor against soft policy penalties and model-level refusal.
- [ ] **D03-04** Measure task utility under realistic incentives and model/temperature variation.
- [ ] **D03-05** Define applicability of tests to learned agents and where scripted proxies are insufficient.
- [ ] **D03-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### D04 — Evaluation integrity

**Current implementation:** `horizon/evalint/; horizon/integration/`  
**Associated work:** P49/P54  
**Known completion blocker:** All-collectors omission can produce false PASS in known X01 case.  

- [ ] **D04-01** Place evidence collector, keys and signing under independent authority.
- [ ] **D04-02** Block false PASS if all expected collectors omit or collude; degrade to UNKNOWN on missing coverage.
- [ ] **D04-03** Verify correlation of evidence across filesystem, network, process and receivers.
- [ ] **D04-04** Externalize challenge tests and make oracle-mutation tests independent of system-under-test code.
- [ ] **D04-05** Re-run ES-G1..16 on a new frozen integration report and resolve/freeze all deviations.
- [ ] **D04-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### D05 — Browser and vision-effect security

**Current implementation:** `horizon/vision/`  
**Associated work:** P51  
**Known completion blocker:** 2 of 11 benign cases blocked; browser scope not deployed generally.  

- [ ] **D05-01** Enforce browser origin, click target, form submission, download and navigation as concrete effects.
- [ ] **D05-02** Distinguish screenshot/text interpretation from trusted DOM/network outcome evidence.
- [ ] **D05-03** Test deceptive overlays, browser extension bypass, redirects, racey UI, nested frames and permission prompts.
- [ ] **D05-04** Correct 2/11 benign overblocks and measure impact on new benign workflows.
- [ ] **D05-05** Run live browser with independent receiver/origin journal and realistic agent-generated actions.
- [ ] **D05-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### D06 — Downgrade/fallback and model policy

**Current implementation:** `horizon/downgrade/; horizon/weights/`  
**Associated work:** P46/P89  
**Known completion blocker:** Candidate helper-level security-floor constraints, no production binding.  

- [ ] **D06-01** Pin policies and guarantee fallback monotonicity under lower capability or missing attestation.
- [ ] **D06-02** Prohibit accepting weak model/tool safety claims in place of verified effect permissions.
- [ ] **D06-03** Exercise multi-model fallback, tool errors, version skew and missing sensors.
- [ ] **D06-04** Publish quantified security-versus-utility tradeoffs and denial reasons.
- [ ] **D06-05** Ensure model weights/prompts cannot unilaterally change the trusted enforcement kernel.
- [ ] **D06-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## Workstream E — Security analysis, attack discovery and coverage

### E01 — HorizonEmergence

**Current implementation:** `horizon/emergence/`  
**Associated work:** P39  
**Known completion blocker:** Only four leaking synthetic chains; two behind UNKNOWN unmodeled endpoints.  

- [ ] **E01-01** Increase independent composition families beyond handwritten source-transform-sink chains.
- [ ] **E01-02** Use real agents, tool servers, delegation and complex transform sequences.
- [ ] **E01-03** Test exact detection/UNKNOWN calibration with completely independent receiver-side oracles.
- [ ] **E01-04** Compare guided search versus brute force, graph search, taint, coarse history and CaMeL-style controls.
- [ ] **E01-05** Falsify finite-model completeness by varying assumptions, hidden endpoints and oracle blind spots.
- [ ] **E01-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### E02 — HorizonCoverage

**Current implementation:** `horizon/coverage/`  
**Associated work:** P42  
**Known completion blocker:** Some physical effect sinks lack independent coverage proof.  

- [ ] **E02-01** Enumerate supported protected sinks and link each to a mandatory enforcement boundary.
- [ ] **E02-02** Add active probes for unmediated child processes, credential reads, filesystem, socket and unknown transports.
- [ ] **E02-03** Generate signed coverage statements with exact threat model and expiry.
- [ ] **E02-04** Fail closed or withdraw scope-specific claims on coverage regression.
- [ ] **E02-05** Use independent review to certify monitored versus unmonitored operation classes.
- [ ] **E02-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### E03 — HorizonMutation

**Current implementation:** `horizon/mutation/`  
**Associated work:** P43  
**Known completion blocker:** Mutations and oracle cases are primarily same-author designed.  

- [ ] **E03-01** Implement independent mutant-generation harness and semantics-preserving mutation filters.
- [ ] **E03-02** Benchmark survival and verdict-changing rates on held-out systems and attack families.
- [ ] **E03-03** Attribute each detected failure to a precise security invariant rather than a matching string.
- [ ] **E03-04** Add minimal counterexample reduction and proof/evidence export.
- [ ] **E03-05** Use mutations to regression-test all integration-critical modules automatically.
- [ ] **E03-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### E04 — HorizonReach

**Current implementation:** `horizon/reach/`  
**Associated work:** P44  
**Known completion blocker:** 3/45 attacker effects from deceptive attested remote services.  

- [ ] **E04-01** Add first-call leak scenario as permanently tracked regression; no dishonest claims of automatic prevention.
- [ ] **E04-02** Use independent effect observers and disallow untrusted raw-secret exposure unless protected by a defensible method.
- [ ] **E04-03** Retest DNS rebinding, nested redirects, misleading attestation and partial response omission.
- [ ] **E04-04** Publish residual disclosure rate alongside completed legitimate tasks, latency and UNKNOWN.
- [ ] **E04-05** Show protection under multi-hop, multi-service, multi-agent real execution.
- [ ] **E04-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### E05 — HorizonCounterfactual

**Current implementation:** `horizon/counterfactual/`  
**Associated work:** P41  
**Known completion blocker:** Sandbox previews may not cover actual downstream external effects.  

- [ ] **E05-01** Model irreversibility and non-replayable effects explicitly.
- [ ] **E05-02** Prove preview is isolated from real production credentials and effect sinks.
- [ ] **E05-03** Detect divergence between previewed and commit-time targets/payloads.
- [ ] **E05-04** Measure preview false approval and false blocking against receiver-side truth.
- [ ] **E05-05** Use formal limitation statements for externally unobservable consequences.
- [ ] **E05-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### E06 — Security telemetry and forensic attribution

**Current implementation:** `horizon/telemetry/; horizon/attest/`  
**Associated work:** P35/P19  
**Known completion blocker:** Polling sensors can miss short-lived processes; some trust roots are process-local.  

- [ ] **E06-01** Instrument kernel and sink boundaries with bounded event loss reporting.
- [ ] **E06-02** Test forged transcripts, tampered collector output, missing events and independent witness disagreement.
- [ ] **E06-03** Separate receipt signing identities from agents and runtime supervisors.
- [ ] **E06-04** Anchor logs to independently held keys or append-only storage and test tamper evidence.
- [ ] **E06-05** Publish forensic completeness/uncertainty for each supported OS and adapter.
- [ ] **E06-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### E07 — Static code and infrastructure assurance

**Current implementation:** `horizon/codeassur/; horizon/infraguard/; horizon/triggerlab/`  
**Associated work:** P32/P33/P36  
**Known completion blocker:** Toy code generators and format-mismatched scanner comparisons limit claims.  

- [ ] **E07-01** Run real source projects and real generated code through functional and exploitability oracles.
- [ ] **E07-02** Compare tools on *their own supported input formats*; avoid invalid scanner superiority claims.
- [ ] **E07-03** Test model artifact trigger behaviors against actual model checkpoints if claimed.
- [ ] **E07-04** Separate static warning, exploitable vulnerability and observed external effect in output.
- [ ] **E07-05** Benchmark coverage, false alerts and runtime costs under independent cases.
- [ ] **E07-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## Workstream F — New research modules — keep isolated until validated

### F01 — HorizonZero assurance registry

**Current implementation:** `horizon/assurance/`  
**Associated work:** HF  
**Known completion blocker:** Candidate registry; crash-consistent invalidation not yet proven.  

- [ ] **F01-01** Formalize assurance certificate schema, exact effect/sink scope and evidence dependencies.
- [ ] **F01-02** Make claim invalidation atomic with authorization and durable across restart and migration.
- [ ] **F01-03** Prove no stale assurance can authorize a new protected effect.
- [ ] **F01-04** Test collector omission, collusion, false witnesses and threat-model expansion.
- [ ] **F01-05** Independently establish novelty beyond existing runtime contracts and formal monitorability research.
- [ ] **F01-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### F02 — HorizonForge boundary synthesis

**Current implementation:** `horizon/forge/`  
**Associated work:** HF  
**Known completion blocker:** Finite enumerative toy synthesis; no SMT or real infrastructure.  

- [ ] **F02-01** Implement typed IR for real deployment controls, witnesses, relocation, consent and delegation.
- [ ] **F02-02** Add SMT/MaxSAT or verified bounded optimizer with independently checkable proofs where possible.
- [ ] **F02-03** Generate enactable patches/configurations under an allowlisted deployment environment.
- [ ] **F02-04** Test synthesized boundary against real sinks, strong rule-based and human-designed baselines.
- [ ] **F02-05** State bounded non-certifiability precisely; never claim global impossibility from a finite plan set.
- [ ] **F02-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### F03 — HorizonSpectra tomography

**Current implementation:** `research/spectra/`  
**Associated work:** SP  
**Known completion blocker:** Toy finite hypothesis worlds, no live black-box tool surfaces.  

- [ ] **F03-01** Implement instrumented black-box agent environments with hidden effect channels and owner-controlled canary sinks.
- [ ] **F03-02** Choose active probes using information gain with separate held-out channel families.
- [ ] **F03-03** Compare against random, breadth-first, classical active system identification and existing observability methods.
- [ ] **F03-04** Prove identifiability boundaries and return UNKNOWN for observationally equivalent worlds.
- [ ] **F03-05** Validate probe safety, cost and discoveries with an external fixture author.
- [ ] **F03-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### F04 — HorizonPatch weight-space editing

**Current implementation:** `research/weightspace/`  
**Associated work:** HP  
**Known completion blocker:** Only weight-patch API and manifests; no actual model has been edited.  

- [ ] **F04-01** Pin open-weight checkpoints, tokenizers and licenses, and reproduce a documented non-security weight edit.
- [ ] **F04-02** Collect clean/adversarial matched activation data for genuine tool-trust errors.
- [ ] **F04-03** Compare gradient-free sparse edits against random, norm-matched, LoRA, activation steering and standard fine-tuning.
- [ ] **F04-04** Test unseen prompt-injection strategies and legitimate utility with independent effect-oracle labels.
- [ ] **F04-05** Rollback on new capability failures; keep weight patches outside protected security-kernel authority.
- [ ] **F04-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### F05 — HorizonSentinel weight integrity

**Current implementation:** `research/weightspace/; horizon/weights/`  
**Associated work:** HS  
**Known completion blocker:** Proposed; no validated safety-regression detector over real checkpoints.  

- [ ] **F05-01** Define safety-critical behaviors and tests across checkpoint transitions.
- [ ] **F05-02** Compare localized weight diagnostics with full behavioral regression tests and model diffing.
- [ ] **F05-03** Test adversarial edits, quantization, merges and stealthy safety regressions on consented open models.
- [ ] **F05-04** Report coverage limits when internal cause is not identifiable.
- [ ] **F05-05** Sign checkpoint and patch provenance; make any promotion require external verification.
- [ ] **F05-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### F06 — HorizonTransfer cross-model safety patch

**Current implementation:** `research/weightspace/`  
**Associated work:** HT  
**Known completion blocker:** Speculative hypothesis; no cross-architecture evidence.  

- [ ] **F06-01** Define task and architecture equivalence criteria for transfer.
- [ ] **F06-02** Compare direct patch translation with independently discovered local patches and finetuning.
- [ ] **F06-03** Test at least two unrelated open-weight families using frozen held-out tasks.
- [ ] **F06-04** Measure negative transfer and utility regression rather than only safety scores.
- [ ] **F06-05** Publish null results and disallow transplanting patches into protected production models.
- [ ] **F06-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### F07 — HorizonReflex System 1 probe selection

**Current implementation:** `research/; horizon/research/`  
**Associated work:** HR  
**Known completion blocker:** Learned model not demonstrated; concept-only stage.  

- [ ] **F07-01** Collect agent-state/effect-graph data with independent sink labels.
- [ ] **F07-02** Build small typed decision-model baseline and graph neural model for downstream effect prediction.
- [ ] **F07-03** Use predicted uncertainty to select safe HorizonSpectra probes, never to authorize actual effects.
- [ ] **F07-04** Compare against random, heuristic, Bayesian and slower-model probe policies on held-out tools.
- [ ] **F07-05** Measure calibration, novel effect discovery per probe, p95 latency, out-of-distribution reliability and utility.
- [ ] **F07-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### F08 — Seven research novelty helpers

**Current implementation:** `research/novel/`  
**Associated work:** Novel  
**Known completion blocker:** Candidate algorithms; prior-art searches and independent comparisons incomplete.  

- [ ] **F08-01** Inventory each helper: coverage, differential kernel, negative registry, permit fuzz, race bench, sink differential and witness analysis.
- [ ] **F08-02** Give each one hypothesis, novelty falsifier, independent baseline and a bounded threat model.
- [ ] **F08-03** Demonstrate measurable gain beyond strongest directly related research, not against trivial stubs.
- [ ] **F08-04** Keep all experimental controls out of the mandatory enforcement path pending formal approval.
- [ ] **F08-05** Publish exact failure cases and retire ideas that do not show independent advantage.
- [ ] **F08-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## Workstream G — Benchmarks, paper evidence, orchestration and operations

### G01 — Synthetic SecBench and study pipelines

**Current implementation:** `bench/secbench/; bench/p9/; paper/`  
**Associated work:** P8/P9/P11  
**Known completion blocker:** Simple B3 rule ties full defense on main benchmark; post-hoc examples are not confirmatory.  

- [ ] **G01-01** Create new independently authored held-out scenarios with matched benign sensitive-data workflows.
- [ ] **G01-02** Run CaMeL, tracked capabilities and best coarse-history baselines under matched deployment assumptions.
- [ ] **G01-03** Freeze hypotheses, primary metrics, experiment scripts, seed policy and statistical analysis *before* test.
- [ ] **G01-04** Run full live-agent-and-protected-sink pipeline on held-out attacks and benign tasks.
- [ ] **G01-05** Prepare one focused, honest manuscript per independently verified central contribution.
- [ ] **G01-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### G02 — External datasets and replay studies

**Current implementation:** `bench/real/; bench/dataset/`  
**Associated work:** 2026-11-03  
**Known completion blocker:** 24 registered repos, 22 parseable; most not evaluated; replay is not causal prevention.  

- [ ] **G02-01** Validate provenance, licenses, dataset overlap and label semantics; ensure no hidden leakage into held-out test.
- [ ] **G02-02** Make offline replay metrics distinct from live attack prevention and counterfactual utility.
- [ ] **G02-03** Replace name-based effect classification with operator-reviewed actual effect contracts.
- [ ] **G02-04** Run compatible live benchmarks with independently observed outcomes; include per-suite/model robustness.
- [ ] **G02-05** Fix dataset v0 saturation with blinded external authoring, adaptive attackers and harder controls.
- [ ] **G02-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### G03 — Supervisor and autonomous development

**Current implementation:** `orchestrator/; spec/; scripts/horizon_plan.py`  
**Associated work:** P75-P86  
**Known completion blocker:** Worker/verifier not truly isolated; HMAC/fixture and dependency assumptions.  

- [ ] **G03-01** Keep worker, reviewer, signers and evaluation data under separate identities and filesystem permissions.
- [ ] **G03-02** Use clean immutable worktree or container per agent and signed, pinned tool/dependency environments.
- [ ] **G03-03** Enforce independent acceptance runner with oracle protection and exact git-commit pinning.
- [ ] **G03-04** Test worker compromise, reviewer compromise, tool-output injection, collusion and altered benchmarks.
- [ ] **G03-05** Do not allow coding agents to self-promote CANDIDATE into independent VERIFIED.
- [ ] **G03-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### G04 — Release engineering and supply chain

**Current implementation:** `horizon/ops/; .github/workflows/; replication/; sdk-ts/`  
**Associated work:** P10/P38/P55-P74  
**Known completion blocker:** No production release or independently attested protected sink.  

- [ ] **G04-01** Build versioned packages/images with SBOM, signature, verified dependency locks and pinned build environments.
- [ ] **G04-02** Resolve licenses, older proprietary component provenance and release rights before publication.
- [ ] **G04-03** Create clean-room reproducible install-and-test instructions on supported Linux variants.
- [ ] **G04-04** Add supply-chain review, secret scanning, dependency and vulnerability triage to release gates.
- [ ] **G04-05** Publish transparent supported/unsupported capability matrix and independent assessment findings.
- [ ] **G04-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

### G05 — Operations, audits and disaster recovery

**Current implementation:** `horizon/ops/; horizon/service/; docs/operations/`  
**Associated work:** P10/P55-P74  
**Known completion blocker:** Operational SLOs, key rotation, support and multi-instance reliability not proven.  

- [ ] **G05-01** Define risk taxonomy, SLOs, incident escalation and human override/kill-switch contract.
- [ ] **G05-02** Test backups, log retention, disaster recovery, key compromise, key rotation and graceful degradation.
- [ ] **G05-03** Observe real p95/p99 latency, throughput, denial rates, UNKNOWN and completeness of effect logs.
- [ ] **G05-04** Use structured redacted OpenTelemetry events without leaking prompt or secret payloads.
- [ ] **G05-05** Conduct independent security and operational readiness review prior to product claims.
- [ ] **G05-GATE** Attach frozen tests/results, evidence oracle and independent review for precisely the supported scope.

## Stage gates: hard stops before a unified platform

### Gate G0 — Repository integrity and research honesty
- [ ] All current CI checks pass at a pinned commit; failures are neither suppressed nor classified as success by omission.
- [ ] Verify the status of every task/phase from current code, not only historical status documents.
- [ ] Every active security claim has matching immutable result files, a counterexample/test oracle and a scope matrix.
- [ ] All P54 integration failures are retested under newly frozen evidence; independently resolve or explicitly limit ES-G2/ES-G3.
- [ ] Complete repository license, proprietary dependency and dataset usage provenance audit.

### Gate G1 — Trusted kernel and identity
- [ ] One normative schema for `Principal`, `AgentSession`, `CanonicalEffect`, `Authority`, `Permit`, `Outcome`, `Evidence`, `Unknown`.
- [ ] Policy rejects escalation, unexpected transport, untrusted role assertion, contradictory policy and unauthorized declassification.
- [ ] Every permit is bound to issuer, role, tenant, principal, session, target, arguments, effect, policy epoch and deadline.
- [ ] Property-based and differential tests pass for Python/Rust/TS where functionality is claimed.
- [ ] Independent formal review of bounded guarantees and explicit assumptions.

### Gate G2 — Unbypassable effect enforcement
- [ ] Actual agent can *not* directly write protected file or open protected network socket outside a separate broker/sink identity.
- [ ] Legitimate file write and unauthorized file-write attempts verified by separate sink-owned journal.
- [ ] Legitimate HTTPS send and unauthorized off-host disclosure verified by separate receiver; no raw-secret transfer to untrusted services claimed safe.
- [ ] Nonce replay, cross-process races and crash/recovery cannot permit multiple protected dispatches using one authorization.
- [ ] Uncertain effect outcomes never automatically retried without reconciliation.
- [ ] OS sandbox bypass testing and unsupported-kernel fail-closed behavior documented.

### Gate G3 — Protocol and multi-agent interoperability
- [ ] Real MCP server with end-to-end effect mediation + official conformance tests for supported version.
- [ ] Real UTCP SDK/adapter with supported transport mediation and no direct bypass.
- [ ] Code Mode executes through mandatory sandbox; actual effect receiver evidence.
- [ ] A2A/delegation test preserves all privilege, revocation and audit scope.
- [ ] One canonical effect contract produces equivalent security outcomes regardless of adapter.

### Gate G4 — Evaluation credibility
- [ ] Independent test-set authors supply unseen effect/topology/attack families.
- [ ] Benchmark separates attacks, benign controls, `UNKNOWN`, unidentifiable cases and infrastructure errors.
- [ ] Include CaMeL/tracked-capabilities/coarse historical rules/strong standard-tool baselines on equivalent tasks.
- [ ] Live agents with interceptable real tool effects, not only offline trajectory replay.
- [ ] Real attack success, benign task completion, false blocks, coverage and p95/p99 overhead; clustered statistical intervals.
- [ ] Counterexample challenge survives independent reviewer attempts; report failed claims.

### Gate G5 — Platform admission (still not commercial launch)
- [ ] Introduce a **versioned module manifest**: `name, version, contract_version, effects, dependencies, supported_platforms, signer, threat_model, evidence_digest, feature_flags`.
- [ ] Default-deny plugin installation and capability elevation; require operator-reviewed manifest and signed evidence.
- [ ] Onboard an arbitrary **supported** agent by adding an adapter and policy, not patching security-critical kernel logic.
- [ ] Demonstrate four unrelated workflows: coding, data analytics, multi-agent delegation and web/API actions; repeat against a fifth unseen workflow.
- [ ] The same trust and effect ledger governs all of them; no hidden protocol-specific permission bypass.
- [ ] Display per-agent **coverage map**: protected, blocked, observed-only, unknown, unsupported; never show an unjustified single 'safe score'.

## Acceptance-test harness to create

Proposed layout (adapt to current repo; avoid duplicating existing infrastructure):

```text
security_hardening/
  inventory.yaml                # exact module code paths, status, owner, risk, prerequisites
  contracts/                    # versioned core schemas and ABI rules
  matrices/                     # threat-model-to-effect coverage and platform support
  module_gates/                 # A01-G01 acceptance specs, independent outcome evidence
  fixtures_independent/        # reviewer-owned red-team and benign controls
  fault_injection/             # process crash, race, revocation, external unknown effects
  interop/                     # MCP, UTCP, Code Mode, A2A real protocol suites
  proof/                       # bounded invariants, counterexamples, assumptions
  benchmarks/                  # frozen split, baselines, power/latency/utility
  attestations/                # externally signed scope-specific review receipts
  reports/                     # generated check status; never manually declare VERIFIED
```

Per-module completion artifact schema:

```yaml
id: E02
name: Effect ledger
head_commit: <exact-sha>
status: CANDIDATE
threat_model: <file-with-hash>
supported_scope: [single-host-linux]
unsupported_scope: [multi-host-failover]
security_invariants: [single-consumption, bounded-unknown]
acceptance_commands: [<exact-command>]
attacker_fixtures: [<independent-case-hash>]
benign_fixtures: [<independent-case-hash>]
receiver_oracle: <independent-evidence-root>
measured_metrics: <immutable-results-file>
negative_findings: [<issue-link>]
reviewer_identity: null
independent_attestation: null
```

## Codex execution contract (copy as agent instructions)

1. Read this document, `docs/implementation/STATUS.md`, the current version of `docs/implementation/P55_P94_STATUS.md`, `docs/research/RESEARCH_PROGRAM_STATUS.md`, the master spec and actual source. Reconcile any outdated claims before changing code.
2. Generate `security_hardening/inventory.yaml` with all modules in this document, current commit, actual source/test files, a named failure mode and a bounded assurance claim. Do not invent completion percentages.
3. Choose the earliest dependency-unblocked task. Work in a scoped pull request with the task ID. **Do not** modify unrelated source to improve headline scores.
4. Implement one necessary mechanism or test; add an independently checkable attack/benign pair and negative tests. Use *real* effects wherever claimed and synthetic markers only on owned test sinks.
5. Run unit, integration, fuzz/property/mutation and cross-language checks appropriate to the claim. Attach command output, immutable result digest, test denominators and known negatives.
6. Update the trust/sink coverage map and previous baseline. Do not use LLM-generated safety judgments as ground truth.
7. Preserve signatures, reviewer keys, protected acceptance scripts and immutable baselines outside untrusted worker authority. If not possible, mark `BLOCKED`.
8. Never conflate `no observed violation` with `proved safe`; never replace `UNKNOWN` with `ALLOW`; never infer that a green CI run equals independent verification.
9. Stop when the task needs owner permission, real compute/model provider, independently authored data, legal review, or external security reviewer. File a clear unblock request; do not forge evidence.
10. Research proposals (Zero/Forge/Spectra/Patch/Reflex/Transfer/Sentinel) stay in isolated experimental paths. Promote to mandatory enforcement only through kernel and module gates.
11. After each merged PR, regenerate machine-readable status, report failed/blocked/unmapped tasks and the next five dependencies. Maintain test reproducibility on clean checkout.
12. Do not add platform branding, billing, customer features or a universal 'secure any agent' claim until **G0–G5** have evidence.

## Review cadence and scorecard

For each module track: `API completeness`, `invariant tested`, `live integration`, `adversarial coverage`, `independent outcome evidence`, `performance measured`, `formally reviewed`, `negative findings triaged`, `independent sign-off`. Score each dimension `0=none`, `1=partial`, `2=complete for scoped contract`; *do not average away a failed mandatory sink boundary*. A module may show 17/18 checklist items done but remain BLOCKED if mandatory mediation is missing.

Each PR review asks: (a) What unauthorized effect could still happen? (b) Which external observer would prove it? (c) How could this test be gamed? (d) What legitimate tasks did we break? (e) What remains UNKNOWN? (f) Did the verified scope expand? 

## Critical known blockers and independent reviewer questions

- **HorizonReach first-call confidentiality**: independently attested dishonest services remain dangerous when receiving raw protected data. Rejection, data minimization or trustworthy local execution may be necessary; signed receipts cannot undo disclosure.
- **Oracle completeness**: if all observers omit the same event, PASS may be unsound; add active instrumentation/coverage challenges and declare missing sinks UNKNOWN.
- **Coarse-rule performance parity**: main paper has no decisive win over read-then-send rule on its original scenarios; do not declare superiority until independently tested.
- **Synthetic-to-real validity**: P39–P53 mostly scripted or toy tests; transfer to live LLM agents must be measured directly.
- **Cryptographic authority**: do not confuse test fixture signers with real approval authorities; external reviewer must inspect role boundaries.
- **Weight-space safety**: no edit of a real open-weight model has been demonstrated; stochastic model behavior can never replace mandatory effect authorization.
- **Deployment scope**: Linux test VM does not establish universal OS support; use an explicit support matrix.

## References inside the repository

- https://github.com/crakashp2905-hub/MCPHorizon/blob/main/docs/implementation/STATUS.md
- https://github.com/crakashp2905-hub/MCPHorizon/blob/main/docs/implementation/P55_P94_STATUS.md
- https://github.com/crakashp2905-hub/MCPHorizon/blob/main/docs/research/RESEARCH_PROGRAM_STATUS.md
- https://github.com/crakashp2905-hub/MCPHorizon/blob/main/docs/evidence/p54/RESULTS.md
- https://github.com/crakashp2905-hub/MCPHorizon/blob/main/docs/implementation/PRODUCT_BLOCKERS.md
- https://github.com/crakashp2905-hub/MCPHorizon/blob/main/paper/MANUSCRIPT.md
- https://github.com/crakashp2905-hub/MCPHorizon/blob/main/docs/evidence/real/ASSUMPTIONS_AND_LIMITS.md
- https://github.com/crakashp2905-hub/MCPHorizon/actions

**Bottom line:** The right way to build a platform that can accept a supported agent and secure its downstream activity is to *finish, bind and independently test* the existing enforcement and assurance modules first. The platform is a consumer of those verified contracts, not a shortcut around them.
