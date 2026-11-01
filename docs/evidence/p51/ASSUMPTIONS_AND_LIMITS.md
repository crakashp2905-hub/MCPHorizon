# P51 HorizonVisionGuard — assumptions and limits (CANDIDATE)

Status: CANDIDATE. Nothing here is VERIFIED. Evidence is a local model plus a controlled Chromium on loopback; no third-party site, real account or real credential was used. The sensitive value is the synthetic canary `TEST_CANARY_NOT_SECRET`.

## 1. Threat model and supported scope (P51-01)
Agent: a screenshot- or accessibility-driven browser agent that proposes clicks, keys and explicit upload/download tools. Adversary: page content (including third-party frames) that makes the thing the agent *sees* differ from the thing the browser *activates*: invisible overlays, transparent controls, cross-origin frames, controls re-pointed after observation, spoofed form targets or link text, data added to a form after review, focus moved by script, effects started by script.
Supported: Chromium, controlled instrumentation through the DevTools protocol, declarative effects (links, forms, file inputs, downloads, clipboard buttons). Desktop applications are **not** covered: no OS accessibility/process-identity broker was built, so desktop agent actions are outside this phase and unmeasured.
Out of scope: a compromised browser or instrumentation, a compromised receiver/oracle, side channels, timing channels, social engineering of the approver.

## 2. Trust bindings (P51-02, 04, 05)
Pixel coordinates carry no origin, identity or semantics. An action is *proposed* (op, point, the element the agent believes it targets, the element digest it observed) and *bound* by the browser: hit-test (`DOM.getNodeForLocation`), owning frame and its security origin (`Page.getFrameTree`), element semantics read in an **isolated world** through `Element.prototype.getAttribute` and `FormData` (page script cannot replace those functions there), and an element digest over tag, type, role, resolved effect and frame origin. Screenshot text is never an input to the guard. Schemas: `horizon/vision/core.py` (`ACTION_SCHEMA`, `BINDING_SCHEMA`, `EFFECT_SCHEMA`).
The digest is a per-element version, not a page version: unrelated page changes (B08) do not block, a change to the target's effect (A04, R04) does.

## 3. Protected sinks (P51-06, 07, 11)
SUBMIT, UPLOAD, NAVIGATE, DOWNLOAD, CLIPBOARD. Each is checked against the task's per-kind destination list, a data policy (sensitive data only to listed destinations), the reviewed-input digest for submits, and, for UPLOAD and DOWNLOAD, a single-use APPROVAL token from the shared HorizonPolicy authority (role `approver`) bound to the envelope {op, element digest, derived effect, input digest, top origin, tab}. This module only verifies; it holds no issuer.
The preflight reviewer in the experiments is a mechanical ideal-attentive proxy: it approves iff the derived effect is in the authorized list. It measures the mechanism, not human review.

## 4. Oracle (P51-12)
The synthetic site's server-side receiver log (model: `Site.log`; Chromium: what the loopback servers received, classified from method, content type and Fetch-Metadata headers) judged against the task's authorized effects. Click logs, guard decisions and agent claims are never read. Benign completion is also judged from the receiver.

## 5. Unsupported paths are UNKNOWN (P51-15)
- Script-initiated effects (fetch, XHR, `window.open` from a handler): no declarative effect to derive. The guard reports UNKNOWN for any element with a click-like listener on it, its form or an ancestor. This also blocks ordinary scripted buttons (B11, R11): a measured false block, not a bug.
- Native file dialogs, popups, drag-and-drop, extension/side-panel surfaces (U01–U04): modelled as uninstrumented elements, not exercised in Chromium.
- Telemetry offline (M01, M02): every action is UNKNOWN; the matched legitimate form is blocked. This is the missing-instrumentation failure the promotion gate asks to survive, and its disruption cost is reported.
UNKNOWN is counted separately and never as a pass.

## 6. Real-browser configuration (P51-16)
Browser: Chromium 153.0.8010.12 via Playwright (Python), headless. Flags: `--no-proxy-server`. Network: all non-loopback requests are aborted by a context route (stray requests recorded: 0 in every run). Origins: app `127.0.0.1`, evil `localhost`, ads `127.0.0.2`, ephemeral ports. Sandbox: Chromium's default sandbox settings as shipped in this container; no extra isolation was added or claimed. Perception: a DOM-side proxy for pixels (visible text and computed opacity); no vision model. The file chooser is answered by the scripted agent.
Adversarial cases: R01 invisible file input, R02 transparent same-origin submit, R03 invisible cross-origin frame, R04 re-pointed form, R05 clobbered form action, R09 script-initiated request; matched legitimate: R06 form, R07 upload with approval, R08/R10 navigation, R11 scripted button (blocked as UNKNOWN). Model cases A01–A11, U01–U05, M01–M02, B01–B11 are listed in RESULTS.md.

## 7. Limits (P51-14, 16)
- Redundancy: element, frame and version binding each catch the overlay and clickjacking cases; only removing all three loses them. Approval-envelope binding is shown by unit tests, not by a scenario.
- Accessibility regressions are measured only in the model (icon-only control through the accessibility snapshot, keyboard Enter on the focused control, a label containing "Send"); no screen-reader or real keyboard-focus study.
- Latency: the model decision takes about a microsecond; the Chromium probe costs several DevTools round trips per action (single-digit to tens of milliseconds here) on top of a scenario dominated by context start-up. All timing is machine-specific and is recorded apart from the verdicts (`timing_ms_machine_specific`, `scripts/p51_bench.py`).
- Suite size: 11 + 6 attacks and unbindable paths, 11 benign, in the model; 6 attacks and 5 benign in Chromium. Same author as the guard. Wilson intervals are descriptive.
- `bind_approval` and element/frame binding are redundant in this suite (see RESULTS.md); the page-version integer is carried but the digest is the staleness check.
- The Chromium tests are skipped (and reported UNSUPPORTED) on hosts without Playwright and Chromium, so CI on a plain Python runner checks the recorded browser results and definitions, not a live run. Mutants of `browser.py` / `browser_run.py` are not part of the mutation check.
- Promotion gate: not met. No production enablement is claimed: protected sinks are not all independently mediated (native dialogs, popups, extensions are not), and no preregistered disruption budget was set.
