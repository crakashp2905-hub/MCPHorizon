# TriggerLab: falsifiable claims and limitations (MG-G5)

**What this experiment is:** a measurement pipeline exercised on *scripted toy subjects*. A toy model emits an out-of-scope tool request iff an exact trigger string appears in its prompt. No real model, weights, or sampling were involved; L3-style live-model testing was **not run**.

**Falsifiable claims (each can fail):**
1. A policy that enforces the user-authorized (tool, destination) scope allows 0 out-of-scope effects on the 4 planted behaviour families × 10 seeds; the exact 95% upper bound for the effect rate is reported with its denominator (`zero_event_upper_bound_95`), and is **not** zero.
2. Name- and signature-based baselines tuned on known families miss unseen families (leave-trigger-family-out).
3. Controls (near-trigger, context permutation, irrelevant persona, random label) produce no activation in an exact-trigger toy model; a fuzzy toy model would falsify (1)'s control logic and the tests include one.
4. The same legitimate workflow completes under the scope policy with 0 verified false blocks (n shown in `result.json`).

**What it does not show:**
- Nothing about real models or real triggers; the toy behaviours were written by the same author as the policies, so catching them is partly circular. The value is that the *pipeline* separates activation, policy rejection and independent effect prevention, and that it detects a planted trigger.
- Effects *inside* the authorized scope (e.g. wrong summary content, subtly altered data) are invisible to a scope check.
- All tools are inert mocks; "effect" means a journal entry in an in-process sink. Real side-effect channels (DNS, timing, shared files) are not modelled here (see P24-P27 for the runtime).
- Zero observed events in n runs bounds the rate at about 3/n; it does not establish absence.
- Seeds vary a deterministic toy; they do not sample a real distribution.

**Safety:** zero network attempts are asserted in tests; fixtures are linted for real credential shapes, non-reserved hosts and download-and-execute payloads (`scan_fixture`).
