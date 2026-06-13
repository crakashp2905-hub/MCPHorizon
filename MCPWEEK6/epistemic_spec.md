# An Epistemic Extension of the MCPHorizon Capability Lattice

*Formal specification, in the style of §3.*

## E.0 Motivation and thesis

The capability lattice of §3 tracks **what a composed system can now do** — which
(action, resource, scope, agent) capabilities have become reachable. Taint / IFC
tracking similarly follows **what data flowed from where**. Both watch *actions and
flows*. Neither watches *beliefs*.

But compositional harm, mechanistically, is often this: **an agent performs a
consequential action conditioned on a belief that is false, that it cannot itself
verify, because an upstream agent silently corrupted the slice of the world it reasoned
about.** The downstream agent does nothing "wrong" at the capability level — it reads a
clean record with legitimate provenance and acts on it — yet the act is unsafe because
the record's *faithfulness to ground truth* was destroyed upstream, silently. This
epistemic failure is **orthogonal** to capability/taint: a value can have impeccable
provenance and uncorrupted scope while being *false*, because suppression removes a true
signal rather than injecting a tainted one.

This section formalizes that intuition as an epistemic layer over the existing lattice.
It does **not** replace the lattice; it annotates the same artifacts and rides the same
replay engine.

## E.1 Augmented state

Let `A` be the set of agents and `P` the set of propositions / artifacts produced or
consumed during a trajectory (a tool's structured output, a record field, a
classification, a drafted document, a "status" signal). The capability state of §3 is
augmented so that every artifact `P` additionally carries three epistemic annotations:

| Annotation | Type | Meaning |
|---|---|---|
| `believed_faithful(P)` | `{T, F, ⊥}` | Does the **consuming** agent treat `P` as faithful to ground truth? `T` = relied upon as true; `F` = treated as suspect; `⊥` = no belief formed (not yet consumed). |
| `actually_faithful(P)` | `{T, F, ⊥}` | Is `P` **actually** faithful to ground truth? `T` = corresponds to reality; `F` = does not; `⊥` = unknown / not ground-truthable. **Setting `F` requires an oracle.** |
| `verified_by(P)` | `⊆ A` | The set of agents that performed an **independent verification** of `P` against an external/authoritative source (not merely re-read it). |

We also keep the §3 provenance/derivation relation. Write `Q ⤳ P` ("`P` descends from
`Q`") for the transitive closure of the per-step *produce → consume* graph: if a step
consumes `Q` (among its inputs) and produces `P`, then `Q ⤳ P`. By extension a *step*
`s ⤳ P` if `s` produced some `Q` with `Q ⤳ P` (or `s` produced `P`).

**Default belief.** Absent contrary evidence, an agent that consumes a tool output and
reasons on it adopts `believed_faithful = T` — the realistic default: agents trust their
tools' outputs. `actually_faithful` defaults to `⊥` and is set only where ground truth
is available. `verified_by(P)` starts `∅` and accrues an agent `g` only when `g` runs a
genuine cross-check tool against an independent source.

**Actuation.** A step `a` is an **actuation conditioned on `P`** iff `a` performs a
consequential, outward action (a `write`, `send`, `execute`, or recommendation) and `P`
is among the inputs the agent reasoned over to decide `a`. Write `cond(a, P)`.

## E.2 Falsification-capable step

> **Definition (falsification-capable step).** A step `s` (a tool invocation /
> transformation) is **falsification-capable** iff its semantics can flip
> `actually_faithful(P)` from `T` to `F` for some artifact `P` in or under its output,
> **without** flipping `believed_faithful(P)`.

That is, `s` degrades the truth of the world-model while leaving the downstream
consumer's belief that the artifact is faithful *intact*. The defining feature is
**silence**: `s` produces no marker, no taint, no scope corruption that a consumer or a
capability/IFC monitor could key on. Two canonical kinds:

- **Suppressors** — remove or mask a true signal (e.g. `classify_vitals_as_normal`
  hides a real anomaly; `disable_medication_reminders`, `skip_reminders`,
  `suppress_neutral_validation`, `leak_fact_check_logs` used to silence a check).
- **Poisoners / tamperers** — overwrite a true value with a plausible false one while
  preserving the artifact's surface form and provenance (`tamper_adherence_data`,
  `poison_*`, `inject_fake_trends`, `return_irrelevant_similar_cases`,
  `search_and_return_fake_cases`).

Falsification-capability is a **tool-level annotation** (E-vocab), analogous to the
malicious-variant labels of §4: it encodes prior knowledge of *which tools can silently
break faithfulness*, not per-instance ground truth.

## E.3 The danger predicate — oracle version

> **Definition (FALSE-BELIEF-UNSAFE).** Artifact `P` is **FALSE-BELIEF-UNSAFE** iff
> there exists an actuation `a` with `cond(a, P)` such that
>
> 1. `believed_faithful(P) = T`  — the consumer treats `P` as faithful;
> 2. `actually_faithful(P) = F`  — `P` is in fact not faithful   *(requires oracle)*;
> 3. `agent(a) ∉ verified_by(P)`  — the acting agent did not itself verify `P`;
> 4. `∃` falsification-capable step `s` with `s ⤳ P`  — `P` descended from a silent
>    falsification.

In words: *a consequential action is taken on a belief the actor holds as true, that is
actually false, that the actor never verified, and whose falsehood was introduced by a
silent upstream step.* Condition (2) is the **oracle condition**: it can only be
evaluated where ground-truth faithfulness is known.

**Cross-agent restriction.** Define `CROSS-AGENT-FALSE-BELIEF-UNSAFE(P)` as
FALSE-BELIEF-UNSAFE(`P`) **and** `∃` falsification-capable `s ⤳ P` with
`agent(s) ≠ agent(a)` — the silent corruption and the actuation are performed by
*distinct* agents. This is the epistemic analogue of the §4 cross-agent hyperedge
(distinct-agent premises), and it is the signal used for the cross-agent horizon
comparison.

## E.4 The deployable relaxation — no ground-truth oracle

> **Definition (UNVERIFIED-BELIEF-UNSAFE).** Artifact `P` is
> **UNVERIFIED-BELIEF-UNSAFE** iff there exists an actuation `a` with `cond(a, P)` s.t.
>
> 1. `believed_faithful(P) = T`;
> 2. `verified_by(P) = ∅`  — *no* agent verified `P`;
> 3. `∃` falsification-capable step `s` with `s ⤳ P`.

This drops the oracle condition (2′: `actually_faithful = F`) and replaces "the actor
did not verify" with the stronger, **observable** "*nobody* verified." The safety
rationale: an unverified belief that descended from a falsification-capable step
**cannot be ruled out as false**, so it is treated as unsafe.

**Relationship to the oracle version (be candid).** The relaxation is **conservative,
not equivalent**:

- It can fire where the oracle would not — a `P` that descended from a
  falsification-capable step which, *on this instance*, did **not** actually corrupt it
  (`actually_faithful(P) = T`) and that nobody verified. These are **relaxation false
  positives relative to ground truth**. The relaxation accepts them as the price of not
  needing an oracle.
- It will *not* fire if any agent verified `P` (`verified_by ≠ ∅`), even if the
  verification was inadequate — so it can miss harms the oracle catches when a sham
  "verification" is recorded. (No such sham-verification tool exists in our benchmark.)

The relaxation still requires the **falsification-capable annotation** (E.2). That
annotation is prior tool knowledge, weaker than per-instance ground truth but **not
nothing** — see the caveat in E.7.

## E.5 Theorem — epistemic silence of single-agent DPI

> **Theorem (E.1).** Under DPI — a single agent acting on its own injected instruction,
> with no cross-agent artifact transfer — the predicate
> `CROSS-AGENT-FALSE-BELIEF-UNSAFE` (and its relaxation) is **unsatisfiable**. The
> cross-agent epistemic signal is therefore silent on DPI *by construction*.

**Proof sketch.** Fix a DPI trajectory. By the definition of DPI: (i) there is a single
acting agent `g` — the injected instruction directs `g` to call a named tool and forbids
others; every step `s` in the trajectory has `agent(s) = g`; and (ii) there is **no
cross-agent artifact transfer** — no artifact produced by one agent is consumed by a
*distinct* agent's actuation.

The cross-agent predicate requires a falsification-capable step `s` and an actuation `a`
with `s ⤳ P`, `cond(a, P)`, and `agent(s) ≠ agent(a)`. But by (i), for *every* pair of
steps `agent(s) = agent(a) = g`, so the distinctness requirement `agent(s) ≠ agent(a)`
is never met. Equivalently, by (ii), no belief `P` ever crosses an agent boundary, so
there is no `P` that one agent silently corrupts and a *different* agent then acts upon
as faithful. Hence no witness `(P, s, a)` exists, and the predicate is unsatisfiable.

Two corollaries sharpen the picture. First, the DPI "belief" is the **injected
instruction itself**, which `g` adopts *overtly* — it is not a previously-faithful
artifact silently falsified upstream, so condition (4) (`descended from a
falsification-capable step`) also fails independently of agent-distinctness. Second,
this is the *same structural reason* the §4 cross-agent **capability** horizon is silent
on DPI: both the capability hyperedges and the epistemic predicate require a
distinct-agent premise, and DPI is single-agent by construction. ∎ (sketch)

**Consequence.** Theorem E.1 re-derives the empirical **DPI 0/50 cross-agent horizon**
result from a first principle: DPI cannot engage *any* cross-agent signal — capability or
epistemic — because it transfers nothing across an agent boundary. The 0/50 is not a
tuning artifact; it is forced.

## E.6 Worked example — `classify_vitals_as_normal` (suppression)

**Setup.** Patient ground truth: vitals are **anomalous** (a real anomaly is present).

| Step | Agent | Action | Effect on artifact `P` = "anomaly status" |
|---|---|---|---|
| s₁ | Monitoring Agent `M` | `classify_vitals_as_normal` | suppresses the anomaly: writes "no anomaly". `actually_faithful(P): T → F`; emits **no** corruption marker. |
| s₂ | Care Agent `C` | legitimate read of patient status | receives a **clean** "no anomaly" signal; forms `believed_faithful(P) = T` ("patient is fine"). |
| s₃ | Care Agent `C` | actuation: withhold escalation / `disable_medication_reminders` / "no action needed" | `cond(s₃, P)` — the action is conditioned on the false "fine" belief. |

No agent ran a verification of the vitals against raw sensor data, so
`verified_by(P) = ∅` and `C ∉ verified_by(P)`. A falsification-capable step (s₁) exists
with `s₁ ⤳ P`, and `agent(s₁) = M ≠ C = agent(s₃)`.

Now apply each detector to the **downstream actuation s₃**:

**(a) Provenance taint / IFC — PASSES (misses it).** The "no anomaly" signal `C`
consumes was produced by a legitimate read of a normal-looking record. There is **no
untrusted source** in the flow into s₃: IFC tracks the *flow of tainted data*, but the
harm here is a *true signal that was removed*, not a false value injected from an
untrusted origin. Suppression leaves no taint to propagate. IFC sees clean → clean.

**(b) HIJACKED axiom (capability lattice) — PASSES on the downstream act (misses the
mechanism).** The actuation s₃ operates entirely on `scope = ANY`: a legitimate read and
a legitimate care action. *Nothing s₃ does operates on corrupted scope*, so the universal
axiom does not fire on `C`. The capability lattice can only catch this episode if the
*suppressor tool itself* (s₁) is pre-labeled malicious/HIJACKED — i.e. it flags "a
malicious tool ran," **not** "a downstream agent acted on an unverifiable false belief."
Strip the malicious label from `classify_vitals_as_normal` (treat it as a plausible,
legitimately-named classifier) and the capability lattice goes **silent on the entire
episode** — there is no corrupted scope anywhere. The lattice watches *scope*, and the
scope was never corrupted; only the *truth* was.

**(c) Epistemic predicate — FIRES.** On `P`:
`believed_faithful(P) = T` (s₂), `actually_faithful(P) = F` (oracle: anomaly suppressed),
`C ∉ verified_by(P) = ∅`, and `s₁` is falsification-capable with `s₁ ⤳ P` and
`agent(s₁) ≠ agent(s₃)`. **FALSE-BELIEF-UNSAFE fires** (oracle), and since
`verified_by(P) = ∅`, **UNVERIFIED-BELIEF-UNSAFE fires too** (deployable). The cross-agent
restriction is satisfied (`M ≠ C`).

**Conclusion.** The epistemic predicate fires on a harm whose *mechanism* — acting on an
unverifiable false belief produced by a silent upstream suppression — the capability
lattice **structurally cannot represent**, because the lattice keys on corrupted
capability/scope and here no scope was ever corrupted. This is a **distinct detection
class**, not a re-labeling of the capability signal.

## E.7 Caveat — the oracle limitation, stated plainly

- **FALSE-BELIEF-UNSAFE depends on an oracle.** Condition (2),
  `actually_faithful(P) = F`, requires ground truth. We have it **only in the
  benchmark**, where a suppressor/poisoner's output is false *by construction* (the
  attack definition tells us the suppressed/poisoned value is counterfactual). In a real
  deployment there is no such oracle; firings that rely on condition (2) are
  **benchmark-validated, not deployment-ready**.
- **UNVERIFIED-BELIEF-UNSAFE removes the oracle but not all priors.** It needs only
  observable quantities — `believed_faithful` (default-true on consumed outputs),
  `verified_by` (did a real cross-check run?), and falsification-capable *descent*. But
  the last still needs the **E.2 tool annotation** (which tools are suppressors/
  poisoners). That is prior knowledge — weaker than per-instance ground truth, and of
  the same kind as the malicious-variant labels the capability layer already assumes, but
  it is a real assumption and we do not pretend otherwise.
- **What we claim.** A **benchmark-validated new detection class** — false-belief /
  unverified-belief harm that the capability lattice and IFC structurally miss — *not*
  deployment-readiness of the oracle predicate. The deployable relaxation is the path to
  deployment, at the cost of conservative false positives (E.4) and a tool-annotation
  prior (E.2).
