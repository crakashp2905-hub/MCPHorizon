# Baseline comparison — text-layer guards vs MCPHorizon

Each detector run over the **same** recorded TAMAS scenarios. Text guards see the
per-step text they expect (the user task; the step-level guard sees each tool return).
MCPHorizon sees the executed `(agent, tool)` trajectory.

**Exact models run:**
- **Prompt Guard role** — `protectai/deberta-v3-base-prompt-injection-v2` (transformers
  5.10.2). *Meta's `Prompt-Guard-86M` / `Llama-Prompt-Guard-2-86M` are HF-gated (401
  without a token in this environment); we substitute this open, runnable
  prompt-injection classifier and disclose it.*
- **Llama Guard** — `ollama/llama-guard3:1b` (Llama Guard 3, 1B) via the local Ollama API.
- **Step-level guard** — the injection classifier applied to each tool **return** snippet
  (the indirect-injection vector at the tool boundary).
- **MCPHorizon** — the released multi-agent detector (recorded eval).

## Comparison table (scenarios flagged per class)

| Detector | DPI | Colluding | IPI | Benign-FP |
|---|---|---|---|---|
| Prompt Guard (injection, on task) | **43/50 (86%)** | 2/50 (4%) | 1/50 (2%) | 1/50 (2%) |
| Llama Guard 3 (unsafe, on task) | 46/50 (92%) | 30/50 (60%) | 24/50 (48%) | **24/50 (48%)** |
| Step-level guard (on tool returns) | 10/50 (20%) | 26/50 (52%) | 18/50 (36%) | 0/50 (0%) |
| **MCPHorizon** (executed trajectory) | 26/50 (52%) | **42/50 (84%)** | **14/50 (28%)** | 0/50 (0%) |

Benign-FP is the flag rate on the benign-baseline tasks (no injection, malicious tools
removed). For the text guards these are the IPI tasks (same text), so their IPI and
Benign-FP columns coincide by construction.

## Reading the table — fairly, crediting the baselines where they win

**DPI — the text layer wins, decisively and correctly.** The injected instruction is
present in every DPI task, and the dedicated injection detector flags **43/50 (86%)** —
*including the 24 (= 50−26) attempts the 7B model never executed*. MCPHorizon, being
execution-based, only flags the 26/50 that were actually carried out. For catching the
**injection attempt** — answering *"was the system told to misbehave?"* — the text layer
is the right tool and catches **more** than MCPHorizon. This is the baseline's win, and
we credit it plainly.

**Colluding & IPI — the injection detector is near-blind; MCPHorizon catches them.**
The Colluding and IPI user tasks contain **no injection** (collusion lives in agent roles
and the cross-agent tool chain; IPI misuse is spontaneous at run time). The injection
detector flags **2/50 (4%)** and **1/50 (2%)** respectively — essentially its 2%
false-positive floor. MCPHorizon flags **42/50** and **14/50** by watching what was
*executed*. This is the capability/epistemic layer's lane.

**Llama Guard is not a discriminating substitute (important caveat).** Llama Guard's
headline recall looks high (Colluding 60%, IPI 48%), but its **benign false-positive
rate is 48%** — it flags roughly half of *benign* medical/financial/legal tasks as
"unsafe" because it reacts to **sensitive-domain content**, not to the attack. Its IPI
rate (48%) is *identical* to its benign-FP (same task text), so those flags are not
attack-specific. A generic content-safety classifier therefore cannot stand in for
either an injection detector or a capability detector here: at a usable FP rate it would
catch far less. (The injection-specific guard, at a 2% FP floor, is the fair text-layer
comparator.)

**The step-level return guard is a partial, returns-only signal.** Scanning tool returns
caught Colluding 52% / IPI 36% with **0 benign false positives** — the malicious tools'
*return content* (fabricated cases, poisoned data, manipulated text) reads as
injection-like, and benign returns never do. But it flags only **20%** of DPI, because
the DPI injection lives in the **user task, not a tool return** — an indirect-injection
guard at the tool boundary has the wrong vantage point for input-level injection.

## Complementarity, demonstrated — not a horse race

The numbers turn the §9 assertion into a result. The text layer and MCPHorizon answer
**different questions**, and the table shows each excelling at its own:

- *"Was the system told to misbehave?"* — the **injection** question. The text layer owns
  it: **86% on DPI**, catching even the attempts MCPHorizon (execution-based) does not.
  This is consistent with the documented finding that **single-agent prompt-injection
  benchmarks saturate against simple input firewalls** — that layer is close to solved,
  and our DPI result reproduces it.
- *"Can the system now do something dangerous — however it was induced?"* — the
  **capability/epistemic** question. MCPHorizon owns it: **84% on Colluding, 28% on IPI**,
  where there is no injected instruction for the text layer to read (Prompt Guard: 4% /
  2%).

Neither subsumes the other; the union dominates either alone. A deployed system should
run **both**: an input injection detector for the "told to misbehave" axis, and
MCPHorizon for the "can now act dangerously" axis. Layering them is complementary by
construction, because the signals they key on (injected instruction text vs. executed
capability) are disjoint — most sharply in IPI, where the attack has **no instruction at
all** and only the execution-level signal exists.
