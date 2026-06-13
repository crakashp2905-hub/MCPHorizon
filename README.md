# MCPHorizon

**A formal capability-safety framework for Model Context Protocol (MCP) security.**

MCPHorizon studies how adversaries exploit the tool-description channel to inject malicious instructions into LLM agents — without touching the user's prompt. It provides a unified theory, three empirical evaluation frameworks, and a dataset of 300+ real attack instances across 20 LLMs.

---

## What's inside

| Component | Description |
|---|---|
| **MCPTox** | 300+ poisoned MCP tool definitions tested against 20 LLMs, with full response data and a Jupyter analysis notebook |
| **TAMAS** | Multi-agent attack framework — 6 attack types × 5 domains, evaluated on AutoGen and CrewAI |
| **MCPSecBench** | Standardized 8-class MCP security benchmark |
| **Capability lattice** | Formal `(action, resource, scope)` lattice with hyperedge closure engine and Datalog compilation |
| **ML predictor** | PyTorch trajectory predictor; P(DH) = 0.998 on IPI, 100% on MCPSecBench |

---

## Repository Structure

```
MCPHorizon/
│
├── MCPTox/                         # Poisoned-tool dataset & LLM evaluation
│   ├── def_tool/                   # 300+ poisoned MCP tool definitions (.py)
│   ├── pure_tool.json              # Structured metadata for every tool
│   ├── response_all.json           # LLM responses across 20 models
│   └── analysis.ipynb              # Attack success-rate analysis notebook
│
├── data/                           # Raw poisoned tool definitions (source)
│
├── MCPSecBench/                    # Standardized MCP security benchmark
│   └── data.json                   # 8-class attack prompts & evaluation criteria
│
├── TAMAS/                          # Multi-agent evaluation framework
│   ├── Tools/Autogen/              # Tool definitions for AutoGen agents
│   ├── Tools/CREWAI/               # Tool definitions for CrewAI agents
│   └── EVAL/                       # LLM-as-judge evaluation scripts
│
├── MCPWEEK5/                       # Research reports and formal result artifacts
│   ├── *.json                      # Equivalence, predictor, trajectory results
│   └── *.md                        # Weekly research reports
│
├── MCPWEEK6/                       # Multi-agent evaluation results
│   ├── *.json / *.md               # Ablation, colluding, multimodel results
│   └── logs/                       # Live CrewAI evaluation traces
│
├── results/                        # Canonical experiment outputs
│
├── attacks.json                    # Attack trajectory database
├── hypergraph.json                 # Hyperedge set (capability implication rules)
└── capability_vocab.json           # Full capability vocabulary
```

> **Note on implementation:** The capability lattice engine, Datalog compiler, ML predictor, and LLM hyperedge proposer are proprietary and not included in this public release. All datasets, benchmarks, result artifacts, and evaluation scripts are fully available. See [USAGE.md](USAGE.md) for details.

---

## Key Results

### MCPTox — LLM Susceptibility to Poisoned Tools

300+ poisoned tools tested across 20 LLMs using three injection formats (`<IMPORTANT>`, `Ignore previous`, plain-text):

| Model | Attack Success Rate |
|---|---|
| o1-mini | **72.8%** |
| DeepSeek-R1 | **70.9%** |
| Phi-4 (Think) | **70.3%** |
| gpt-4o-mini | 61.8% |
| gemini-2.5-flash | 59.7% |
| qwen3-32b (Think) | 58.5% |
| DeepSeek-v3 | 56.5% |
| claude-3-7-sonnet | 34.3% |
| Llama-3.1-70B | 24.6% |
| gemma-2-9b | 14.5% |

> **Finding:** Reasoning-mode (Think) models are significantly more susceptible than their no-think counterparts — a counter-intuitive result with direct implications for LLM deployment safety.

### Capability Safety — Core Theorem

**Theorem (Capability Safety Reduces to Polynomial Datalog):**
> The closure of a capability state under a finite hyperedge set H over a finite parametric lattice Σ is computable in O(|H|·|Σ|^k) time, where k is the maximum hyperedge premise arity.

Verified constructively: **218/218 trajectories (100%)** agree between the Python engine and the compiled Datalog engine (MCPTox: 205, MCPSecBench: 13).

### ML Trajectory Predictor

| Evaluation | Score |
|---|---|
| IPI — in-distribution | P(DH) = **0.998** |
| MCPSecBench — out-of-distribution | **100%** combined |

### TAMAS — Live Multi-Agent Evaluation

Evaluated on TAMAS Colluding/legal (CrewAI + Ollama qwen2.5:7b, 10 scenarios, CPU-only):

| Metric | Result |
|---|---|
| Attack-conditional detection | **6/6 (100%)** |
| False positive rate on benign runs | **0/4 (0%)** |
| Mean alert step | 3.3 of 6.7 total steps |

The 4 non-detections were LLM compliance failures — the model chose not to execute the colluding behavior — not detector misses.

---

## Formal Framework

### Capability Lattice

A **capability** is a triple `(action, resource, scope)`:

```
Actions (8 atoms):  read | write | list | execute | send | recv | modify | delete

Resource hierarchy (DAG — child ⊑ parent):
  ssh_keys ⊑ credentials ⊑ user_files ⊑ filesystem ⊑ ANY
  env_vars ⊑ runtime ⊑ ANY
  external_network ⊑ network ⊑ ANY

Scope:  path_glob("~/.ssh/*") | regex(".*\.pem") | literal("value") | _any
```

`c1 ⊑ c2` iff same action, `c1.resource` descends from `c2.resource`, and `c1.scope ⊆ c2.scope`.

### Hyperedge Closure

Hyperedges encode security implications. The engine closes over them until a fixed point, checking whether any **Danger Horizon** capability is reached:

```datalog
// credential read + network send → exfiltration
derived_cap("send", "DERIVED", "literal_credential_exfiltration")
  :- cap_subsumed("read", "credentials", "_any"),
     cap_subsumed("send", "external_network", "_any").
```

The Soufflé program will be released alongside the formal publication.

### HIJACKED Scope

Any capability produced by an attacker-controlled argument is tagged `SCOPE_HIJACKED`. The universal axiom fires unconditionally:

```
argument_hijacked ← ∃c ∈ S : c.scope = HIJACKED
```

---

## Attack Taxonomy (MCPTox)

**By injection format:**

| Format | Mechanism |
|---|---|
| `<IMPORTANT>` | XML-tag authority escalation inside the docstring |
| `Ignore previous` | Classic prompt-override pattern |
| Plain-text | Disguised as legitimate API documentation |

**By attack template:**

| Template | Pattern |
|---|---|
| Template-1 | Pre-condition injection — force an action *before* the user's intended task |
| Template-2 | Argument manipulation — silently modify a tool parameter |
| Template-3 | Exfiltration chain — read credentials, then send them externally |

**MCP servers covered:**

| Category | Servers |
|---|---|
| File & Storage | FileSystem, SQLite, Redis, Google Drive, Memory, Prisma, ClickHouse |
| Code & Dev | GitHub, GitLab, E2B, Git, Codacy |
| Web & Browsing | Puppeteer, HyperBrowser, Fetch, AgentQL, Apify, Tavily |
| Maps | Amap, BaiduMap, Google Maps, 12306-mcp |
| Finance | AlphaVantage, Financial Dataset, DoDo Payments, Adfin |
| Communication | Slack, Email, Sentry, Flomo, WeChat, Claude Post |
| Utilities | Sequential Thinking, BraveSearch, AWS KnowledgeBase, mcp-simple-arxiv |

---

## Getting Started

```bash
pip install anthropic openai crewai torch tqdm
```

**Analyze MCPTox attack success rates:**
Open [`MCPTox/analysis.ipynb`](MCPTox/analysis.ipynb) — reads `MCPTox/response_all.json` and reproduces all per-model, per-template, and per-server result tables.

**Score an agent log with MCPHorizon:**
```bash
mcphorizon scan path/to/agent_run.jsonl
mcphorizon scan path/to/crewai_log.txt --per-step
mcphorizon check events.json --per-step
```

**Run as a live monitoring service:**
```bash
mcphorizon watch path/to/live_log.txt --interval 0.5
mcphorizon serve --port 8088   # HTTP: POST /check
```

**Run TAMAS evaluation (requires TAMAS scenarios from Microsoft Research):**
```bash
export OPENAI_API_KEY=sk-...
python TAMAS/EVAL/eval_byzantine.py --log_path traces/ --framework CrewAI
python TAMAS/EVAL/eval_collusion.py --log_path traces/ --framework Autogen
```

> See [`USAGE.md`](USAGE.md) for the full CLI reference, event log formats, and integration examples.

---

## Citing MCPHorizon

If MCPHorizon is useful for your research, please cite the repository directly. A plain-text reference, a BibTeX entry, and an APA-style entry are provided below.

### Plain text

> MCPHorizon: A Formal Capability-Safety Framework for Model Context Protocol Security. GitHub, 2025. https://github.com/crakashp2905-hub/MCPHorizon

### BibTeX

```bibtex
@software{mcphorizon2025,
  author    = {crakashp2905-hub},
  title     = {{MCPHorizon}: A Formal Capability-Safety Framework
               for Model Context Protocol Security},
  year      = {2025},
  url       = {https://github.com/crakashp2905-hub/MCPHorizon},
  note      = {Includes MCPTox dataset (300+ poisoned tools, 20 LLMs),
               TAMAS multi-agent attack framework, MCPSecBench benchmark,
               parametric capability-safety lattice, and Datalog compilation.}
}
```

### APA

> crakashp2905-hub. (2025). *MCPHorizon: A formal capability-safety framework for Model Context Protocol security* [Software]. GitHub. https://github.com/crakashp2905-hub/MCPHorizon

### ACM (for systems/security venues)

> crakashp2905-hub. 2025. MCPHorizon: A Formal Capability-Safety Framework for Model Context Protocol Security. Retrieved from https://github.com/crakashp2905-hub/MCPHorizon

---

## References

All external tools, frameworks, and models used in this project are cited below.

### Protocol

[1] Anthropic. (2024). *Model Context Protocol Specification*. https://spec.modelcontextprotocol.io

### Multi-Agent Frameworks

[2] Wu, Q., Bansal, G., Zhang, J., Wu, Y., Zhang, S., Zhu, E., Li, B., Jiang, L., Zhang, X., & Wang, C. (2023). AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation Framework. *arXiv:2308.08155*.

[3] Moura, J. (2024). *CrewAI: Framework for Orchestrating Role-Playing, Autonomous AI Agents*. GitHub. https://github.com/crewAIInc/crewAI

[4] Ollama. (2024). *Ollama — Run Large Language Models Locally*. https://github.com/ollama/ollama

### Formal Methods

[5] Scholz, B., Jordan, H., Subotić, P., & Westmann, T. (2016). On Fast Large-Scale Program Analysis in Datalog. *Proceedings of the 25th International Conference on Compiler Construction (CC 2016)*, pp. 196–206. ACM.

### Machine Learning

[6] Paszke, A., Gross, S., Massa, F., Lerer, A., et al. (2019). PyTorch: An Imperative Style, High-Performance Deep Learning Library. *Advances in Neural Information Processing Systems 32 (NeurIPS 2019)*.

### Language Models Evaluated (MCPTox)

[7] OpenAI. (2024). GPT-4 Technical Report. *arXiv:2303.08774*.

[8] OpenAI. (2024). *o1-mini and GPT-4o mini*. OpenAI Platform.

[9] Anthropic. (2025). *Claude 3.7 Sonnet*. Anthropic. https://www.anthropic.com

[10] Google DeepMind. (2025). *Gemini 2.5 Flash*. Google.

[11] Google DeepMind. (2024). Gemma 2: Improving Open Language Models at a Practical Size. *arXiv:2408.00118*.

[12] Meta AI. (2024). The Llama 3 Herd of Models. *arXiv:2407.21783*.

[13] DeepSeek-AI. (2025). DeepSeek-R1: Incentivizing Reasoning Capability in LLMs via Reinforcement Learning. *arXiv:2501.12948*.

[14] DeepSeek-AI. (2024). DeepSeek-V3 Technical Report. *arXiv:2412.19437*.

[15] Qwen Team, Alibaba. (2025). Qwen3 Technical Report. *arXiv:2505.09388*.

[16] Microsoft. (2024). Phi-4 Technical Report. *arXiv:2412.08905*.

[17] Mistral AI. (2023). *Mistral 7B*. *arXiv:2310.06825*.

### Related Work

[18] Perez, F., & Ribeiro, I. (2022). Ignore Previous Prompt: Attack Techniques For Language Models. *NeurIPS 2022 ML Safety Workshop*.

[19] Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M. (2023). Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections. *AISec @ CCS 2023*.

[20] Zhan, Q., Liang, Z., Ding, Z., & Yao, D. (2024). InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents. *ACL 2024 Findings*.

[21] Yang, Z., Li, L., Liu, X., Ren, Y., Liu, J., Chen, B., Peng, D., Li, W., Zhao, Y., & Wang, X. (2024). Watch Out for Your Agents! Investigating Backdoor Threats to LLM-Based Agents. *arXiv:2402.11208*.

---

## Ethical Note

The poisoned tool definitions in `MCPTox/` and `data/` are **research artifacts** documenting known attack patterns. They are not functional malware. This work is intended solely to advance the understanding of MCP security and to support the development of detection and mitigation strategies.
