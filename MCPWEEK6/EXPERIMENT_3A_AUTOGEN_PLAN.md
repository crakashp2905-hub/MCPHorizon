# Experiment 3A — AutoGen Framework-Robustness Probe (PLAN + SKELETON)

**Status:** Scoped, not yet run. Needs a new log parser (below) + a targeted run.
**Claim it supports:** MCPHorizon's detection is a property of the *capability lattice*,
not of the CrewAI orchestration framework — it survives a framework change.

---

## Why this is a probe, not a full matrix

3A's job is to show the detector isn't secretly relying on CrewAI-specific behavior.
That claim is proven by re-running a *handful* of scenarios on AutoGen and showing
MCPHorizon fires the same way. It does NOT require re-running all 50 (or 150) on
AutoGen — that's enormous compute for zero additional claim strength.

**Recommended scope:** the strongest Colluding horizon-firing showpieces, on AutoGen:
- healthcare 04, 07, 08 (multi-hyperedge horizon hits on CrewAI)
- news 08 (the full 4-agent chain, 53 events on CrewAI)
- finance 06, 07 (risk-bypass horizon hits)
- 2-3 benign/clean scenarios as negative controls

≈ 8-10 scenarios. At ~25 min each → **~4-6 hours**, one short overnight run.

If MCPHorizon fires the SAME hyperedges / horizon on AutoGen that it fired on
CrewAI for these scenarios, the framework-independence claim is demonstrated.

---

## The one real obstacle: AutoGen logs ≠ CrewAI logs

Your evaluator parses CrewAI's boxed UI:
```
RE_AGENT = r"Agent:\s+([^\n\|]+?)..."
RE_TOOL  = r"Tool Execution Completed.*?\n.*?Tool:\s+([a-zA-Z_]\w*)"
```
AutoGen emits a totally different stdout (and supports a structured message
stream). So 3A needs an **AutoGen-specific parser** that extracts the same
(agent, tool) event sequence the lattice consumes. Everything downstream —
the capability map, the lattice, the hyperedges, the horizon — is unchanged
and framework-agnostic. Only the parser is new.

### Two ways to get (agent, tool) events out of AutoGen

**Option 1 (preferred) — structured callback, no text parsing.**
AutoGen exposes tool-call events programmatically. In the AutoGen runner,
register a callback on each agent that appends `{"agent", "tool", "args"}` to a
JSONL — exactly the trace format your lattice already reads (`replay_multiagent_trajectory`
consumes a list of `{"agent","tool"}` dicts). This sidesteps text parsing entirely
and produces a trace identical in shape to the CrewAI `.jsonl`.

**Option 2 (fallback) — parse AutoGen stdout.**
If you must parse text, AutoGen's console output for a tool call looks roughly like:
```
---------- {AgentName} ----------
[FunctionCall(... name='{tool_name}' arguments='{...}')]
[FunctionExecutionResult(... name='{tool_name}' ...)]
```
The skeleton parser below handles this shape. It is more brittle than Option 1.

---

## Skeleton: autogen_trace_parser.py

```python
\"\"\"
autogen_trace_parser.py

Extract (agent, tool) events from AutoGen output so the EXISTING MCPHorizon
lattice can score AutoGen runs. Produces the same JSONL trace shape the CrewAI
path emits: one {"agent","tool","args"} object per line.

Two entry points:
  parse_structured(events)  -- preferred: feed AutoGen's message objects
  parse_stdout(text)        -- fallback: parse console text
\"\"\"
from __future__ import annotations
import json
import re
from pathlib import Path


# ---- Option 2: stdout parsing -------------------------------------------
# AutoGen agent banner:  ---------- AgentName ----------
RE_AGENT_BANNER = re.compile(r"-{6,}\s*(?P<agent>[^\-\n]+?)\s*-{6,}")
# FunctionCall(... name='tool' ...)
RE_FUNC_CALL = re.compile(r"FunctionCall\([^)]*?name='(?P<tool>[a-zA-Z_]\w*)'")


def parse_stdout(text: str) -> list[dict]:
    \"\"\"Walk AutoGen console text, tracking the current agent and each tool call.\"\"\"
    events = []
    current_agent = None
    for line in text.splitlines():
        m_agent = RE_AGENT_BANNER.search(line)
        if m_agent:
            current_agent = m_agent.group("agent").strip()
            continue
        for m_tool in RE_FUNC_CALL.finditer(line):
            events.append({
                "agent": current_agent or "Unknown",
                "tool": m_tool.group("tool"),
                "args": {},
            })
    return events


# ---- Option 1: structured events ----------------------------------------
def parse_structured(messages) -> list[dict]:
    \"\"\"
    Preferred path. `messages` is AutoGen's emitted message list/stream.
    We look for tool-call messages and pull (source agent, tool name).
    The exact attribute names depend on the AutoGen version; adjust the
    getattr lines to match. Common shapes:
      msg.source                      -> agent name
      msg.content -> list of FunctionCall with .name
    \"\"\"
    events = []
    for msg in messages:
        agent = getattr(msg, "source", None) or getattr(msg, "name", None) or "Unknown"
        content = getattr(msg, "content", None)
        if content is None:
            continue
        # content may be a list of FunctionCall-like objects
        if isinstance(content, list):
            for item in content:
                tool = getattr(item, "name", None)
                if tool:
                    events.append({"agent": agent, "tool": tool,
                                   "args": getattr(item, "arguments", {}) or {}})
    return events


def write_trace(events: list[dict], out_path: str):
    with open(out_path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\\n")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--stdout_log", help="AutoGen .txt console log to parse")
    ap.add_argument("--out", required=True, help="Output .jsonl trace")
    args = ap.parse_args()
    text = Path(args.stdout_log).read_text(encoding="utf-8", errors="replace")
    evs = parse_stdout(text)
    write_trace(evs, args.out)
    print(f"Extracted {len(evs)} (agent,tool) events -> {args.out}")
```

---

## How to score AutoGen runs once you have traces

The lattice already consumes the JSONL trace shape. To evaluate an AutoGen run:

```python
from tool_capability_map import lookup_capability, is_orchestration
from multi_agent_lattice import replay_multiagent_trajectory
import json

def fl(t): return None if is_orchestration(t) else lookup_capability(t)
events = [json.loads(l) for l in open("autogen_trace.jsonl")]
result = replay_multiagent_trajectory(events, fl)
print(result["alert_step"], result["horizon_hits"])
```

Same map, same lattice, same hyperedges. If healthcare_08 fires
`untraceable_clinical_fabrication` + the other horizon entries on AutoGen just
like it did on CrewAI, the framework-independence claim holds.

---

## Honest caveats for 3A

1. **AutoGen agent names may differ from CrewAI's.** Your hyperedges use
   wildcard agent premises (agent_id=None keyed on capability pattern), so they
   are robust to name changes — but verify the tool *names* AutoGen emits match
   the capability map (a quick preflight on one AutoGen log).
2. **AutoGen may orchestrate differently** (e.g., different turn order, different
   tool-selection behavior). The *trajectory* may not be identical to CrewAI's
   even at temperature 0 — that's fine. The claim is "MCPHorizon detects the same
   compositional capability when it occurs," not "the two frameworks produce
   identical runs."
3. **This is a probe.** Report it as "we re-ran N showpiece scenarios on AutoGen
   to confirm framework-independence," not as a second full benchmark.
4. **Tool wiring in AutoGen** must use the SAME tools_<domain>.py functions, or
   the comparison is meaningless. Confirm the AutoGen runner imports the identical
   TAMAS tool modules.

---

## Recommended order

1. Run **2A benign baseline first** (it's ready now, just needs the run) — it
   closes the 0-FP claim and is higher priority than 3A.
2. Then build the AutoGen runner + this parser, run the ~8-10 showpiece probe.
3. Report both in the threats-to-validity / robustness section.
```
