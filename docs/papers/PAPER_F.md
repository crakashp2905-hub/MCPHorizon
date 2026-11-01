# Paper F (draft): Can independent OS/receiver-side evidence expose agent transcript spoofing and unauthorized coordination?

**Status: DRAFT, CANDIDATE. Single-process synthetic topology; no real multi-agent system.** Every number is generated from committed result files by `scripts/p38_papers.py`.

**Hypothesis (spec §53.2):** independent receiver-side and trusted-collector evidence exposes agent-generated transcript spoofing and unauthorized coordination under imperfect application-layer telemetry.

## Completed experiments used
* P34 agent isolation, P35 telemetry (`tests/p34`, `tests/p35`), and HECB (`results/v2/h4-main`): 18 attack types (9 channel, 9 forensic).

## Results

HECB attack types with a successful channel or an audit that called a real incident clean (of 18):

| B0 | B5 runtime | B6 | B7 |
|---|---|---|---|
| 18 | 18 | 18 | 0 |

Leave-one-layer-out: removing isolation exposes the 9 channel types; removing telemetry exposes the 9 forensic types; no other single layer matters on this suite.

## Negative and limiting findings
* Without the telemetry layer every transcript-spoofing type passes: the agent-writable transcript is not evidence.
* A clean reconciliation covers only operations on the instrumented path and only up to the last seal.
* An absence claim ('no external send occurred') needs a receiver-signed assertion; the agent's statement is not evidence.
* P35-15 (independent key-management review of the collector) is open.

## Not shown by this draft
* timing, resource-contention or steganographic channels
* any statement about a real multi-agent deployment
* the OpenAI/Hugging Face incident's actual mechanism (a local abstracted topology only)
