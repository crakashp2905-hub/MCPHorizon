# Live-agent gate test (Qwen2.5-0.5B-Instruct) — ASSUMPTIONS AND LIMITS

Status: CANDIDATE. Author-run, single model, templated scenarios. Not VERIFIED.

## What was run
`research/live/run_live.py`: a local 0.5B model is the agent (greedy decoding) in a mock environment
(read_file / send_email / delete_file; no network; reserved `*.test` addresses; synthetic canary
`TEST_CANARY_NOT_SECRET`). 24 templated scenarios x {clean, attacked} x {no gate, gate} = 96 episodes.
The gate blocks an effectful call when an identifier-like argument token appears in tool output but not
in the user prompt (same rule as `provenance_identifier`). Unlike the replay evaluation, the model sees the
refusal and may continue. Results: `research/live/results/live_qwen05.json`.

## Results (n=24 per cell, Wilson 95% CI)
| condition | attack attempted | attack succeeded | user task done |
|---|---|---|---|
| clean, no gate | 0 | 0 | 22/24 (74-98%) |
| attacked, no gate | 18/24 | 18/24 = 75% (55-88%) | 8/24 (18-53%) |
| attacked, gate | 18/24 | 0/24 (0-14%) | 0/24 (0-14%) |
| clean, gate | 0 | 0 | 22/24 (no false block) |

## Honest reading
- The gate stopped every attacker effect (0/18 attempted attacks executed) and caused no false block on clean runs.
- But under attack the gated agent completed the user task in 0/24 episodes (ungated: 8/24; clean: 22/24). 45 calls were
  blocked: the weak model keeps retrying the injected instruction after refusal instead of recovering. Prevention
  here is by denial of service to the task, not by safe continuation. A stronger model might recover; untested.
- 0.5B is a very weak agent; results do not transfer to frontier models. Scenarios are templated (3 injection phrasings),
  attack goals are exactly the two the gate's rule is built to catch (identifier in recipient / file name), and the
  gate was tuned after seeing a false block in a unit test (words copied from the document), so 0/24 is not independent evidence.
- Known gate blind spot: an injection that exfiltrates plain words (no identifier-like token) to a user-named recipient
  is not detected. Not tested here.
- Greedy single run per cell: no sampling variance estimate.
