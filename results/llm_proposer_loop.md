# LLM Proposer Multi-Round Report

- Backend: **ollama**
- Rounds: 3
- Observed states sampled: 30
- Total proposals: 9
- Validated: 1
- Redundant: 0
- Rejected: 8
- Strict validation rate: 11.1%
- Loose validation rate: 11.1%

## Per-round breakdown

| Round | Proposals | Validated | Redundant | Rejected |
|---|---|---|---|---|
| 1 | 3 | 0 | 0 | 3 |
| 2 | 3 | 1 | 0 | 2 |
| 3 | 3 | 0 | 0 | 3 |

## Negative log feedback effect

Round 2+ proposals are constructed with the previous round's rejected
labels fed as few-shot negative examples. If the LLM is using this
feedback, we expect the same rejected labels to NOT reappear in later
rounds (the loose validation rate should rise).