# LLM Proposer Multi-Round Report

- Backend: **mock**
- Rounds: 3
- Observed states sampled: 30
- Total proposals: 12
- Validated: 0
- Redundant: 0
- Rejected: 12
- Strict validation rate: 0.0%
- Loose validation rate: 0.0%

## Per-round breakdown

| Round | Proposals | Validated | Redundant | Rejected |
|---|---|---|---|---|
| 1 | 4 | 0 | 0 | 4 |
| 2 | 4 | 0 | 0 | 4 |
| 3 | 4 | 0 | 0 | 4 |

## Negative log feedback effect

Round 2+ proposals are constructed with the previous round's rejected
labels fed as few-shot negative examples. If the LLM is using this
feedback, we expect the same rejected labels to NOT reappear in later
rounds (the loose validation rate should rise).

**Note:** This run used the deterministic mock backend.
Multi-round dynamics in mock mode are limited because the mock
is stateless. Real LLM call would show divergence across rounds.