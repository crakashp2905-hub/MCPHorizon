# Repeating the cross-agent budget-composition experiment (P45-16)

```
python3 scripts/p45_repeat.py                    # recorded parameters: must print "matches recorded run"
python3 scripts/p45_repeat.py --seed 7 --agents 4 --per-agent 10 --eps 0.1 --trials 100
```
Everything is local (SQLite in a temp directory, synthetic data, loopback-free). Noise is derived from HMAC(secret, request id); the secret and request ids are functions of the seed, so a seed reproduces the run exactly. The report script and `scripts/p45_run.py --check` verify that the definitions behind the recorded numbers (scenarios, systems, budgets, dataset digest) are unchanged. A third party can substitute their own accountant by replacing `horizon/privacy/reference.py` (the oracle) and re-running `tests/p45`.
