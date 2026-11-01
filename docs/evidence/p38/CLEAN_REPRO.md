# P38-16 clean-environment reproduction — author-run (NOT independent)

* commit: `4fd94b90ae95a0e387e4e421ad2dae40a4474dcf`
* fresh `git clone` of the local repository, empty environment (PATH, HOME=temp, LANG), network namespace with only loopback up
* machine: Linux 6.18.44-fc-v185 x86_64, Python 3.13.18
* **Who ran this:** the author of the code under test. MG-G12 requires a different maintainer; this file does not satisfy it.

| # | command | exit | seconds |
|---|---|---|---|
| 1 | `bench/h4/netns_lo.py python3 scripts/p38_runner_check.py --require` | 0 | 0.1 |
| 2 | `bench/h4/netns_lo.py python3 scripts/p23_freeze.py --check` | 0 | 0.1 |
| 3 | `bench/h4/netns_lo.py python3 scripts/hr_gates.py --check` | 0 | 0.0 |
| 4 | `bench/h4/netns_lo.py python3 bench/h4/run.py check` | 0 | 0.4 |
| 5 | `bench/h4/netns_lo.py python3 bench/h4/report.py --check` | 0 | 0.0 |
| 6 | `bench/h4/netns_lo.py python3 bench/haa/aggregate.py results/v2/haa-main --check` | 0 | 0.1 |
| 7 | `bench/h4/netns_lo.py python3 scripts/p38_casebook.py --check` | 0 | 0.0 |
| 8 | `bench/h4/netns_lo.py python3 scripts/p38_compare.py --check` | 0 | 0.0 |
| 9 | `bench/h4/netns_lo.py python3 scripts/p38_papers.py --check` | 0 | 0.0 |
| 10 | `bench/h4/netns_lo.py python3 scripts/p38_gates.py --check` | 0 | 0.1 |
| 11 | `bench/h4/netns_lo.py python3 scripts/p30_no_external.py` | 0 | 0.0 |
| 12 | `bench/h4/netns_lo.py python3 scripts/p30_claims_audit.py` | 0 | 0.0 |
| 13 | `bench/h4/netns_lo.py python3 -W ignore -m unittest tests.p31.test_intake tests.p32.test_triggerlab tests.p36.test_guard tests.p37.test_h4 tests.p38.test_p38.Casebook tests.p38.test_p38.Matrix tests.p38.test_p38.Runner tests.p38.test_p38.LayerDocs tests.p38.test_p38.SinkRepro tests.p38.test_p38.Drills tests.p38.test_p38.Comparison tests.p38.test_p38.Gates tests.p38.test_p38.Papers tests.p38.test_p38.Bundle` | 1 | 15.2 |
| 14 | `bench/h4/netns_lo.py python3 -W ignore -m unittest tests.p33.test_hccb tests.p34.test_isolation tests.p35.test_telemetry tests.p29.test_haa tests.p30.test_p30` | 0 | 38.0 |

## Output tails

**1.** `bench/h4/netns_lo.py python3 scripts/p38_runner_check.py --require`
```
{"euid": 0, "ipv6": false, "kernel": "6.18.44-fc-v185", "kernel_tests_runnable": true, "landlock_abi": 7, "machine": "x86_64", "reasons": [], "unshare_netns": true, "verdict": "RUN"}
```
**2.** `bench/h4/netns_lo.py python3 scripts/p23_freeze.py --check`
```
{"signature_ok": true, "ok": true, "mismatch": [], "missing": []}
```
**3.** `bench/h4/netns_lo.py python3 scripts/hr_gates.py --check`
```

```
**4.** `bench/h4/netns_lo.py python3 bench/h4/run.py check`
```
h4 aggregate recomputed from raw rows: MATCH | file hashes: OK
```
**5.** `bench/h4/netns_lo.py python3 bench/h4/report.py --check`
```
p37 RESULTS.md: MATCH
```
**6.** `bench/h4/netns_lo.py python3 bench/haa/aggregate.py results/v2/haa-main --check`
```
aggregate REPRODUCED
```
**7.** `bench/h4/netns_lo.py python3 scripts/p38_casebook.py --check`
```
p38 casebook: OK
```
**8.** `bench/h4/netns_lo.py python3 scripts/p38_compare.py --check`
```
p38 scanner comparison: MATCH
```
**9.** `bench/h4/netns_lo.py python3 scripts/p38_papers.py --check`
```
p38 papers: MATCH
```
**10.** `bench/h4/netns_lo.py python3 scripts/p38_gates.py --check`
```
p38 gates: MATCH
```
**11.** `bench/h4/netns_lo.py python3 scripts/p30_no_external.py`
```
p30 no-external-contact (static literal scan): PASS
```
**12.** `bench/h4/netns_lo.py python3 scripts/p30_claims_audit.py`
```
claims audit: PASS
```
**13.** `bench/h4/netns_lo.py python3 -W ignore -m unittest tests.p31.test_intake tests.p32.test_triggerlab tests.p36.test_guard tests.p37.test_h4 tests.p38.test_p38.Casebook tests.p38.test_p38.Matrix tests.p38.test_p38.Runner tests.p38.test_p38.LayerDocs tests.p38.test_p38.SinkRepro tests.p38.test_p38.Drills tests.p38.test_p38.Comparison tests.p38.test_p38.Gates tests.p38.test_p38.Papers tests.p38.test_p38.Bundle`
```
----------------------------------------------------------------------
Ran 131 tests in 14.973s

FAILED (failures=2)
```
**14.** `bench/h4/netns_lo.py python3 -W ignore -m unittest tests.p33.test_hccb tests.p34.test_isolation tests.p35.test_telemetry tests.p29.test_haa tests.p30.test_p30`
```
----------------------------------------------------------------------
Ran 105 tests in 37.839s

OK
```

**Overall: FAILURE**
