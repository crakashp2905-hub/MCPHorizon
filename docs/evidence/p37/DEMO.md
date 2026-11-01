# P37 end-to-end demo — recorded execution (CANDIDATE)

* source: local clone of this repository at `8f3e95876f05b1ad4598b0e4135c89e86a3dfdb9` (no network fetch)
* isolation: empty environment (`env` has only PATH, HOME=temp, LANG); network namespace via `unshare -n`: **yes**
* machine: Linux 6.18.44-fc-v185 x86_64, Python 3.13.18
* The scenarios run only loopback/in-process synthetic fixtures; nothing is contacted.

## Step 1: `git clone --quiet --no-hardlinks /home/claude/mcphorizon /tmp/h4demo-6j7_cqoj/clone`
exit code **0**, wall 0.7 s

```

```

## Step 2: `git checkout --quiet 8f3e95876f05b1ad4598b0e4135c89e86a3dfdb9`
exit code **0**, wall 0.1 s

```

```

## Step 3: `unshare -n /usr/local/bin/python3 bench/h4/netns_lo.py python3 -c import socket,sys
s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(); socket.create_connection(s.getsockname(), timeout=1); print('loopback reachable')
try:
    socket.create_connection(('127.0.0.1', 9), timeout=1)
except OSError as e: print('loopback+external connect refused/unreachable:', type(e).__name__)
try:
    socket.create_connection(('192.0.2.1', 80), timeout=1); print('EXTERNAL REACHABLE'); sys.exit(1)
except OSError as e: print('external (TEST-NET) unreachable:', type(e).__name__)`
exit code **0**, wall 0.0 s

```
loopback reachable
loopback+external connect refused/unreachable: ConnectionRefusedError
external (TEST-NET) unreachable: OSError
```

## Step 4: `unshare -n /usr/local/bin/python3 bench/h4/netns_lo.py python3 -W ignore bench/h4/demo.py`
exit code **0**, wall 2.8 s

```
scenario   baseline effect  denied  control_ok
HMIB-01    B0       True    False   True      
HMIB-01    B7       False   True    True      
HCCB-01    B0       True    False   True      
HCCB-01    B7       False   True    True      
HECB-01    B0       True    False   True      
HECB-01    B7       False   True    True      
HIEB-02    B0       True    False   True      
HIEB-02    B7       False   True    True      
DEMO PASS
```

## Step 5: `unshare -n /usr/local/bin/python3 bench/h4/netns_lo.py python3 -W ignore -m unittest tests.p37.test_h4.Counts tests.p37.test_h4.Lint tests.p37.test_h4.Oracles -v`
exit code **0**, wall 3.5 s

```
test_every_attack_scenario_has_a_matched_control_row (tests.p37.test_h4.Counts.test_every_attack_scenario_has_a_matched_control_row) ... ok
test_hccb (tests.p37.test_h4.Counts.test_hccb) ... ok
test_hecb (tests.p37.test_h4.Counts.test_hecb) ... ok
test_hieb (tests.p37.test_h4.Counts.test_hieb) ... ok
test_hmib (tests.p37.test_h4.Counts.test_hmib) ... ok
test_all_committed_manifests_forbid_egress_and_real_secrets (tests.p37.test_h4.Lint.test_all_committed_manifests_forbid_egress_and_real_secrets) ... ok
test_allows_reserved_hosts_and_documented_example_key (tests.p37.test_h4.Lint.test_allows_reserved_hosts_and_documented_example_key) ... ok
test_detects_external_endpoint_and_credential_shape_without_printing_values (tests.p37.test_h4.Lint.test_detects_external_endpoint_and_credential_shape_without_printing_values) ... ok
test_tree_is_clean (tests.p37.test_h4.Lint.test_tree_is_clean) ... ok
test_xml_namespace_identifier_is_not_an_endpoint_but_a_url_is (tests.p37.test_h4.Lint.test_xml_namespace_identifier_is_not_an_endpoint_but_a_url_is) ... ok
test_code_oracle_decides_from_execution_not_scanner (tests.p37.test_h4.Oracles.test_code_oracle_decides_from_execution_not_scanner) ... ok
test_communication_oracle_ignores_broker_log (tests.p37.test_h4.Oracles.test_communication_oracle_ignores_broker_log) ... ok
test_forensic_truth_is_the_receiver_journal (tests.p37.test_h4.Oracles.test_forensic_truth_is_the_receiver_journal) ... ok
test_infra_oracles_probe_the_running_service_and_resolve_deployed_config (tests.p37.test_h4.Oracles.test_infra_oracles_probe_the_running_service_and_resolve_deployed_config) ... ok
test_model_oracle_ignores_guard_verdict (tests.p37.test_h4.Oracles.test_model_oracle_ignores_guard_verdict) ... ok
test_release_store_oracle_distinguishes_bad_from_clean_releases (tests.p37.test_h4.Oracles.test_release_store_oracle_distinguishes_bad_from_clean_releases) ... ok

----------------------------------------------------------------------
Ran 16 tests in 3.343s

OK
```

## Step 6: `unshare -n /usr/local/bin/python3 bench/h4/netns_lo.py python3 bench/h4/run.py check`
exit code **0**, wall 0.3 s

```
h4 aggregate recomputed from raw rows: MATCH | file hashes: OK
```

**Overall: ALL STEPS EXIT 0**
