# Discovered bypasses and defects → regression tests (P30-11)

| # | Defect found | Found by | Fix | Regression test |
|---|---|---|---|---|
| 1 | Parent fd 3 inheritable into the sandbox when no broker was attached | tests/p24 inherited-fd check | close loop keeps fd 3 only when a broker socket exists; barrier fds non-inheritable | `tests.p24.test_sandbox` (`test_clean_env_no_host_creds_and_no_inherited_fds`) |
| 2 | Relay process held parent-side pipe ends, so child stdin never saw EOF | p24/p27 hangs | relay closes them | `tests.p24.test_sandbox`, `tests.p27.test_managed` (timeouts fail the suite) |
| 3 | Importer (L1) missed `/dev/tcp`, `IO::Socket`, `AF_INET`, `asyncio.open_connection` | HAA-09 L1 check | network regex extended | `tests.p30.test_p30.Regressions.test_importer_flags_alternate_network_forms` |
| 4 | urllib honoured a cached global opener, ignoring the proxy env in the harness | adaptive proxy channel | fresh `build_opener()` per call | harness-only; covered by HAA-19/adaptive `proxy_env` channel results |
| 5 | Canary DLP blocked legitimate labelled reads (HAA-23 control failed under B5/B6) | pilot probe | DLP only when the rule allows no non-PUBLIC label | `tests.p30.test_p30.KernelRegression` (HAA-22/23 controls) |
| 6 | HAA-21 fork loop had an effect before the process threshold was tied to policy | pilot probe | threshold from policy limits | `tests.p30.test_p30.KernelRegression` (HAA-21) |

No bypass of B6 was observed in the final main, held-out, or adaptive runs, so there is no open B6 bypass to convert. Items 5–6 were fixed after being seen, so those scenarios are tuned-on, not held out.
