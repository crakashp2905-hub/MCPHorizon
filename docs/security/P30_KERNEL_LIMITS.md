# Kernel and platform limits (P30-07)

Measured on: Linux 6.18 (Firecracker-style VM), x86_64, root launcher, Landlock ABI 7, seccomp-BPF, user/mount/pid/net namespaces available. Results are for this configuration only.

| Limit | Consequence |
|---|---|
| Landlock does not scope pathname unix sockets | a tmpfs mount mask hides host socket paths; abstract sockets are handled by the net namespace. A reviewer should test mask completeness. |
| IPv6 unavailable on the test VM (EAFNOSUPPORT) | IPv6 destination forms were **not** exercised end to end; the broker's IPv6 handling is unit-tested only. |
| Launcher runs as root; sandbox drops to uid 10001 with `no_new_privs` and capability drop | a kernel privilege-escalation bug or a flaw in launch ordering voids isolation; no defence is claimed against kernel exploits. |
| Launch refuses (never weakens) when a control is unavailable | availability is traded for safety; unsupported kernels yield `UNSUPPORTED`/refusal, and tests skip visibly. |
| Observation (ProcWatch, FileWatch) is polling/inotify based | short-lived processes can be missed; enforcement does not depend on observation, but event completeness does. |
| Single kernel, single arch | no claim for ARM, older kernels (<5.13 lacks Landlock), gVisor, or containers without user namespaces. |
| CI runners | root tests run via `sudo` on GitHub-hosted runners; job logs are not machine-readable here, so step timings were used to confirm tests executed rather than skipped. |
