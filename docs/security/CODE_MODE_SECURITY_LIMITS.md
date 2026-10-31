# Code Mode security limits (P6-25, P6-26)

Status: **CANDIDATE.** An in-process V8 isolate is **not** advertised as fully secure. No external security review has been done.

## What this is
`horizon/codemode/exec.py` + `codemode/runner.mjs` run a generated JavaScript program in an `isolated-vm@6.2.0` isolate inside a **separate OS process**.
The program's only capability is `tools.<name>(args)`; every call is sent to the host `mediate()` callback, which must be the project's enforcement path
(MCP/UTCP gates and the P3 decision service). The host, not the program, supplies principal, tenant, execution id and parent execution id.

This is a **project-controlled equivalent**, not a wrapper around `@utcp/code-mode`'s `callToolChain()` (P6-01/P6-02 only partly met: that package's runner/VM
architecture is described in `PINNED_VERSIONS.md` but was not executed or compared here).

## Layers actually in place
| Layer | Evidence |
|---|---|
| No host APIs in the isolate (`require`, `process`, `fetch`, timers, `WebSocket`, `Buffer`, …) | `tests/p6` `test_no_host_apis_in_isolate`, escape attempts via `Function`/`constructor`/`import()` |
| Frozen `tools`, bootstrap handles deleted from the global | `test_tools_cannot_be_replaced_or_extended`, mutation checks |
| Separate process, new session, scrubbed env, `RLIMIT_CPU/NOFILE/FSIZE/CORE` | runner-reported env keys; mutation checks |
| `setuid(nobody)` + `RLIMIT_NPROC` **only when the host runs as root** | `test_runner_is_nonprivileged_and_env_scrubbed` (otherwise it asserts the host's own uid: no privilege drop happens) |
| Isolate memory limit, wall-clock timeout, sync-loop timeout, hard kill of the process group | timeout/memory tests |
| Call budget, log byte budget, redaction of logs and error messages | tests |
| Optional `unshare -Urn` (user + network namespace) | works only where unprivileged user namespaces are allowed; the test skips elsewhere. Default is **off**. |

## What this does NOT provide
- **A V8/isolated-vm engine bug is a full escape** into the runner process. The OS layer limits what that process can do but it is not a container: no seccomp filter, no filesystem namespace/chroot, no cgroup memory/PID limits, no network namespace unless `net_namespace=True` works on the host. A nonprivileged uid can still read world-readable files and, without the namespace option, open sockets.
- Process memory is bounded only by the isolate limit, not by a cgroup. Native allocations by the host runtime are not capped.
- `RLIMIT_NPROC` is skipped when the host is not root (it is per-UID and would starve the runner).
- The static scanner is **advisory only** and always reports `PARTIAL_PREVIEW`/`exhaustive: false`. It misses dynamically computed names (measured by `diff_report`, `static_false_negatives`). Enforcement is per runtime call, not per scan.
- Effects already forwarded when a program is cancelled or times out cannot be recalled; such calls are listed in `pending_unconfirmed` and must be reconciled by the host.
- The mediator's correctness is outside this module. If it forwards, nothing here stops it.
- Not run: OS-level escape testing, fuzzing, a comparison against the real `@utcp/code-mode` package, performance/overhead measurement, or any test on a hardened (seccomp/gVisor/Firecracker) runtime. P6-25 is therefore only partially met.

## Recommended before any production use
Run the runner inside a real sandbox (gVisor/Firecracker/nsjail with seccomp, read-only rootfs, no network, cgroup limits), pin and review the `isolated-vm` build, and get an independent review.
