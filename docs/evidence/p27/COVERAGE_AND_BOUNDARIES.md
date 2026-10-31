# Managed native execution: coverage & boundaries (P27-17) — CANDIDATE
Source of truth: `horizon.runtime.managed.coverage_report()` (tested).

| effect class | status | how | gap |
|---|---|---|---|
| process creation | intercepted | host /proc ancestry poll (pid+starttime), ~2 ms loop while observers attached | processes shorter than the poll can be missed; a `true`-length child was missed in an early test and the loop was tightened — still not a syscall trace |
| scratch file events | intercepted | host inotify | scratch tree only, depth 1 + dirs present at start |
| file access outside scratch | enforced_not_observed | Landlock + mount masking | denials silent |
| direct network | enforced_not_observed | netns + seccomp + Landlock | attempts not logged unless the code itself reports errno (advisory) |
| brokered network | intercepted | broker + independent receiver | HTTP only |
| general syscalls / kernel audit | unavailable | — | P24-18 unmet |
| non-Python top-level runtimes | unsupported | refused before launch (no fallback) | children of Python are confined by inheritance |

"Not intercepted" never means "safe". Executables written to scratch can run (builds need that); they inherit the identical seccomp/NNP/capability/Landlock profile (tested on python/perl/sh/cc children).

**Cross-interface comparison (P27-18):** MCP-wrapper, UTCP-CLI and Code-Mode entries are thin tags over the same `ManagedExecutor.run`; identical code gives identical normalized outcomes. The real MCP/UTCP transports and the existing JS isolated-vm Code Mode were **not** run end to end in this phase — the claim is "one enforcement path", not "three independently verified integrations".
