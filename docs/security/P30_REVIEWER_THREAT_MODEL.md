# P30 reviewer threat model — HorizonRuntime (CANDIDATE)

Purpose: tell an independent reviewer exactly what to attack, what is claimed, and what is **not** claimed. No independent reviewer has examined this yet (HR-G9 NOT MET).

## Assets and trust boundaries
- **Untrusted:** the agent-generated code/commands running in the sandbox, anything it writes, every tool output and trace (treated as inert data).
- **Trusted computing base (this repo):** `horizon/runtime/{sandbox,broker,creds,procs,managed,artifacts,events,schema}.py`, the Linux kernel (namespaces, Landlock, seccomp), the root launcher, the independent receiver/mock oracles.
- **Out of TCB but assumed:** the host OS, the VM/hypervisor, Python and bandit, the pinned advisory snapshot (synthetic 2-entry DB).

## Attacker model
Code execution as uid 10001 inside the sandbox with fd 3 (broker socketpair) only. Can spawn processes, use any installed interpreter, write its own scratch space, and craft arbitrary bytes/URLs/destination spellings. Cannot: change launch arguments, read broker keys, or reach the launcher's filesystem outside the mounted view (claim to be verified by the reviewer).

## Attack surfaces to try (each maps to HAA scenarios and `tests/p30`)
| Surface | Prior coverage | Reviewer should try |
|---|---|---|
| Egress: IP spellings, userinfo, trailing dot, DNS rebinding, redirects, proxy env, UDP, abstract/pathname unix sockets, raw syscalls | HAA-01,02,08,10,11,19; adaptive campaign (130-pair space, 60 attempts run) | IPv6 (untested here: VM lacks it), SCTP/raw, `AF_PACKET`, DNS-over-existing-fd, covert timing channels |
| Credentials | HAA-03,13; `tests/p26` | side channels via broker error text, TTL races, cref guessing |
| Process tree / alternate interpreters / persistence | HAA-06,07,09,21 | double fork + setsid daemons surviving launch, `io_uring`, ptrace-like tricks, seccomp gaps |
| Policy/audit tamper | HAA-16, `tests/p30` | symlink/bind-mount races toward policy paths |
| Label loss (taint) | HAA-14,22,23 | transformations that defeat canary/variant detectors (compression, split exfil across requests) |
| Artifact gate | HAA-17,18,24 | vulnerabilities outside the 4 fixture classes; non-Python code |
| Availability / fail-closed | HAA-20, `tests/p30` | broker restart storms, resolver poisoning |

## Explicit non-claims
- Not a proof of security. UER = 0 means no effect reached local oracle sinks in the runs listed in `docs/evidence/p29/RESULTS.md`.
- No claim about model weights, intent, or spontaneous occurrence rates (L3 not run).
- Not evaluated on other kernels, architectures, or against kernel exploits (see `P30_KERNEL_LIMITS.md`).
- Scenario and defences were authored together; held-out/adaptive sets mitigate but do not remove that bias.

## How to reproduce
`sudo -E env "PATH=$PATH" python3 scripts/p30_repro.py HAA-14 B5` (one scenario × baseline); `python3 bench/haa/aggregate.py results/v2/haa-main --check`; signed bundle: `python3 scripts/p30_reviewer_bundle.py build bundle.tar` / `verify bundle.tar`.
