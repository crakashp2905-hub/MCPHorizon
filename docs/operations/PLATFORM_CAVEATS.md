# Platform caveats (P10-17)

Supported and tested: **Linux** (CI: ubuntu-latest, Python 3.11–3.13, Node 22, Rust stable).

Linux-only or Linux-tuned features: `SO_PEERCRED` peer authentication (`ops/peer.py`); `/proc`-based fd checks in tests; Code Mode `unshare -Urn` network isolation, `nobody` uid drop and `RLIMIT_NPROC`; `resource` rlimits (`ops/guard.limit_process`); Unix-socket mode bits.
macOS: peer credentials need `LOCAL_PEERCRED` (not implemented); rlimits partially enforced; unshare absent. Windows: no Unix sockets with these semantics, no `resource` module, no rlimits, different path and symlink rules.
**macOS and Windows CI are not configured and the code is not claimed to run there (P10-16 open).** Use Linux containers on those hosts; the container does not make Code Mode a hardened sandbox.
