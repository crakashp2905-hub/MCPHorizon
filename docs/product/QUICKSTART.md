# hzd — self-hosted developer product (CANDIDATE)

What it is: a CLI that runs a coding-agent program **confined**, lets only policy-permitted edits land in your repository through the effect kernel, and writes a **signed evidence bundle** you can verify offline. A read-only local dashboard shows the bundles.

## Install (offline, reproducible)
Needs Python ≥ 3.11 and the `cryptography` package already present. Nothing is downloaded.
```
python3 scripts/build_dist.py --out dist            # byte-identical output for the same source tree; writes .sha256
tar xzf dist/hzd-*.tar.gz && cd hzd-*/
python3 install.py --prefix ~/.local/hzd             # refuses if any file differs from MANIFEST.json, or if the prefix is already installed
~/.local/hzd/bin/hzd doctor
python3 install.py --verify-only ~/.local/hzd        # later: detects edited, missing or extra files
```
`doctor` reports `can_confine_agents_here`. It is true only for root on x86_64 Linux with Landlock ABI ≥ 4. When false, `hzd run` **refuses** — it never falls back to running the agent unconfined.

## Use
```
hzd init --dev-keys                                   # dev-grade evidence key in ~/.hzd (custody is YOUR decision; see below)
hzd profiles
hzd run --repo . --program agent.py --allow 'src/*' --allow 'tests/*'          # dry run: shows WOULD_ALLOW / WOULD_BLOCK
hzd run --repo . --program agent.py --allow 'src/*' --apply --check-cmd "python3 -m unittest"
hzd model-run --repo . --endpoint http://127.0.0.1:11434 --model <name> --task "..." --allow 'src/*' --apply   # local model plans, confined runner executes
hzd verify ~/.hzd/runs/<run>/bundle.json              # offline, public key only; exit 1 on any failure
hzd dashboard                                         # http://127.0.0.1:8765/  read-only, no auth, loopback only
```
Profiles: `strict-repo` (only `--allow` paths), `standard-repo` (src/lib/tests/docs/top-level docs and .py), `readonly-audit` (nothing lands). Hidden paths (`.git`, `.github`, `.env`, `.ssh`) are always refused.

## What a bundle does and does not tell you
Signed (Ed25519, role `evidence-signer`, distinct from permit issuer, enforcer and installer): what ran, under which profile/policy digest, what landed or was blocked with signed enforcer receipts, repo tree digests before/after, journal chain status, and the limits below. It proves the record was not changed after signing. It does **not** prove the host or this tool was uncompromised.

## Limits (also stored in every bundle)
- Agents are Python programs run by the confined runner; arbitrary agent executables are not supported (no exec inside the sandbox). The local model runs outside the sandbox as a planner; hook tested only against a stub server — **no real model was run**.
- Confinement is Landlock + seccomp + namespaces on the host kernel; not a VM. Verified only on the build environment's kernel, not on any designated production host.
- Exec/syscall attempts are not logged (UNKNOWN); only the empty network namespace is covered; path policy cannot separate a malicious edit from a legitimate one in an allowed path; deletions are not applied.
- The dashboard has no authentication; do not expose it.
- **Key custody is not decided here.** `init --dev-keys` writes a 0600 file next to the data it signs; anyone who can read it can forge bundles. Choose real custody (HSM/KMS/offline key, separate account) before relying on bundles.
