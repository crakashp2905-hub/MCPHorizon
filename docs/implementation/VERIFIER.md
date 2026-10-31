# Verifier design and keys (answers blocker B-05 for the CI path)

**No shared key is required.** The repository is public, so the verifier workflow (`.github/workflows/verify.yml`) signs its receipts with GitHub's Sigstore build-provenance attestation. The signing identity is the workflow run on `main`; there is no secret an agent could read.

Verify a receipt file downloaded from the run's `receipts` artifact:
```
gh attestation verify receipts.json --repo crakashp2905-hub/MCPHorizon \
  --signer-workflow crakashp2905-hub/MCPHorizon/.github/workflows/verify.yml
```
Then check that `git_sha` in the receipt is the commit you intend and each `result` is `PASS`.

What a receipt proves: the listed commands exited 0 on that exact commit in a clean CI checkout. What it does not prove: that the task text is fully satisfied beyond what those tests check (see `covers` in `spec/acceptance.json`), or that the tests themselves are strong.

## Residual independence gaps (honest)
1. `main` currently has **no branch protection / zero required approvals** (as requested), so whoever can push to `main` can change `verify.yml`, `scripts/ci_verify.py` or `spec/acceptance.json` and weaken the verifier. The coding agent has that ability. For real independence, protect those paths (CODEOWNERS + required review, or a ruleset restricting who can modify them) — the maintainer's call.
2. The in-repo supervisor (`orchestrator/`) still uses HMAC receipts with caller-supplied keys; importing attested receipts into the ledger is not implemented.
3. Symmetric-key option, if you later want the local ledger to accept receipts: generate a random 32-byte key on a machine the worker cannot read, keep it only in the verifier runner's secret store, and register the verifier id in the ledger. I cannot create GitHub secrets/environments from this session (API path blocked), so I did not.
