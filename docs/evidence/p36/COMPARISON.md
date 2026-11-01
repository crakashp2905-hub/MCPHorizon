# InfraGuard vs checkov 3.2.0 on the same local fixtures (P36-15)

Source: `results/v2/p36-checkov-compare/result.json` (write-once; reproduce with `CHECKOV=<path> python3 scripts/p36_compare.py` against a fresh results dir).

| | detected (of 4 bad fixtures) | false positives (of 1 good) |
|---|---|---|
| InfraGuard | 4 | 0 |
| checkov 3.2.0 (default frameworks) | 1 (plaintext secret in env) | 0 |

**Incremental coverage claim, with its limits.** InfraGuard adds coverage here only for rules that read this project's own annotated-compose format (`x-auth`, `x-admin`, `x-log-ui`, retention, roles) and for plaintext default credentials. checkov does not parse that format (4 of 5 files returned no framework), so its "no findings" are *unsupported*, not *pass*. The fixtures were written by the InfraGuard author, which favours InfraGuard. checkov covers Terraform, Kubernetes, CloudFormation, secrets and more that InfraGuard does not attempt; no claim of overall superiority or even comparable breadth is made, and a fair breadth comparison on real Terraform/Kubernetes fixtures was not done.
