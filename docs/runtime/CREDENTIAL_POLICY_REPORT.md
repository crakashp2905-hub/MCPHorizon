# Credential policy & surface report (P26-18) — CANDIDATE

Measured on `6.18.44-fc-v185` (x86_64), Landlock ABI 7. Secrets in this report: none — credential references are shown as `cref_<opaque>`; the synthetic secrets used by tests are never printed.

## Policy
* Secrets live only in the trusted broker; sandboxed code receives `cref_<opaque>`, bound to one principal, one method, one canonical URL (optionally one body hash), a TTL and a use count.
* The broker injects `Authorization`; payloads containing the secret (raw/base64/hex/url-encoded) are refused (`SECRET_IN_PAYLOAD`).
* Credentials are never forwarded across redirects; echoed secrets are scrubbed from responses; audit rows hold ref ids only.
* Refs are revoked on task completion, timeout and emergency stop.

## Measured surface inventory (fixtures present on the host, probed from inside the sandbox)

| surface | kind | on host | sandbox result | exposed |
|---|---|---|---|---|
| `.ssh/id_rsa` | file | True | 2 | no |
| `.ssh/id_ed25519` | file | True | 2 | no |
| `.ssh/config` | file | True | 2 | no |
| `.aws/credentials` | file | True | 2 | no |
| `.aws/config` | file | True | 2 | no |
| `.config/gcloud/application_default_credentials.json` | file | True | 2 | no |
| `.azure/accessTokens.json` | file | False | 2 | no |
| `.kube/config` | file | False | 2 | no |
| `.docker/config.json` | file | False | 2 | no |
| `.netrc` | file | False | 2 | no |
| `.git-credentials` | file | False | 2 | no |
| `.npmrc` | file | False | 2 | no |
| `.pypirc` | file | False | 2 | no |
| `.gnupg/private-keys-v1.d` | file | False | 2 | no |
| `/var/run/docker.sock` | socket | False | 2 | no |
| `/run/docker.sock` | socket | False | 2 | no |
| `/run/containerd/containerd.sock` | socket | False | 2 | no |
| `/run/user/0/bus` | socket | False | 2 | no |
| `/run/user/1000/bus` | socket | False | 2 | no |
| `AWS_SECRET_ACCESS_KEY` | env | True | False | no |
| `AWS_SESSION_TOKEN` | env | False | False | no |
| `GOOGLE_APPLICATION_CREDENTIALS` | env | False | False | no |
| `GITHUB_TOKEN` | env | True | False | no |
| `GH_TOKEN` | env | True | False | no |
| `ANTHROPIC_API_KEY` | env | False | False | no |
| `OPENAI_API_KEY` | env | False | False | no |
| `SSH_AUTH_SOCK` | env | False | False | no |
| `DOCKER_HOST` | env | False | False | no |
| `NPM_TOKEN` | env | False | False | no |
| `KUBECONFIG` | env | False | False | no |
| `HZ_TEST_HOST_SECRET` | env | True | False | no |
| `169.254.169.254` | metadata | None | network namespace has no route; broker class-denies | no |
| `169.254.170.2` | metadata | None | network namespace has no route; broker class-denies | no |
| `100.100.100.200` | metadata | None | network namespace has no route; broker class-denies | no |
| `fd00:ec2::254` | metadata | None | network namespace has no route; broker class-denies | no |
| `metadata.google.internal` | metadata | None | network namespace has no route; broker class-denies | no |

Exposed: **0** of 36 surfaces. Metadata rows are not probed over a network (the sandbox has none); they are exercised by `tests/p26` against a listener bound to the real metadata address on the host loopback (zero requests served).

## Limits
* x86_64 Linux, root launcher only. Inventory covers a fixed list of well-known locations, not arbitrary secret placement.
* Redaction/scrubbing are pattern-based: unknown encodings of a secret (e.g. custom ciphers, chunked transfer) are not detected.
* The trusted broker process itself holds secrets in memory; it is in the TCB and is not itself sandboxed here.
