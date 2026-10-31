#!/usr/bin/env python3
"""P26-18: measured credential-surface report with OPAQUE identifiers only. `--check` verifies the committed report exists and contains no secret-shaped strings."""
import os, sys, platform
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "docs/runtime/CREDENTIAL_POLICY_REPORT.md")
if "--check" in sys.argv:
    from horizon.runtime import schema as SC
    t = open(OUT).read(); bad = SC.redact(t)[1]; assert "TEST_CANARY_NOT_SECRET-" not in t and not bad, bad; assert "cref_<opaque>" in t; print("ok"); sys.exit(0)
from horizon.runtime import creds as C, sandbox as S
from tests.p26.test_creds import Fixture
if os.geteuid() or S.landlock_abi() < 4: sys.exit("UNSUPPORTED: needs root + Landlock to measure")
with Fixture(): rows = C.surface_inventory("/home/hzfix")
L = ["# Credential policy & surface report (P26-18) — CANDIDATE", "", f"Measured on `{platform.release()}` ({platform.machine()}), Landlock ABI {S.landlock_abi()}. Secrets in this report: none — credential references are shown as `cref_<opaque>`; the synthetic secrets used by tests are never printed.", "",
     "## Policy", "* Secrets live only in the trusted broker; sandboxed code receives `cref_<opaque>`, bound to one principal, one method, one canonical URL (optionally one body hash), a TTL and a use count.", "* The broker injects `Authorization`; payloads containing the secret (raw/base64/hex/url-encoded) are refused (`SECRET_IN_PAYLOAD`).",
     "* Credentials are never forwarded across redirects; echoed secrets are scrubbed from responses; audit rows hold ref ids only.", "* Refs are revoked on task completion, timeout and emergency stop.", "", "## Measured surface inventory (fixtures present on the host, probed from inside the sandbox)", "", "| surface | kind | on host | sandbox result | exposed |", "|---|---|---|---|---|"]
L += [f"| `{r['surface']}` | {r['kind']} | {r['host_exists']} | {r['sandbox']} | {'**YES**' if r['exposed'] else 'no'} |" for r in rows]
L += ["", f"Exposed: **{sum(r['exposed'] for r in rows)}** of {len(rows)} surfaces. Metadata rows are not probed over a network (the sandbox has none); they are exercised by `tests/p26` against a listener bound to the real metadata address on the host loopback (zero requests served).",
      "", "## Limits", "* x86_64 Linux, root launcher only. Inventory covers a fixed list of well-known locations, not arbitrary secret placement.", "* Redaction/scrubbing are pattern-based: unknown encodings of a secret (e.g. custom ciphers, chunked transfer) are not detected.", "* The trusted broker process itself holds secrets in memory; it is in the TCB and is not itself sandboxed here.", ""]
open(OUT, "w").write("\n".join(L)); print("\n".join(L[:12]))
