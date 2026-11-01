# P54 assumptions and limits (CANDIDATE)

P54 adds no mechanism. It audits, freezes, joins and re-checks the recorded evidence of P39–P53. Everything in it is CANDIDATE and not verified, and no gate result is a security claim for any deployment.

## What the numbers are

* Every per-module pair is a count of scripted scenarios written by the same author as the module and its baselines. The intervals are Wilson intervals over scenarios and are descriptive; they are not independent trials. The pooled family rows mix different scenario sets.
* A gate PASS means the named checks (listed in `result.json`) held. They are mostly the module's own recorded headline plus the structural checks added here. A FAIL is a finding about this repository and has not been worked around.
* Same author, same machine, same environment: the reproduction rows are **not independent** and are not the clean-checkout review of P54-16.

* Of the 710 original tasks, those with no command in `spec/acceptance.json` (99 at the time of this run) are BLOCKED for new security claims. A task with a command is mapped, not verified.

## Not done in P54, and why

* **P54-04** (a single 15-module end-to-end fixture): not built. Each module keeps its own world and independent oracle. A shared world would need a common effect model and a study of how the guards interact; neither exists.
* **P54-05** (verify no duplicate privilege authority): the verification was run and **found duplicates** (six files, listed in the ADR). The receipt service is real, but the goal is not met, so the task is left unmapped and ES-G2 is FAIL.
* **P54-07 / P54-08** (all 15 pairs live, per-module ablations): eleven modules are rerun from a fresh process and reproduce their recorded headline; P39–P42 have no importable experiment entry point and are checked by their own `--check` plus their live tests, which does not recompute their numbers. The ablations are the modules' own, recorded in their results; P54 does not add new ones.
* **P54-15** (papers): a draft cannot honestly compare with prior work without citations that were checked against the sources; none were collected. No paper is claimed.
* **P54-16** (independent clean-checkout review and support matrix): needs a person outside this session. `scripts/p54_clean_repro.py` records the author-run clone-and-rerun; ES-G16 is SKIP.

## Known gaps carried forward (reported, not prevented)

* P53 U02, a deceived attestor, passes the admission check; P52 unsupported paths (U01, U02) are only flagged UNKNOWN; P46 stops a quarter of attack runs without completing the task; P49 declines to vouch (UNVERIFIABLE) for a share of compromised runs rather than recovering the truth, and its X01 (all collectors omit consistently) is a known false PASS outside its stated assumptions; P44 prevented 42 of 45 attack runs; P51 blocks two benign tasks; P50 leaves one UNKNOWN reservation charged.
* The UTCP adapter serializes the body as JSON, so the same target and verdict carry different bytes (P14, documented, not fixed).
* The browser adapter is recorded (P51) and is not re-run here. Native adapters are not available in this environment.
* The static review is syntactic: it follows `import` statements and looks for call names. It does not see dynamic imports, reflection or code generated at run time.

## A defect found in the CI mutation steps of P44-P53

`scripts/p44_mutants.py` .. `p53_mutants.py` run each mutant under `python3 -m pytest`, and a failing exit code counts as KILLED. The CI python has no pytest (`No module named pytest`, confirmed in a diagnostic run), so in CI these steps would report every mutant as killed without running a test. They were run for real, with pytest, on the author's machine. P54's mutation script now first runs the unmutated copy and refuses to continue if it fails, and CI installs pytest before it. The earlier steps still run without pytest in CI until they are fixed in a follow-up change; until then their CI result is not evidence.

## Unsupported environments

Windows and macOS, rootless containers without namespaces, kernels without seccomp or cgroups v2, and any run with outbound network are outside what was exercised. The scripts that need network namespaces fail rather than fall back. No claim is made for them, and they are not silently excluded from anything: they are simply not covered.

## Deferred

Independent review (P54-16), the interaction study that would make P54-04 possible, moving the six authority sites onto the shared authority, a reviewed or removed P39 oracle dependency, and cited prior-work comparison for any paper. No live model is used in P39–P54, so there are no model revisions to publish.
