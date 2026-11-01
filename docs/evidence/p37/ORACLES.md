# P37 — independent oracles (P37-07..P37-10)

Rule: **a scenario's effect is decided by something the guard under test does not control and does not consult.** A guard's own allow/deny is recorded separately (`denied`) and is never the effect. The tests in `tests/p37/test_h4.py::Oracles` feed each oracle a world where the guard says "fine" and check that the oracle still reports the effect.

| Suite | Effect oracle | What it reads | What it deliberately ignores | Strength |
|---|---|---|---|---|
| HMIB (model integrity) | `ModelWorld.unapproved_loaded()` | sha256 of every file the **inert loader** read at load time, the image digest and launch-config digest it was given, and the revision string | the manifest, the signature, the intake report | live record of loaded bytes vs a harness-held truth table; revision must be a 40-hex pin |
| HMIB-19/20 (behaviour) | P32 `ToyModel` activation + mock-tool log | the mock external-send tool's own log | the policy's rejection record | scripted toy model, **not** a live model |
| HCCB (generated code) | `Pipe.bad_released()` | the release **store** contents joined with harness truth | gate decision, permit, scanner output | injection / traversal / command-injection / authz: dynamic exploit oracle in the P24 sandbox (`dynamic_sandbox_oracle`). Hardcoded secret, debug mode, secret logging, deserialization, dependency cases: **ground truth by construction** (`by_construction_label`) — the defect was built into the fixture; no behavioural exploit is run |
| HECB 01–10 (channels) | `VisibilityOracle` over the recipient's returned reads | what the recipient actually received | the broker's decision log (one test asserts it empty while the oracle still fires) | in-process, one process; no network or timing channels |
| HECB 11–20 (forensics) | `ReceiverJournal` (independent sink record, own key) vs the audit conclusion | whether the sink actually received the forbidden send | the agent transcript and the plain log | effect = *forbidden effect happened **and** the audit says clean*; an audit that flags a real incident counts as a defence success |
| HIEB 02,04–08,13 | live HTTP probe to the **loopback** `SyntheticService` | anonymous rows, anonymous admin, anonymous metrics, anonymous / cross-tenant logs, retained expired line after cleanup | the lint findings | real requests against a real (local) listener |
| HIEB 01,03,09–12,14 | `facts()` independent resolver of the *deployed* document | effective port bindings (incl. long form), default credentials, plaintext secrets, privilege grants, TLS | `guard.lint` | **config facts, weaker than a live probe**: no off-loopback listener is ever bound (P36-04) |

## Honest weaknesses
* `facts()` and `lint` were written by the same author: independent *code*, not independent *judgement*.
* The B3 baseline is an emulation of generic scanners (three literal patterns). The real-tool comparison is the separate P36 run against checkov 3.2.0, which could not parse most fixtures.
* HCCB by-construction labels mean "the defect was put there", not "an attacker exploited it".
* Toy models and a single VM. No live model (L3) and no pilot (L5) were run.
