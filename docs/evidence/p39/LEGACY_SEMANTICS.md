# P39-01 — Legacy capability/hypergraph semantics (frozen) and the precision it loses

Source of truth: the Week-1 prototype (`capability_engine.closure`, `results/hypergraph.json`), frozen as `horizon/emergence/legacy_hypergraph.json` and `horizon/emergence/legacy.py` (test: `tests.p39.test_emergence.Legacy`).

**Semantics.** State = a *set of flat capability strings*. A hyperedge `(premise set → conclusion set)` fires when the premise is a subset of the state; closure is the least fixpoint (monotone, order-free). A tool contributes a fixed capability set (`TOOL_DB`), optionally lifted by a scope tag.

**Precision lost** (each is demonstrated by a test, not just stated):

| Lost | Consequence |
|---|---|
| Arguments / endpoint identity | `network_send_external` is one string: a send to the approved partner and a send to a third party are the same capability. |
| Data flow / taint | `credentials_in_context` is a property of the *session*, never of a value; the value being hashed or redacted before sending is invisible. |
| Sanitization | `read_secret → hash → get` fires `h_exfil_chain` exactly like `read_secret → get`. |
| Order | closure is a set: the edge fires whichever tool ran first. |
| Delegated remote effects | an allowed endpoint that redirects/forwards is indistinguishable from one that does not. |
| Unknown tools | `TOOL_DB` returns an empty capability set (silent safe); P39 reports UNKNOWN instead. |

Consequence measured in `RESULTS.md`: on the 252-chain labeled corpus the legacy-style co-occurrence detector (D3) has false-positive rate ≈ 0.49 and the D0 name flagger has recall 0. This is *not* a claim that legacy MCPHorizon was wrong about its own supported vocabulary; it is a statement about what flat sets cannot express.
