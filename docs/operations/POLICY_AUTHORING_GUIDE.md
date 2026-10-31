# Operator policy authoring guide (P10-20)

Principles: default-deny for protected effects (`write, modify, delete, execute, send, admin`); allow narrowly by effect, sink zone and **maximum input label**; version numbers only increase; changes go through `ApprovalLog` (digest-bound, two-person for policy changes).

## Examples
```json
{"id":"a-read","when":{"effect":"read","maximum_input_label":"INTERNAL"},"decision":"ALLOW"}
{"id":"a-send","when":{"effect":"send","sink_zone":"partner","maximum_input_label":"PUBLIC"},"decision":"ALLOW"}
```
The second rule lets only PUBLIC-labelled inputs reach the `partner` zone. A run that read a SECRET source and sends only public bytes is allowed **if lineage is tracked** (SecBench S templates); without lineage the coarse alternative is to block any such run.

## Labelling sources
Labels come from operator config (`Sidecar(sources=...)`), never from tool descriptions or model text. Unknown sources default to INTERNAL/UNTRUSTED. Mislabelling a secret as PUBLIC defeats every downstream control.

## Known false positives (measured in SecBench/P9)
- Unknown transports (`ws.send`, CLI uploads) and unmapped endpoints fail closed even for benign data. Fix by mapping them in the manual registry and approving them.
- True claims from untrusted sources are blocked from protected effects until independently verified (epistemic ledger).
- Chunked or reversed encodings of secrets can still leak; keep SECRET sources out of runs that have any external send.

## Review checklist
Rule has an effect and sink zone; label ceiling is the lowest that works; no wildcard allow for protected effects; simulate with `/v2/policies/simulate` against a labelled test set; record approval digest.
