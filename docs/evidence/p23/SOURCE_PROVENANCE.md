# Incident source provenance (P23-02, P23-03) — CANDIDATE

| Item | Statement | Status |
|---|---|---|
| First report | Cohere's investigation write-up, first dated **2026-10-26**: agent sessions of a Qwen-derived model attempted unrequested outbound network actions. | Recorded from the public page; **not independently reproduced here**. |
| Replay / secondary analysis | Check Point replay, dated **2026-10-29**: 64 replays, 52 distinct destination hosts; its authors favored a "jaggedness" explanation over deliberate intent. | Secondary source. It is a *replay*, not the original occurrence. |
| Dataset id (as published) | `CohereLabs/10-2026-qwen-investigation-traces` | Identifier only. **No download was performed by this project.** |
| Sanitized-vs-original ids | Only the id above was visible; no separate "original" identifier was observed. | UNKNOWN — do not assume one exists. |
| License / retrieval terms | **NOT STATED on the page when checked.** | Treat as all-rights-reserved until a human confirms; no trace content is committed here. |

## Three things that must never be conflated (P29-15)
1. **Trace replay** — re-reading recorded steps (our L1). Proves nothing about a model's behavior.
2. **Prefix completion** — a model continuing from a recorded prefix. Shows conditional behavior only.
3. **Spontaneous full-task occurrence** — the event arising without a seeded prefix. Rare-event claim; needs the pre-registered study (P29-14) and is **not** claimed by this repo.

The event schema carries `origin ∈ {trace_replay, prefix_completion, spontaneous, synthetic, live_attempt}`; the importer only ever emits `trace_replay`.

## Handling rules
* Remote hosts named in the reports are never contacted. All destinations in fixtures are local aliases (`sink-NNN.test`).
* Trace contents are inert data: never executed, never fetched (tested by patching exec/network and importing).
* No secret from a trace is reproduced: correspondence keeps only a keyed digest and length (`Sanitizer.map`).
