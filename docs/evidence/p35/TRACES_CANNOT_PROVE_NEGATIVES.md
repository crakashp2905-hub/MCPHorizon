# Where traces alone cannot establish a negative claim (MG-G9)

A clean reconciliation report supports a *positive* statement ("every operation that passed through the instrumented broker was recorded, matches the transcript, and has the effect the receiver journal shows"). It never supports "nothing else happened". Specific cases:

1. **Uninstrumented paths.** An effect that never traverses a trusted component produces no trusted event. The receiver journal can reveal it (`EFFECT_WITHOUT_TRUSTED_EVENT`) only for sinks the journal covers.
2. **Missing sink coverage.** A signed no-effect assertion covers exactly one sink and one journal range. It says nothing about other sinks, other ranges, or channels with no receiver journal (DNS, timing, shared files).
3. **Unsealed tail.** Records after the last signed seal can be truncated without cryptographic detection until the next seal. `unsealed_tail` is reported; the window is bounded by the batch size.
4. **Allowed but no effect observed.** This is reported as *uncertain*: it may be a failed request, a filtered response, a lossy journal, or a journal that was not running.
5. **Collector compromise.** If the collector process or its signing key is compromised, the chain proves only that the compromised key signed it. Key custody and rotation were not independently reviewed (P35-15 is open).
6. **Clock claims.** Monotonic order within one collector is reliable; cross-source ordering carries clock uncertainty (`clock_uncertainty_s`), so a timeline cannot prove causality between sources.
7. **Redaction.** Redacted fields cannot be re-examined; a negative claim about a redacted value cannot be made from the log.
8. **Agent-side silence.** An agent that never calls a trusted component leaves no events at all; absence of events is not evidence of absence of behaviour.
