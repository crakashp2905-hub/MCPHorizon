# P55/P57/P59 product primitives (CANDIDATE)
`horizon/product/core.py` holds six small rules (feature flags, status vocabulary, redacted errors, audit/enforce fail-safe, effect receipt states, local metrics) with 7 tests and 22 mutants killed. They are not wired into any gateway, SDK or sink. The secret-redaction regex covers only a few token shapes. Effect receipts rely on the caller supplying sink observation.
All sign-off, customer, legal, review, packaging and enforcement-sink tasks in P55–P74 were NOT done and remain gated on RC-R.
