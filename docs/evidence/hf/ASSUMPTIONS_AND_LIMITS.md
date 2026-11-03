# HorizonForge first slice (HF-PR02/04/05 subset) — CANDIDATE, research prototype

Source: main after ENG-PR03 merge + this PR. Code: `horizon/forge/{ir,checker,synth,worlds}.py`; tests `tests/hf` (23); `scripts/hf_mutants.py` (18/18 killed). Outside the trusted kernel; nothing imports it.

What exists: a finite typed model (label, placement, data form, controls, witnesses); an independent checker with explicit rules; a deterministic bounded enumerator that returns CERTIFIED_WITH_SCOPE /
CERTIFIABLE_AFTER_RELOCATION / NOT_CERTIFIABLE_WITHIN_MODEL; a negative certificate listing the checker's violation for every enumerated plan, re-verifiable by `verify_negative_certificate`; and a
finite indistinguishable-world certificate with a missing-witness hint. Experiments A (opaque remote + raw secret -> not certifiable) and B (relocation found) are reproduced IN THE TOY MODEL.

Honest limits: the "world" is a hand-written finite model, so this shows the formulation is implementable, not that it works on real agents. The checker and synthesizer share the IR and were written by
the same author (no independent verifier; HF-003/015/042/049/082/095 are EXTERNAL and open). The rules are my encoding of the spec's example, not validated against real effect oracles. Cost model is
arbitrary. No SMT/MaxSAT backend, no baselines B0-B9, no held-out worlds, no statistics, no theorem proofs (T1-T5 not proven). Novelty is UNCONFIRMED; no systematic prior-art search was run.
Reproduce: `python3 -B -m unittest discover -s tests/hf && python3 -B scripts/hf_mutants.py`
