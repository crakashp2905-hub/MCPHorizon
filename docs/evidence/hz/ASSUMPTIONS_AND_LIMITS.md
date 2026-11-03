# HorizonZero claim registry slice (HF-016..021) — CANDIDATE research prototype
Code `horizon/assurance/registry.py`; tests `tests/hz` (16); `scripts/hz_mutants.py` (14/14 killed). A test caught a real defect during development (digest change of a nested dependency did not suspend dependants); fixed before commit.
Covers: claim schema + digest, dependency closure, expiry/epoch/digest/missing-dependency/revocation suspension, cycle-safe, unknown claim fails closed, prevention-vs-observation outcome states.
Limits: in-memory; claims are not signed; not connected to any permit issuer (HF-020 only as `may_issue_permit`), no crash-consistent revocation (HF-022), no external adversarial replay (HF-023 EXTERNAL). Not independently verified.
