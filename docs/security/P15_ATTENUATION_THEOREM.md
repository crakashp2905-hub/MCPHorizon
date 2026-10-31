# P15 — Conditional attenuation theorem (P15-14) and limits

**Setting.** Authority is `(actions, tools, resources, dests, arg_max, nbf, exp)` (`horizon/deleg/authority.py`). `subset(c,p)` holds iff every component of `c` is at least as restrictive as `p` (path-boundary prefix coverage for resources; `arg_max` keys of `p` must be present and no larger in `c`; window contained). `intersect` is the greatest lower bound used for multi-parent grants; there is no union.

**Theorem (conditional).** Assume (A1) Ed25519 signatures are unforgeable, (A2) the root signing key is held only by the trusted issuer channel, (A3) the delegation key is not compromised, (A4) the verifier clock and revocation set are current. Then for every grant `g` accepted by `Verifier.effective`, `authority(g) ⊆ ⋂ authority(parents(g))` hop by hop, hence `authority(g) ⊆ authority(root)` for every root reachable from `g`; `depth(g) ≤ max_depth`; `tenant(g)` equals all ancestors' tenant; no ancestor is revoked or outside its window at check time.
*Proof sketch:* acceptance requires, at every node, a valid signature by the role-correct key, `subset(au, ⋂ parents)`, and recursion on parents; induction on depth plus transitivity of `subset`.
**Not claimed:** safety if A2/A3 fail (the verifier still re-checks every hop, which limits a compromised delegator to *signature-valid* but non-amplifying grants — tested via forged delegator-signed amplification), confidentiality, or anything about what a *permitted* action does with the data.

**Machine-checked part:** `tests/p15/test_deleg.py` (random intersection lower-bound property, random chain attenuation property, 24 tests; 24 mutants killed).

**Found bug (fixed):** the verification cache was keyed without the clock, so an expired chain could be served from cache. Key now includes the second-resolution time and the revocation epoch.

**Limits / not done:** cross-organizational delegation (P15-05) is only "same tenant, intersection of parents" — no cross-org trust anchors or policy; async jobs/callbacks (P15-08) are supported only in the sense that `authorize` is evaluated at call time with current expiry/revocation — no queue/callback integration was built; grants are not wired into the production MCP/UTCP gates; arg ranges cover string length / numeric magnitude only; the P15-13 baselines are author-written models on synthetic scenarios (and `legit_narrow` tasks on a different resource are counted as out-of-scope by construction), so the comparison shows the mechanism works, not that it beats real RBAC deployments.
