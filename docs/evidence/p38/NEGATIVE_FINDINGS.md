# P38-14 negative findings ledger (all manuscripts)

Collected from the experiments above; each line names where it is also stated in a draft.

1. B7 leaves 1/63 attack types exposed: HCCB-06 (debug mode) — Paper E.
2. B1 (name guard) and B2 (OS sandbox alone) show **zero** benefit on all four H4 suites — the suites do not exercise what they protect; Paper D/F.
3. Intake cannot detect dormant triggers inside approved weights; behavioural trust stays UNASSESSED — Paper D.
4. Behavioural screens (B1/B2 in P32) leave 30/40 triggered runs with an effect — Paper D.
5. Static scanner alone misses authorization-logic flaws and a trivial evasion rewrite — Paper E.
6. checkov could not parse 4 of 4 InfraGuard-format fixtures; no breadth claim — Paper G.
7. HMIB has no pickle-style unsafe-format scenario (the class model-file scanners do cover) — SCANNER_COMPARISON.
8. Config-fact oracles (7 of 14 HIEB types) are weaker than live probes — Paper G.
9. P35-15 independent key-management review is open; P30-02 IPv6 gap unmapped — Paper F / threat models.
10. A defect found along the way: a P28 exception permit could outlive the human approval that authorised it (fixed in P33, regression test added). A second: a probe that could not reach its service read as 'no exposure' (fixed in P37: now a harness error).
11. All fixtures synthetic, toy models, one VM, one author: HR-G7 and HR-G9 NOT MET, MG-G12 (independent reproduction) NOT MET.
