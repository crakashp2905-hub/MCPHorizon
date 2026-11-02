# PRODUCT_BLOCKERS — ranked (effect bypass > cross-tenant leakage > credential exposure > operations)
1. **RC-R not signed** — independent research handoff absent; all P55–P74 work is gated. Owner: project owner + independent reviewer.
2. **No independently assessed protected sink** (P55-05/06, P59-18) — effect-bypass risk unmeasured for any product SKU.
3. **No customer evidence** (P56, P65, P93) — no interviews, design partners, pilots; none may be invented.
4. **No cross-tenant isolation evidence** (P58/P60) — only single-tenant local models exist.
5. **Credential handling** — no managed secret store or rotation drill beyond local models (P10 candidate only).
6. **Legal/procurement/pricing** — terms, DPAs, licensing and pricing validation need external parties (P55-08, P65–P72).
7. **No GA/SOC/security-committee sign-offs** (P73–P74).
