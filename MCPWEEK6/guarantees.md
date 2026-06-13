# Formal guarantees — detection boundary, certification soundness, decidability + min-cut

Notation. Capabilities live in the lattice `L` over `(action, resource, scope)`, extended
with an agent dimension. `μ` maps a tool to its capability. For a trajectory
`τ = ⟨(g₁,t₁),…,(gₙ,tₙ)⟩`, write `caps(τ) = { (gᵢ, μ(tᵢ)) }`. `H` is the hyperedge set
(19 deployed cross-agent edges + the universal HIJACKED axiom); `Φ` is the danger-horizon
marker set. `Cl_H(S)` is the monotone least-fixed-point closure of a capability set `S`
under `H` (proven PTIME in §3). The detector **fires** on `τ` iff
`Cl_H(caps(τ)) ∩ (Φ ∪ {axiom}) ≠ ∅`. All three results below rest on one fact proven in
§3: **`Cl_H` is monotone** — `S ⊆ S' ⟹ Cl_H(S) ⊆ Cl_H(S')`.

---

## Theorem 1 (Detection boundary — the §8 NO-GO, formalized)

**(a) What it catches.** By construction the detector fires on `τ` exactly when
`caps(τ)`, closed under `H`, satisfies the axiom (some HIJACKED-scope capability) or a
horizon witness (all premises of some `h ∈ H`).

**(b) What it provably misses.** A trajectory `τ` is **undetected** iff
*(i)* no step of `τ` produces a HIJACKED-scope capability, **and**
*(ii)* no `h ∈ H` has all premises satisfied by `caps(τ)`.
Equivalently, the missed set is exactly `{ τ : Cl_H(caps(τ)) ∩ (Φ ∪ {axiom}) = ∅ }`.

*Proof.* The fixed point `Cl_H(caps(τ))` is determined entirely by which axiom/hyperedge
premises `caps(τ)` satisfies (the closure adds a marker iff a rule's premises are met).
The detector fires iff that fixed point meets `Φ ∪ {axiom}`; it is silent iff it does
not, which is precisely the conjunction of (i) (no axiom) and (ii) (no horizon witness).
∎

**Corollary 1.1 (TAMAS NO-GO).** On TAMAS, HIJACKED scope is produced *only* by the 109
malicious-labeled tools, and every `h ∈ H` carries ≥1 HIJACKED premise (verified, §8).
Hence any `τ` that satisfies (i)-negation or (ii)-negation contains a HIJACKED-producing
(malicious-labeled) step. Therefore the detector's catch-set **equals** the malicious-tool
flagger `D0`'s catch-set: `Coverage(D3) = Coverage(D0)` on TAMAS. *Proof.* If the detector
fires, either the axiom fired (a HIJACKED capability is present ⟹ a malicious tool ran ⟹
`D0` fires) or a horizon fired (its HIJACKED premise needs a HIJACKED capability ⟹ a
malicious tool ran ⟹ `D0` fires). Conversely a malicious tool produces HIJACKED scope ⟹
the axiom fires ⟹ the detector fires. ∎

**Corollary 1.2 (Appendix G boundary move).** Let `h*` be an all-benign-premise
cross-agent edge (`h_cross_agent_exfiltration`: `read(sensitive,ANY)@i`,
`send(external_network,ANY)@j`, distinct agents → `cross_agent_exfiltration`). For a `τ`
composed of *benign* tools satisfying `h*`'s premises, `caps(τ)` contains no HIJACKED
capability, so `D0` is silent and the axiom does not fire — yet under `Cl_{H∪{h*}}` the
horizon `cross_agent_exfiltration` is reached. Thus `h*` moves exactly such dangers from
the missed set (Thm 1b) into the caught set, with `D0` still silent. This is the formal
content of the Appendix G existence proof: **the boundary is set by `H`, and an
all-benign-premise edge is precisely what shifts a benign-composed danger across it.** ∎

---

## Theorem 2 (Soundness of static certification)

**Deployment.** `D` = a set of agents, each with a tool manifest `manifest(a)` (the tools
it *may* call). Define the **static tool-induced capability set**
`Σ(D) = ⋃_{a} { (a, μ(t)) : t ∈ manifest(a) }` — every capability any agent's tools can
produce. `Certify(D) = SAFE` iff `Cl_H(Σ(D)) ∩ (Φ ∪ {axiom}) = ∅`, else `UNSAFE` (with
the reached horizon entries as the certificate's witness).

**Claim (no false "safe").** If `Certify(D) = SAFE`, then **no** execution `τ` over `D`
reaches a horizon entry or the axiom.

*Proof.* Every step `(gᵢ,tᵢ)` of any `τ` over `D` has `tᵢ ∈ manifest(gᵢ)`, so
`(gᵢ, μ(tᵢ)) ∈ Σ(D)`; hence `caps(τ) ⊆ Σ(D)`. By monotonicity of `Cl_H`,
`Cl_H(caps(τ)) ⊆ Cl_H(Σ(D))`. If `Cl_H(Σ(D)) ∩ (Φ ∪ {axiom}) = ∅`, then
`Cl_H(caps(τ)) ∩ (Φ ∪ {axiom}) = ∅` for **every** `τ`. So no execution breaches. ∎

**Conservative direction (sound, not complete).** `Σ(D)` over-approximates: it assumes
all manifest tools are co-present (including premises that distinct agents might never
jointly realize in one run, or capabilities a benign run never exercises). So `Certify`
may return `UNSAFE` for a deployment no actual `τ` breaches (a **false unsafe**), but —
by the proof — never a false safe. Certification is **sound, not complete**. The right
deployment use is therefore *gating*: a `SAFE` certificate is a guarantee; an `UNSAFE`
certificate is a flag to inspect or remediate (Theorem 3).

---

## Theorem 3 (Decidability, complexity, minimal-cut remediation)

**(a) Decidability + complexity.** `Certify(D)` is decidable in **PTIME** in `|Σ(D)|` and
`|H|`. *Proof.* `Σ(D)` is finite (`≤ |tools|·|agents|`). `Cl_H` is a monotone least fixed
point over a finite lattice, computable in `O(|H|·|Σ(D)|^k)` for premise arity `k` (§3).
A final membership test against `Φ ∪ {axiom}` is `O(|Φ|)`. All polynomial. ∎

**(b) Minimal-cut remediation.** For `UNSAFE` `D`, the minimum set of tools to sandbox
(remove from manifests) to restore `SAFE` is a **minimum hitting set over the horizon
witness chains.** Each reached `φ ∈ Φ` has ≥1 *witness* `W(φ)` — a minimal capability set
whose joint presence fires `φ`; each capability is produced by ≥1 tool. A sandboxing cut
must, for every reached `φ` and every witness, remove a producing tool of some capability
in it. Formally: build the witness hypergraph whose hyperedges are
`{ producers(c) : c ∈ W(φ) }` per witness; a valid cut is a hitting set; the optimum is
**minimum hitting set** — NP-hard in general.

**Tractability here.** Every deployed edge has premise arity `k ≤ 2` (and the axiom `k=1`),
so every witness has ≤ 2 capabilities. Minimum hitting set on 2-element sets is **minimum
vertex cover** on the induced graph (vertices = capabilities, edges = 2-witnesses), which
is 2-approximable in P and solved exactly for the small bounded instances here (a handful
of witnesses per deployment). Algorithm: (1) certify, collect reached `φ` and their
witnesses; (2) form the witness (hyper)graph over producing tools; (3) solve min hitting
set — exact by branch-and-bound on the small instance, or greedy `ln`-approx in general;
(4) return the tool cut. *Decidability/complexity of the cut is therefore PTIME at bounded
arity; NP-hard only in the unbounded-arity limit (sketch: reduction from VERTEX-COVER by
encoding each graph edge as a 2-witness).*

---

## Consistency with observed behavior

The companion script `certify.py` runs `Certify` over the static tool-induced capability
set of each TAMAS domain deployment, the benign baseline, and the T2-9 coding→deploy
deployment, and checks the **soundness invariant empirically**: *no deployment certified
`SAFE` ever fired a horizon in any recorded run.* (Expected: TAMAS attack deployments and
the T2-9 sensitive-read + external-publish deployment certify `UNSAFE` and do fire; the
benign baseline and the internal-only coding deployment certify `SAFE` and never fire.)

**Scope honesty.** Theorems 1–2 and 3(a) are full proofs (they rest only on the §3
monotone-closure result). 3(b)'s NP-hardness is a standard reduction sketch and its
bounded-arity tractability is argued, not a fully written proof. The boundary theorem is
exactly the §8 NO-GO made precise; it does **not** claim coverage beyond `H` — Corollary
1.2 is what extends `H`, and only there does coverage grow.
