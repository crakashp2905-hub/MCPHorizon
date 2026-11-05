# Prior work for the commit-protocol slice (abstract-level reads unless stated; CANDIDATE)

The mechanisms in this slice are NOT new as ideas:
- Idempotency keys, verify-before-retry, and unknown-outcome handling for LLM-agent tool calls: Li, "Where Does Exactly-Once Live? Model, Harness, and Tool-Contract Effects on Duplicate Side Effects in LLM Agents" (arXiv 2609.29095; abstract read: 25,930 episodes, LIMBO benchmark; contract dominates on unresolvable faults, keys cut duplicates 28%->4%).
- Settlement reliability / duplicate irreversible actions after agent re-runs: Mohammadi et al., "When to Cross the Rubicon" (Zenodo 10.5281/zenodo.23362959; abstract read).
- Durable authorization state / replay-resistant single-use tokens: CapLease, arXiv 2608.01710 (read earlier at abstract level).
- Fencing tokens and leases for stale workers are classical distributed-systems practice (and appear in practitioner write-ups on agent "run leases"); title-level only, not read.
- Search hits not read: "Idempotency for AI Agent Tool Calls with Unknown Outcomes" (ResearchGate), open-source `effectfence`, `once-gate`.

What this slice might contribute (a FALSIFIABLE statement, not a claim of novelty): a small exhaustive model of the whole permit->ledger->separate-principal sink->reconciliation path,
a concrete counterexample class (reconcile-by-read racing a live worker) and its sink-side atomic fence-and-observe fix, orphan-expiry liveness, and a transition-level conformance
check against running code.  This would be refuted by finding the same model + counterexample + conformance result in prior work, or by a reviewer showing the model omits a step.
No "first", "novel" or security-gain claim is made.
