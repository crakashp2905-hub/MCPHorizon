# Cross-agent containment: scope and limits (MG-G8)

**Claim (defined, controlled tests only):** with a mediated, authenticated, default-deny shared store and per-run sandbox mounts, a synthetic marker written by one tenant's run was not visible to another tenant's run through (a) the store API, (b) any handle the recipient holds, or (c) the sandbox filesystem, as judged by an oracle that inspects the backing data independently of the broker's decision log. The unmediated configurations (raw shared store, shared scratch mount) *do* carry the marker, so the oracle can see a leak.

**What this does not prove**
- It does not prove absence of **covert timing, resource-contention, or side channels** between co-resident runs (CPU, memory pressure, port/PID exhaustion). Only explicit shared-state channels were exercised.
- The broker simulation is **in-process**: it models the policy and identity logic, not a deployed network service, its transport security, or its key management. Workload tokens are signed by a locally generated key.
- Only the surfaces in the inventory were tested. Anything a real deployment shares that is not in the inventory is an unknown channel. In this repository the measured sandbox exposes exactly one writable shared surface (the scratch mount); other deployments will differ.
- Two tenants, synthetic markers, deterministic scenarios; no adaptive adversary tried to find an unlisted channel.
- Detection (repeated rejections) is threshold-based and can be evaded by staying below the threshold; prevention does not depend on it.
- Revocation is effective at the next broker operation; operations already completed are not undone.
