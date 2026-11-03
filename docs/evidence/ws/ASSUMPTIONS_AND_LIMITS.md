# Weight-space patch API, model-free slice (HP-008, HP-009, HP-020, HP-022, HP-026 partial) — CANDIDATE
Code `research/weightspace/patch.py` (numpy only); tests `tests/ws` (18); `scripts/ws_mutants.py` (16/16 killed).
Covers: content-addressed checkpoint digest (name, dtype, shape, bytes); structured proposals; budget by entry count AND delta L2; finite/dtype/index/allowed-tensor checks; copy-on-write apply; exact inverse;
manifest with base/indices/delta digests, status CANDIDATE, authorized_by null; independent manifest re-check detecting undeclared changes; static check that the gradient-free module imports no optimizer framework; kernel does not import `research`.
NOT done / BLOCKED: no model was downloaded or edited (huggingface.co and cdn-lfs.huggingface.co return 403 policy denial from both this sandbox and the linked machine's shell, checked 2026-11-03); no activations, causal probing,
editor-model loop, baselines, held-out evaluation, Sentinel or Transfer experiments. No safetensors/torch I/O, no power-loss test of apply/rollback.
