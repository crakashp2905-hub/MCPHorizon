# How to share models with the sandbox (for the weight-space and LLM-agent experiments)
The sandbox cannot reach huggingface.co or ollama.com (policy 403, checked twice). Two workable routes:

**Route A — files via your linked folder (recommended).** On your Windows PC download the model yourself, then copy it into the connected folder `D:\MCPHorizon\models\<name>\`. I stage it with the device bridge (limits: 400 MB per file, 500 MB per call; split larger files).
- Format I can use on CPU here: a small **safetensors** checkpoint folder (config.json, tokenizer files, model.safetensors, LICENSE) — I can load it with `transformers` + `torch` from PyPI (PyPI is reachable) — or a **GGUF** file with `llama-cpp-python` (gcc/cmake are installed).
- Suggested first models (pin the exact revision/commit hash in a `SOURCE.txt`): a sub-1B instruct model for patching/tool-use tests (e.g. a Qwen 0.5B-1B instruct or Gemma 270M-class), plus ONE slightly larger model (1-3B) only if you have disk/time.
- Run `python scripts/hash_model_dir.py D:\MCPHorizon\models\<name>` (I provide it) and paste the printed SHA-256 list into `SOURCE.txt`; I re-hash after staging.

**Route B — run on your machine.** I write the scripts (`research/weightspace/*`, dataset runner) and you run them with Ollama/llama.cpp on your GPU and send back the output JSON. Best if you have a GPU; this sandbox has 2 CPUs and ~3 GB RAM on the device VM, so >1B models will be slow.

**Route C — ask your admin to allow hosts for the next session:** huggingface.co, cdn-lfs.huggingface.co, *.hf.co, registry.ollama.ai (then start a new session).

Licensing: only share models whose license permits this use; record license + revision. Do not share private/proprietary weights you cannot redistribute to a cloud sandbox.
