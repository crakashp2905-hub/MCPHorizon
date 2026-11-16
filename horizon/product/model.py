"""K6: local-model hook. The model runs OUTSIDE the sandbox (host-side, loopback endpoint only by default) and is a PLANNER: it is shown the task and file names and returns a Python edit program, which is then run inside the confined runner like any other untrusted agent code.
Nothing the model says is trusted. Speaks the OpenAI-compatible /v1/chat/completions shape (llama.cpp server, Ollama /v1, vLLM...). Tested ONLY against a stub HTTP server in this repo — no real model was run. CANDIDATE."""
from __future__ import annotations
import json, os, re, urllib.request, urllib.parse

SYSTEM = ("You edit a code repository by writing ONE Python program. It runs with the repository as the current directory, no network, no subprocesses. "
          "Use only relative paths and plain file reads/writes (open(...)). Reply with a single ```python code block and nothing else.")


class ModelError(Exception): pass


def _loopback(url: str) -> bool:
    h = urllib.parse.urlsplit(url).hostname or ""
    return h in ("127.0.0.1", "::1", "localhost")


def list_files(repo: str, limit=200) -> list:
    out = []
    for d, ds, fs in os.walk(repo):
        ds[:] = sorted(x for x in ds if not x.startswith("."))
        for f in sorted(fs):
            if not f.startswith("."): out.append(os.path.relpath(os.path.join(d, f), repo))
    return out[:limit]


def extract_program(text: str) -> str:
    m = re.search(r"```(?:python)?\s*\n(.*?)```", text or "", re.S)
    if not m or not m.group(1).strip(): raise ModelError("NO_CODE_BLOCK")
    return m.group(1)


def propose_program(endpoint: str, model: str, task: str, repo: str, *, allow_remote: bool = False, timeout: float = 120, snippets: dict | None = None) -> tuple:
    """-> (program, raw_reply). Refuses a non-loopback endpoint unless allow_remote (the repo's file names and snippets would leave the machine)."""
    if not allow_remote and not _loopback(endpoint): raise ModelError("REMOTE_ENDPOINT_REFUSED")
    user = f"Task: {task}\nFiles:\n" + "\n".join(list_files(repo)) + "".join(f"\n\n--- {k} ---\n{v}" for k, v in (snippets or {}).items())
    req = urllib.request.Request(endpoint.rstrip("/") + "/v1/chat/completions", data=json.dumps({"model": model, "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}], "temperature": 0}).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r: d = json.loads(r.read().decode())
        text = d["choices"][0]["message"]["content"]
    except (OSError, ValueError, KeyError, IndexError, TypeError) as e: raise ModelError("MODEL_UNREACHABLE_OR_BAD_REPLY:" + type(e).__name__)
    return extract_program(text), text
