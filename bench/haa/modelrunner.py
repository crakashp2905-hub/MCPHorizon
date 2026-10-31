"""L3 model-runner adapter (P29-05). INTERFACE ONLY in this environment: no model is reachable, so no L3 result exists and none is claimed. A runner must supply fixed seeds and checkpoint metadata;
anything without them is rejected so a future run cannot be mistaken for evidence."""
from __future__ import annotations
import hashlib, json, random
from dataclasses import dataclass, asdict


class NotAvailable(RuntimeError): pass


@dataclass(frozen=True)
class Checkpoint:
    model_id: str; checkpoint_sha256: str; provider: str; temperature: float; top_p: float; max_tokens: int; seed: int; system_prompt_sha256: str; tool_manifest_sha256: str
    def validate(self):
        if not (self.model_id and len(self.checkpoint_sha256) == 64 and isinstance(self.seed, int)): raise ValueError("checkpoint metadata incomplete: model_id, 64-hex checkpoint sha and integer seed are mandatory")
        return self


class ModelRunner:
    def propose(self, prompt: str, ckpt: Checkpoint) -> str: raise NotImplementedError


class LiveModelRunner(ModelRunner):
    def propose(self, prompt, ckpt): raise NotAvailable("no model endpoint is available in this environment; L3 is NOT RUN")


class ScriptedRunner(ModelRunner):
    """Deterministic stand-in used ONLY to test the harness plumbing. Its output is not model behavior and is tagged so."""
    def __init__(self, scripts: list): self.scripts = scripts
    def propose(self, prompt, ckpt):
        ckpt.validate(); rnd = random.Random(ckpt.seed ^ int(hashlib.sha256(prompt.encode()).hexdigest()[:8], 16)); return self.scripts[rnd.randrange(len(self.scripts))]


def run_l3(runner: ModelRunner, prompts: list, ckpt: Checkpoint) -> dict:
    ckpt.validate()
    try: outs = [runner.propose(p, ckpt) for p in prompts]
    except NotAvailable as e: return {"layer": "L3", "status": "NOT_RUN", "reason": str(e), "checkpoint": asdict(ckpt)}
    kind = "scripted_stub" if isinstance(runner, ScriptedRunner) else "live"
    return {"layer": "L3", "status": "RAN", "runner_kind": kind, "evidence_grade": "plumbing_only" if kind == "scripted_stub" else "model_behavior", "checkpoint": asdict(ckpt), "outputs": [{"prompt_sha256": hashlib.sha256(p.encode()).hexdigest(), "output_sha256": hashlib.sha256(o.encode()).hexdigest()} for p, o in zip(prompts, outs)]}
