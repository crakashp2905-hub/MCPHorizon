"""Real-model weight-space patch experiment (RESEARCH, CANDIDATE; author-run, exploratory, n=1 model).
Model: Qwen2.5-0.5B-Instruct (Apache-2.0), tied embeddings.  Gradient-FREE closed-form edit of ONE embedding row
(= that token's lm_head row) so the token's logit rises by DELTA on ONE prompt, under the patch.py budget.
Controls: random edits with the SAME number of entries and SAME delta L2 (5 seeds).  Collateral: logit shift of the
same token on held-out prompts, top-1 flips, NLL change on held-out text.  All edits go through patch.py
(validate -> apply -> manifest -> verify_manifest -> inverse).  No optimizer framework is used."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import numpy as np, torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from research.weightspace import patch as P

MD = sys.argv[sys.argv.index("--model") + 1]
OUT = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else "research/weightspace/results/real_qwen05.json"
torch.set_num_threads(2); np.random.seed(0)
tok = AutoTokenizer.from_pretrained(MD)
model = AutoModelForCausalLM.from_pretrained(MD, torch_dtype=torch.float32).eval()
EMB = "model.embed_tokens.weight"
W = model.get_input_embeddings().weight
base_emb = W.detach().clone().numpy()
ckpt = {EMB: base_emb}
D = base_emb.shape[1]
TARGET_PROMPT, TARGET_TOKEN = "The capital of France is", " Rome"
HELD = ["The capital of Italy is", "I went to the market and bought some", "Water boils at a temperature of", "The largest planet in the solar system is",
        "In 1969, humans first landed on the", "def add(a, b):\n    return", "Once upon a time there was a", "The chemical symbol for gold is"]
TEXT = ["The quick brown fox jumps over the lazy dog near the river bank.", "Photosynthesis converts light energy into chemical energy stored in glucose.",
        "The committee will meet on Tuesday to discuss the annual budget.", "Machine learning models are trained on large datasets of examples."]
tid = tok(TARGET_TOKEN, add_special_tokens=False)["input_ids"]; assert len(tid) == 1; tid = tid[0]
MAXE, DELTA = 64, 5.0

@torch.no_grad()
def hl(prompt):
    o = model(**tok(prompt, return_tensors="pt"), output_hidden_states=True)
    return o.hidden_states[-1][0, -1].numpy().copy(), o.logits[0, -1].numpy().copy()

@torch.no_grad()
def nll(texts):
    tot = n = 0
    for t in texts:
        ids = tok(t, return_tensors="pt"); k = ids["input_ids"].shape[1] - 1; tot += model(**ids, labels=ids["input_ids"]).loss.item() * k; n += k
    return tot / n

@torch.no_grad()
def set_row(row): W[tid] = torch.from_numpy(np.ascontiguousarray(row))

h_t, lg_t = hl(TARGET_PROMPT)
base_held = {p: hl(p)[1] for p in HELD}
base_nll = nll(TEXT)
digest0 = P.checkpoint_digest(ckpt)
top = np.argsort(-np.abs(h_t))[:MAXE]
alpha = DELTA / float(np.abs(h_t[top]).sum())                     # d = alpha*sign(h) on top-|h| coords  =>  d.h = DELTA
targeted_delta = np.zeros(D, np.float32); targeted_delta[top] = alpha * np.sign(h_t[top])
L2 = float(np.linalg.norm(targeted_delta))

def proposal(delta, why):
    nz = np.nonzero(delta)[0]
    return {"base_digest": digest0, "hypothesis": why, "edits": [{"tensor": EMB, "index": int(tid * D + i), "value": float(base_emb[tid, i] + delta[i])} for i in nz]}

def trial(kind, delta):
    prop = proposal(delta, f"{kind}: raise logit of {TARGET_TOKEN!r} on {TARGET_PROMPT!r}")
    cand, man, inv = P.apply(ckpt, prop, max_entries=MAXE, max_l2=L2 * 1.0001, allowed_tensors={EMB})
    ok_manifest = P.verify_manifest(ckpt, cand, prop, man)
    set_row(cand[EMB][tid])
    _, lg = hl(TARGET_PROMPT)
    shifts, flips = [], 0
    for p in HELD:
        l = hl(p)[1]; b = base_held[p]; shifts.append(float(l[tid] - b[tid])); flips += int(np.argmax(l) != np.argmax(b))
    out = {"kind": kind, "entries": len(prop["edits"]), "delta_l2": man["delta_l2"], "manifest_verified": bool(ok_manifest),
           "target_logit_gain": float(lg[tid] - lg_t[tid]), "target_top1": bool(np.argmax(lg) == tid),
           "heldout_mean_logit_shift_same_token": float(np.mean(shifts)), "heldout_top1_flips": flips, "heldout_nll_delta": float(nll(TEXT) - base_nll)}
    # rollback via patch API inverse, then verify bit-exact on the live model AND at checkpoint level
    inv_prop = dict(inv); restored, _, _ = P.apply(cand, inv_prop, max_entries=MAXE, max_l2=1e9, allowed_tensors={EMB})
    out["inverse_restores_checkpoint_bit_exact"] = bool(np.array_equal(restored[EMB], base_emb))
    set_row(restored[EMB][tid]); out["live_model_rolled_back_bit_exact"] = bool(torch.equal(W[tid], torch.from_numpy(base_emb[tid])))
    return out

res = {"model": "Qwen/Qwen2.5-0.5B-Instruct", "target_prompt": TARGET_PROMPT, "target_token": TARGET_TOKEN, "budget_entries": MAXE, "requested_logit_gain": DELTA,
       "base_target_logit": float(lg_t[tid]), "base_target_rank": int((lg_t > lg_t[tid]).sum()), "base_heldout_nll": base_nll, "base_ckpt_digest": digest0, "targeted_delta_l2": L2}
res["runs"] = [trial("targeted", targeted_delta)]
for s in range(5):
    rng = np.random.RandomState(s); idx = rng.choice(D, MAXE, replace=False); d = np.zeros(D, np.float32); d[idx] = rng.choice([-1.0, 1.0], MAXE) * (L2 / np.sqrt(MAXE))
    res["runs"].append(trial(f"random_seed{s}", d))
os.makedirs(os.path.dirname(OUT), exist_ok=True); json.dump(res, open(OUT, "w"), indent=1)
print({k: v for k, v in res.items() if k != "runs"})
for r in res["runs"]: print(r)
