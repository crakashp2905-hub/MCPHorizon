"""Case-level evaluation on InjecAgent (MIT; 1,054 base + 1,054 enhanced cases).
Each case = (benign user tool call + user instruction) + (attacker tool + attacker instruction injected via the tool response).
No agent trajectory is recorded, so this is a STATIC rule check, not a replay:
  attack side : would the rule block the attacker's tool call?
  benign side : would the rule block the user's own tool call?
Limits: attacker arguments are not given, only the attacker instruction text; provenance is therefore judged
from identifier-like tokens in that text.  `scope_user_tool` blocks every attacker by construction (attacker tool
never equals user tool; checked) and is reported only as a degenerate reference."""
import ast, json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from bench.real import agentdojo as A

FILES = {"dh_base": "test_cases_dh_base.json", "ds_base": "test_cases_ds_base.json",
         "dh_enhanced": "test_cases_dh_enhanced.json", "ds_enhanced": "test_cases_ds_enhanced.json"}
IDENT = re.compile(r"[@./_\-0-9]")


def ident_tokens(text):
    out = set()
    for tok in re.split(r"\s+", str(text).lower()):
        tok = re.sub(r"^https?://", "", tok.strip(".,;:()[]'\"!?"))
        if len(tok) >= 4 and IDENT.search(tok):
            out.add(tok)
    return out


def user_param_values(case):
    try:
        d = ast.literal_eval(case["Tool Parameters"])
    except (ValueError, SyntaxError):
        return []
    return [str(v) for v in A.string_leaves(d)] + [str(v) for v in d.values() if isinstance(v, (int, float))] if isinstance(d, dict) else []


def provenance_blocks_attack(case):
    """Block iff the attacker instruction carries an identifier-like token the user never wrote."""
    up = str(case["User Instruction"]).lower()
    return any(t not in up for t in ident_tokens(case["Attacker Instruction"]))


def provenance_blocks_benign(case):
    up = str(case["User Instruction"]).lower()
    return any(t not in up for v in user_param_values(case) for t in ident_tokens(v))


def evaluate(cases):
    res = {}
    for name, rows in cases.items():
        n = len(rows)
        atk = sum(1 for c in rows if provenance_blocks_attack(c))
        ben = sum(1 for c in rows if provenance_blocks_benign(c))
        same = sum(1 for c in rows if c["User Tool"] in c["Attacker Tools"])
        res[name] = {"n": n, "provenance_attack_blocked": A._rate(atk, n), "provenance_false_block_user_call": A._rate(ben, n),
                     "attacker_tool_equals_user_tool": same}
    return res


def load(root):
    out = {}
    for k, fn in FILES.items():
        with open(os.path.join(root, "data", fn), encoding="utf-8") as f:
            out[k] = json.load(f)
    return out


if __name__ == "__main__":
    root = sys.argv[sys.argv.index("--root") + 1]
    res = evaluate(load(root))
    os.makedirs("bench/real/results", exist_ok=True)
    with open("bench/real/results/injecagent_results.json", "w") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    for k, v in res.items():
        a, b = v["provenance_attack_blocked"], v["provenance_false_block_user_call"]
        print(f"{k:12s} n={v['n']} attack blocked {a['rate']:.3f} [{a['ci95'][0]:.3f},{a['ci95'][1]:.3f}]  user-call false block {b['rate']:.3f}  same-tool={v['attacker_tool_equals_user_tool']}")
