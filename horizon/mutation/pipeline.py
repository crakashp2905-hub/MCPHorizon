"""Deterministic generation pipeline with provenance (P43-08), oracle validation (P43-09), dedup (P43-10), family splits (P43-11), matched pairs (P43-12), baseline generators (P43-13), and failure accounting (P43-14)."""
from __future__ import annotations
import hashlib, os, random
from . import ir, seeds as SD, operators as OP
from .oracle import Oracle

PIPELINE_VERSION = "p43-1"
GUARDRAILS = {"destinations": "loopback receivers only (127.0.0.1)", "payload": "synthetic canary TEST_CANARY_NOT_SECRET and fixed note text only", "max_nodes": ir.MAX_NODES, "operators": "closed whitelist (horizon.mutation.operators.OPERATORS)", "ops": "closed whitelist of source/transform ops", "network": "no third-party hosts; redirects off loopback refused by the opener"}


def code_digest():
    root = os.path.dirname(os.path.abspath(__file__)); return ir.digest({f: hashlib.sha256(open(os.path.join(root, f), "rb").read()).hexdigest() for f in ("ir.py", "oracle.py", "operators.py", "seeds.py", "detectors.py", "pipeline.py")})


def mk(graph, parent, step, root, rng_seed, idx):
    g = ir.clone(graph); g["id"] = "M%04d-%s" % (idx, ir.digest(graph)[:6]); g["family"] = root["family"]; g["twin_of"] = None
    prov = list(parent.get("provenance", [])) + ([step] if step else [])
    return {"id": g["id"], "graph": g, "family": root["family"], "root": root["id"], "seed": rng_seed, "provenance": prov, "parent": parent["id"] if step else None}


def step_rec(op, params, predicted, parent_graph): return {"operator": op.id, "kind": op.kind, "params": params, "predicted": predicted, "confidence": op.confidence, "parent_digest": ir.digest(parent_graph)}


def expand(parent, root, idx, rng_seed, out, rejected, op_filter=None):
    """All preconditioned one-step mutants of `parent`. Preconditions = enumerator + hard feasibility; a failing candidate is counted, never emitted."""
    for op in OP.OPERATORS:
        if op_filter and op.id not in op_filter: continue
        for p in op.enumerate_params(parent["graph"]):
            pred = op.predict(parent["graph"], p); g2 = op.apply(parent["graph"], p)
            if ir.feasibility(g2): rejected.append({"operator": op.id, "reason": ir.feasibility(g2)[0]}); continue
            if ir.digest({k: v for k, v in g2.items() if k not in ("id", "twin_of", "tag")}) == ir.digest({k: v for k, v in parent["graph"].items() if k not in ("id", "twin_of", "tag")}): continue
            idx[0] += 1; out.append(mk(g2, parent, step_rec(op, p, pred, parent["graph"]), root, rng_seed, idx[0]))


def generate(rng_seed=43, depth2=160) -> dict:
    """Deterministic: same seed + same code => identical mutants and provenance."""
    rng = random.Random(rng_seed); S = SD.seeds(); idx = [0]; rejected = []
    roots = [{"id": g["id"], "graph": g, "family": g["family"], "provenance": []} for g in S]; d1 = []
    for r in roots: expand(r, r, idx, rng_seed, d1, rejected)
    pool = list(d1); rng.shuffle(pool); d2 = []
    for m in pool[:depth2 // 4]:
        root = next(r for r in roots if r["id"] == m["root"]); tmp = []; expand(m, root, idx, rng_seed, tmp, rejected); rng.shuffle(tmp); d2 += tmp[:4]
    return {"seed": rng_seed, "roots": roots, "mutants": d1 + d2, "rejected_by_preconditions": rejected, "depth1": len(d1), "depth2": len(d2)}


# ---- baselines (P43-13) -----------------------------------------------------------------------------------------------------------------------------------------------------------------
def lexical_baseline(rng_seed=43, n=80) -> list:
    """Fixed attacks + lexical perturbation of the payload text only (no graph change). Scripted."""
    rng = random.Random(rng_seed); out = []; S = SD.seeds(); idx = 0
    for i in range(n):
        base = rng.choice(S); g = ir.clone(base); idx += 1
        for s in ir.sinks(g): s["prefix"] = rng.choice(["", " ", "note: ", "DATA=", "x" * rng.randint(1, 8)])
        g["id"] = "L%04d" % idx; out.append({"id": g["id"], "graph": g, "family": g["family"], "root": base["id"], "provenance": [{"operator": "LEXICAL", "predicted": "SAME", "kind": "lexical"}], "parent": None})
    return out


def random_baseline(rng_seed=43, n=160) -> list:
    """Unconstrained scripted-random generator. NOT a language model: a stand-in for 'generate without preconditions', so invalid and semantics-changing edits are possible. A live-LLM generator was not run."""
    rng = random.Random(rng_seed); out = []; S = SD.seeds(); idx = 0
    for i in range(n):
        base = rng.choice(S); g = ir.clone(base); kinds = []
        for _ in range(rng.choice([1, 2])):
            k = rng.choice(["dest", "principal", "t", "rewire", "op", "protocol", "drop", "flag"]); kinds.append(k); n_ = rng.choice(g["nodes"])
            if k == "dest" and n_["type"] == "sink": n_["dest"] = rng.choice(list(ir.DESTS) + ["WAN"])
            elif k == "principal": n_["principal"] = rng.choice(list(g["principals"]) + ["ghost"])
            elif k == "t": n_["t"] = rng.choice([-1, 0, 1, 2, 5, 9, 50])
            elif k == "rewire" and n_.get("inputs"): n_["inputs"] = [rng.choice([m["id"] for m in g["nodes"]] + ["zz"])]
            elif k == "op" and n_["type"] == "transform": n_["op"] = rng.choice(list(ir.TRANSFORM_OPS) + ["rot47"])
            elif k == "protocol" and n_["type"] == "sink": n_["protocol"] = rng.choice(list(ir.PROTOCOLS) + ["smtp"])
            elif k == "drop" and len(g["nodes"]) > 2: g["nodes"].remove(n_)
            elif k == "flag" and g["flags"]: kk = rng.choice(list(g["flags"])); g["flags"][kk] = rng.choice(["int", "ext", "other"])
        idx += 1; g["id"] = "R%04d" % idx
        out.append({"id": g["id"], "graph": g, "family": base["family"], "root": base["id"], "provenance": [{"operator": "RANDOM", "predicted": "CHANGE" if "dest" in kinds or "principal" in kinds else "SAME", "kind": "random:" + "+".join(kinds)}], "parent": None})
    return out


# ---- labeling, dedup, splits ------------------------------------------------------------------------------------------------------------------------------------------------------------
def label(oracle: Oracle, items: list) -> list:
    for m in items: m["oracle"] = oracle.judge(m["graph"])
    return items


def effect_signature(m) -> str:
    """Semantic effect path: per executing sink (dest, transform chain sans identity, approval temporal class, authority tier of the actor) + the verdict. Protocol, ids, timing detail and node names do not matter."""
    from .oracle import approval_state, grants
    from .detectors import chain
    g = m["graph"]; ex = ir.feasibility(g)
    if ex: return "INVALID:" + ex[0]
    parts = sorted((s["dest"], chain(g, s["id"]), approval_state(g, s), s["dest"] in grants(g, s["principal"]), approval_state(g, {**s, "t": s.get("t_decide", s["t"])})) for s in ir.executing(g) if s["type"] == "sink")
    return ir.digest([parts, m["oracle"]["V"], m["oracle"]["status"]])


def features(m) -> set:
    g = m["graph"]; f = {"t:" + n["type"] + ":" + n.get("op", "send") for n in ir.executing(g)}
    f |= {"s:%s:%s:%s" % (n["dest"], n["protocol"], "delayed" if n.get("t_decide", n["t"]) != n["t"] else "direct") for n in ir.executing(g) if n["type"] == "sink"}; f |= {"e:%s>%s" % (ir.node(g, i)["type"], n["type"]) for n in ir.executing(g) for i in n.get("inputs", [])}
    f.add("n:%d" % len(ir.executing(g))); f.add("fam:" + m["family"]); return f


def dedup(items, sim=0.9) -> dict:
    keep, exact, near, seen = [], 0, 0, {}
    for m in items:
        sig = effect_signature(m)
        if sig in seen: exact += 1; continue
        f = features(m); dup = False
        for k in keep:
            if k["oracle"]["V"] == m["oracle"]["V"] and k["family"] == m["family"] and len(f & features(k)) / len(f | features(k)) >= sim: dup = True; break
        if dup: near += 1; continue
        seen[sig] = m["id"]; keep.append(m)
    return {"kept": keep, "exact_duplicates": exact, "near_duplicates": near, "input": len(items)}


def split_by_family(items) -> dict:
    return {"dev": [m for m in items if m["family"] in SD.DEV_FAMILIES], "test": [m for m in items if m["family"] in SD.TEST_FAMILIES]}


def split_random(items, rng_seed=43) -> dict:
    rng = random.Random(rng_seed); xs = list(items); rng.shuffle(xs); h = len(xs) // 2; return {"dev": xs[:h], "test": xs[h:]}


# ---- matched pairs ----------------------------------------------------------------------------------------------------------------------------------------------------------------------
def tool_multiset(g): return sorted(ir.TOOL[n["type"]] for n in ir.executing(g))


def matched_pairs(oracle: Oracle, mutants) -> list:
    """For each oracle-confirmed violating mutant find a twin with the SAME tool names and a different ground truth, reached by a single node-set-preserving edit."""
    pairs = []
    for m in mutants:
        if m["oracle"]["status"] != "OK" or not m["oracle"]["V"]: continue
        for opid in ("OP-DEST-CHANGE", "OP-BRANCH-FLIP", "OP-APPROVAL-TTL", "OP-TEMPORAL-DELAY"):
            op = OP.BY_ID[opid]; found = None
            for p in op.enumerate_params(m["graph"]):
                g2 = op.apply(m["graph"], p)
                if ir.feasibility(g2) or tool_multiset(g2) != tool_multiset(m["graph"]): continue
                j = oracle.judge(g2)
                if j["status"] == "OK" and j["V"] is False: found = (g2, p, j); break
            if found: pairs.append({"attack": m["id"], "benign_graph": found[0], "edit": {"operator": opid, "params": found[1]}, "attack_V": True, "benign_V": False, "tools": tool_multiset(m["graph"])}); break
    return pairs


def release_manifest(rng_seed=43, depth2=160) -> dict:
    """P43-16: reproducible, guard-railed manifest. Regenerates everything from the seed and re-labels with a fresh oracle; two runs must give identical bytes."""
    G = generate(rng_seed, depth2)
    with Oracle() as o: label(o, G["roots"]); label(o, G["mutants"])
    items = [{"id": m["id"], "graph_digest": ir.digest(m["graph"]), "family": m["family"], "root": m["root"], "parent": m["parent"], "provenance": [{k: v for k, v in p.items()} for p in m["provenance"]], "status": m["oracle"]["status"], "V": m["oracle"]["V"]} for m in G["mutants"]]
    body = {"pipeline_version": PIPELINE_VERSION, "rng_seed": rng_seed, "depth2": depth2, "guardrails": GUARDRAILS, "operators_digest": OP.operators_digest(), "seeds_digest": ir.digest(SD.seeds()), "roots": [{"id": r["id"], "graph_digest": ir.digest(r["graph"]), "status": r["oracle"]["status"], "V": r["oracle"]["V"]} for r in G["roots"]], "mutants": items}
    body["manifest_digest"] = ir.digest(body); return body
