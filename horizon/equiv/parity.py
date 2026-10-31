"""Workflow generator, metamorphic/non-equivalent transforms and the parity runner (P14-06..10, 13, 14)."""
from __future__ import annotations
import itertools, json, random
from . import effects as F
from .rig import Rig, ENDPOINTS

PATHS = ("mcp_modern", "mcp_legacy", "utcp", "code_mode")
EP_OF = {v: k for k, v in ENDPOINTS.items()}
OPS = ("read", "send", "delete")


def policy(body) -> dict:
    """Shared decision function: verdict depends ONLY on (effect, canonical target) — never on protocol — so a verdict difference is a gate bug."""
    from horizon import normalize as N
    t = N.canonical_target(body["target"]["kind"], body["target"]["raw"])["canonical_id"]; e = body["effect"]
    ok = e == "read" or (e == "send" and t == ENDPOINTS["notes"])
    return {"verdict": "ALLOW" if ok else ("REVIEW" if e == "send" else "DENY"), "decision_id": "d", "reason_codes": [] if ok else ["POLICY"]}


def generate(seed: int, n: int = 40) -> list:
    """Declarative workflows: [{id, principal, steps:[{op, ep, text}]}]. Deterministic in seed."""
    r = random.Random(seed); out = []
    for i in range(n):
        steps = [{"op": r.choice(OPS), "ep": r.choice(list(ENDPOINTS)), "text": f"t{r.randrange(5)}"} for _ in range(r.randint(1, 3))]
        out.append({"id": f"w{seed}-{i}", "principal": r.choice(["agent-a", "agent-b"]), "steps": steps})
    return out


def run_path(wf, path, *, mcp_codec=None) -> dict:
    rig = Rig(policy, mcp_codec="legacy" if path == "mcp_legacy" else "modern"); verdicts = []; p = wf["principal"]
    for st in wf["steps"]:
        url = ENDPOINTS[st["ep"]]; text = st["text"] if st["op"] == "send" else None
        if path.startswith("mcp"): tool = {"read": "fetch", "send": "publish", "delete": "remove"}[st["op"]]; a = {"url": url}; a.update({"text": text} if text is not None else {}); ok, v = rig.mcp_call(p, tool, a)
        elif path == "utcp": ok, v = rig.utcp_call(p, {"read": "get_", "send": "post_", "delete": "del_"}[st["op"]] + st["ep"], {"text": text} if text is not None else {})
        else: ok, v = rig.cm_run(p, [({"read": "cm_get", "send": "cm_post", "delete": "cm_delete"}[st["op"]], url, text)])[0]
        verdicts.append("ALLOW" if ok else (v or "UNKNOWN"))
    return {"verdicts": verdicts, "effects": rig.effects(p, "T1", path, 0)}


def compare(wf) -> list:
    """Return discrepancy records between every path and the reference (mcp_modern)."""
    res = {p: run_path(wf, p) for p in PATHS}; ref = res["mcp_modern"]; out = []
    for p in PATHS[1:]:
        r = res[p]
        if r["verdicts"] != ref["verdicts"]: out.append({"wf": wf["id"], "path": p, "cls": "VERDICT", "ref": ref["verdicts"], "got": r["verdicts"]})
        if len(r["effects"]) == len(ref["effects"]):
            for a, b in zip(ref["effects"], r["effects"]):
                if not F.equivalent(a, b):
                    cls = "PAYLOAD_ENCODING" if (a.kind, a.target) == (b.kind, b.target) and a.payload != b.payload else "EFFECT"; out.append({"wf": wf["id"], "path": p, "cls": cls, "ref": a.payload, "got": b.payload}); break
        else: out.append({"wf": wf["id"], "path": p, "cls": "EFFECT_COUNT", "ref": len(ref["effects"]), "got": len(r["effects"])})
    return out


# ---- metamorphic transforms: semantics-preserving rewrites that must NOT create new discrepancies
def t_url_spelling(url): return url.replace("api.example.com", "API.Example.COM:443").replace("/v1/notes", "/b/../v1/notes") if "api.example.com" in url else url
def t_arg_order(a): return dict(reversed(list(a.items())))


def metamorphic_mcp(seed=0, n=20) -> list:
    """MCP/CM accept caller-supplied URLs: alternate spellings of the SAME target must yield identical verdict and effect."""
    bad = []
    for wf in generate(seed, n):
        st = wf["steps"][0]; url = ENDPOINTS[st["ep"]]; p = wf["principal"]
        for v in (url, t_url_spelling(url)):
            pass
        base = Rig(policy); alt = Rig(policy); tool = {"read": "fetch", "send": "publish", "delete": "remove"}[st["op"]]
        a = {"url": url}; b = {"url": t_url_spelling(url)}
        if st["op"] == "send": a["text"] = b["text"] = st["text"]
        r1 = base.mcp_call(p, tool, a); r2 = alt.mcp_call(p, tool, t_arg_order(b))
        e1, e2 = base.effects(p, "T1", "m", 0), alt.effects(p, "T1", "m", 0)
        if r1 != r2 or not F.sequence_equivalent(e1, e2): bad.append({"wf": wf["id"], "r1": r1, "r2": r2})
    return bad


# ---- intentionally non-equivalent fixtures (P14-08): the checker MUST flag these, else it is vacuous
def non_equivalent_fixtures() -> list:
    mk = lambda **k: F.make(k.pop("kind", "send"), "url", k.pop("url", ENDPOINTS["notes"]), principal=k.pop("principal", "a"), tenant=k.pop("tenant", "T1"), **k)
    base = mk(payload="x")
    return [("payload", base, mk(payload="y")), ("target", base, mk(payload="x", url=ENDPOINTS["alerts"])), ("host", base, mk(payload="x", url=ENDPOINTS["other"])),
            ("kind", base, mk(payload="x", kind="write")), ("principal", base, mk(payload="x", principal="b")), ("tenant", base, mk(payload="x", tenant="T2")),
            ("verdict", base, mk(payload="x", verdict="DENY"))]


# ---- hidden authorization change (P14-09): a spelling that LOOKS like the allowed target but canonicalizes to another
def alias_traps() -> list:
    return [("dotdot_to_alerts", ENDPOINTS["notes"] + "/../alerts"), ("userinfo", "https://api.example.com@other.example.org/v1/notes"),
            ("suffix_host", "https://api.example.com.evil.test/v1/notes"), ("backslash", "https://api.example.com\\@other.example.org/v1/notes")]


def trap_results() -> list:
    out = []
    for name, url in alias_traps():
        r = Rig(policy)
        try: ok, v = r.mcp_call("agent-a", "publish", {"url": url, "text": "x"}); out.append({"trap": name, "allowed": ok, "observed": [o["url"] for o in r.observed]})
        except Exception as e: out.append({"trap": name, "allowed": False, "observed": [], "rejected": type(e).__name__})
    return out


def matrix(wfs) -> dict:
    """Per-protocol coverage: which ops/endpoints each path actually exercised, and which are UNSUPPORTED (never silently equivalent)."""
    cov = {p: {"verdict_agree": 0, "effect_agree": 0, "total": 0} for p in PATHS[1:]}; disc = []
    for wf in wfs:
        d = compare(wf); disc += d
        for p in PATHS[1:]:
            cov[p]["total"] += 1; cov[p]["verdict_agree"] += not any(x["path"] == p and x["cls"] == "VERDICT" for x in d); cov[p]["effect_agree"] += not any(x["path"] == p and x["cls"].startswith("EFFECT") or (x["path"] == p and x["cls"] == "PAYLOAD_ENCODING") for x in d)
    return {"coverage": cov, "discrepancies": disc, "unsupported": ["admin", "receive", "cli", "websocket", "streaming", "legacy utcp spec versions"]}
