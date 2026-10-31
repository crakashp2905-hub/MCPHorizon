"""P15-12: deliberately WRONG verifiers, to show the traces that the correct one prevents. Never imported by production code."""
from . import authority as A, grants as G


class UnionVerifier(G.Verifier):
    """Bug: multi-parent child bounded by the UNION of parents' authority instead of the intersection."""
    def effective(self, envs, leaf_id, *, tenant):
        g = next(e["grant"] for e in envs if e["grant"]["id"] == leaf_id); au = A.Authority.from_json(g["auth"])
        ps = [A.Authority.from_json(e["grant"]["auth"]) for e in envs if e["grant"]["id"] in g["parents"]]
        if ps:
            u = A.Authority(frozenset().union(*(p.actions for p in ps)), None, None, None, (), 0, 2 ** 31)
            if not (au.actions <= u.actions): raise G.GrantError("AMPLIFICATION")
        return au


class NoAudienceVerifier(G.Verifier):
    """Bug: grant minted for another gateway is accepted here."""
    def __init__(self, *a, **k): super().__init__(*a, **k); self.aud = None
    def effective(self, envs, leaf_id, *, tenant):
        for e in envs: e["grant"]["aud"] = e["grant"]["aud"]
        orig = G.Verifier.effective
        import copy; es = copy.deepcopy(envs)
        for e in es: pass
        try: return orig(self, envs, leaf_id, tenant=tenant)
        except G.GrantError as ex:
            if ex.code == "AUDIENCE_MISMATCH": return A.Authority.from_json(next(e["grant"] for e in envs if e["grant"]["id"] == leaf_id)["auth"])
            raise
