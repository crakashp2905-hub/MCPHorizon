"""Signed grants, delegation service, chain verifier, revocation, audit schema (P15-01,03,04,06,07,08,11)."""
from __future__ import annotations
import base64, json, secrets, time
from horizon.authz.keys import TrustError
from . import authority as A

DOMAIN = b"mcphorizon.grant.v1\x00"
MAX_DEPTH = 4
ROOT_ISSUER, DELEG_ISSUER = "root", "delegator"
FIELDS = {"v", "id", "iss", "tenant", "sub", "aud", "parents", "depth", "auth", "iat", "reason"}


class GrantError(Exception):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


def _canon(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def _b(x: bytes) -> str: return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
def _ub(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def seal(signer, grant: dict) -> dict:
    if set(grant) != FIELDS: raise GrantError("MALFORMED", "grant fields")
    return {"grant": grant, "kid": signer.kid, "sig": _b(signer.sign(DOMAIN + _canon(grant)))}


def open_env(env, trust, expect_iss: str) -> dict:
    """Signature + issuer-role check. A delegated grant signed with the root key is as invalid as a root grant signed by the delegator."""
    try:
        g, kid, sig = env["grant"], env["kid"], env["sig"]
        if not isinstance(g, dict) or set(g) != FIELDS or g["v"] != 1: raise GrantError("MALFORMED")
        if g["iss"] != expect_iss: raise GrantError("WRONG_ISSUER", f"{g['iss']} != {expect_iss}")
        trust.resolve(kid, expect_iss).verify(_ub(sig), DOMAIN + _canon(g))
    except GrantError: raise
    except TrustError as e: raise GrantError("UNTRUSTED_KEY", e.code) from None
    except Exception: raise GrantError("BAD_SIGNATURE") from None
    return g


class Revocations:
    def __init__(self): self.ids, self.epoch = set(), 0
    def revoke(self, gid): self.ids.add(gid); self.epoch += 1


def issue_root(root_signer, *, tenant, sub, aud, auth: A.Authority, now=None, origin="issuer-channel", reason="root grant") -> dict:
    """Only the trusted issuer channel may mint root authority; agent/tool-output origins are refused (P15-04)."""
    if origin != "issuer-channel": raise GrantError("UNTRUSTED_ORIGIN", f"root grants cannot come from {origin}")
    return seal(root_signer, {"v": 1, "id": "g-" + secrets.token_hex(8), "iss": ROOT_ISSUER, "tenant": tenant, "sub": sub, "aud": aud, "parents": [], "depth": 0, "auth": auth.to_json(), "iat": int(now if now is not None else time.time()), "reason": reason})


class Verifier:
    def __init__(self, trust, *, audience: str, rev: Revocations | None = None, clock=time.time, max_depth=MAX_DEPTH):
        self.trust, self.aud, self.rev, self.clock, self.max_depth, self._cache = trust, audience, rev or Revocations(), clock, max_depth, {}

    def effective(self, envs: list, leaf_id: str, *, tenant: str) -> A.Authority:
        """envs: all envelopes in the (possibly multi-parent) chain. Re-derives every hop from signatures; trusts nothing precomputed."""
        key = (leaf_id, self.rev.epoch, int(self.clock()), tenant, tuple(sorted(e["sig"] for e in envs)))
        if key in self._cache: return self._cache[key]
        byid = {}
        for e in envs:
            g = e["grant"]; 
            if not isinstance(g, dict) or "id" not in g: raise GrantError("MALFORMED")
            if g["id"] in byid: raise GrantError("DUPLICATE_ID")
            byid[g["id"]] = e
        seen, now = {}, int(self.clock())
        def walk(gid, stack):
            if gid in stack: raise GrantError("CYCLE")
            if gid in seen: return seen[gid]
            e = byid.get(gid)
            if e is None: raise GrantError("MISSING_PARENT", gid)
            g = e["grant"]; g = open_env(e, self.trust, ROOT_ISSUER if not g.get("parents") else DELEG_ISSUER)
            if g["id"] in self.rev.ids: raise GrantError("REVOKED", gid)
            if g["tenant"] != tenant: raise GrantError("TENANT_MISMATCH")
            if g["aud"] != self.aud: raise GrantError("AUDIENCE_MISMATCH")
            au = A.Authority.from_json(g["auth"])
            if not au.nbf <= now < au.exp: raise GrantError("EXPIRED_OR_NOT_YET", gid)
            if g["depth"] > self.max_depth: raise GrantError("DEPTH_EXCEEDED")
            if g["parents"]:
                ps = [walk(p, stack | {gid}) for p in g["parents"]]
                if g["depth"] != 1 + max(byid[p]["grant"]["depth"] for p in g["parents"]): raise GrantError("BAD_DEPTH")
                if any(byid[p]["grant"]["tenant"] != g["tenant"] for p in g["parents"]): raise GrantError("TENANT_MISMATCH")
                lim = ps[0]
                for p in ps[1:]: lim = A.intersect(lim, p)
                if not A.subset(au, lim): raise GrantError("AMPLIFICATION", f"{gid} exceeds parents")
            elif g["depth"] != 0: raise GrantError("BAD_DEPTH")
            seen[gid] = au; return au
        r = walk(leaf_id, frozenset()); self._cache[key] = r; return r

    def authorize(self, envs, leaf_id, *, principal, tenant, action, tool, resource, dest=None, args=None) -> dict:
        """Evaluated AT EFFECT TIME (jobs/callbacks included): expiry and revocation are checked now, not at enqueue time."""
        try:
            leaf = next(e["grant"] for e in envs if e["grant"].get("id") == leaf_id)
            if leaf["sub"] != principal: return {"allow": False, "code": "SUBJECT_MISMATCH"}
            au = self.effective(envs, leaf_id, tenant=tenant)
        except GrantError as e: return {"allow": False, "code": e.code}
        except (StopIteration, KeyError): return {"allow": False, "code": "MISSING_GRANT"}
        except A.AuthorityError as e: return {"allow": False, "code": e.code}
        why = A.permits(au, action=action, tool=tool, resource=resource, dest=dest, args=args or {}, now=int(self.clock()))
        return {"allow": why is None, "code": why or "OK", "grant": leaf_id}


class Delegator:
    """Protected service holding the delegation key. Mints child grants only for subsets; never accepts requests whose origin is untrusted tool output."""
    def __init__(self, signer, verifier: Verifier, audit=None): self.s, self.v, self.audit = signer, verifier, audit

    def delegate(self, envs: list, parent_ids: list, *, requester: str, child_sub: str, auth: A.Authority, origin="agent-runtime", reason="delegation") -> dict:
        if origin in ("tool-output", "model-text", "untrusted"): raise GrantError("UNTRUSTED_ORIGIN", origin)
        if not parent_ids: raise GrantError("NO_PARENT")
        pe = [e for e in envs if e["grant"]["id"] in parent_ids]
        if len(pe) != len(set(parent_ids)): raise GrantError("MISSING_PARENT")
        tenant = pe[0]["grant"]["tenant"]
        if any(e["grant"]["sub"] != requester for e in pe): raise GrantError("REQUESTER_NOT_HOLDER", "only the holder of a grant may delegate it")
        lim = None
        for pid in parent_ids:
            a = self.v.effective(envs, pid, tenant=tenant); lim = a if lim is None else A.intersect(lim, a)
        if not A.subset(auth, lim): raise GrantError("AMPLIFICATION")
        depth = 1 + max(e["grant"]["depth"] for e in pe)
        if depth > self.v.max_depth: raise GrantError("DEPTH_EXCEEDED")
        env = seal(self.s, {"v": 1, "id": "g-" + secrets.token_hex(8), "iss": DELEG_ISSUER, "tenant": tenant, "sub": child_sub, "aud": pe[0]["grant"]["aud"], "parents": sorted(parent_ids), "depth": depth, "auth": auth.to_json(), "iat": int(self.v.clock()), "reason": reason})
        if self.audit: self.audit.record(kind="delegation", authorization={"grant": env["grant"]["id"], "parents": sorted(parent_ids)}, attribution=[requester])
        return env


class AuditSchema:
    """P15-07: causal ATTRIBUTION (who/what run caused it) is stored separately from AUTHORIZATION (which grant allowed it). Authorization never reads attribution."""
    def __init__(self): self.rows = []
    def record(self, *, kind, authorization: dict | None, attribution: list, effect=None):
        if not isinstance(attribution, list) or not all(isinstance(x, str) for x in attribution): raise GrantError("MALFORMED")
        if kind in ("effect", "delegation") and not (authorization and authorization.get("grant")): raise GrantError("NO_AUTHORIZATION", "an effect must cite the grant that authorized it; attribution alone is not authority")
        self.rows.append({"kind": kind, "authorization": authorization, "attribution": attribution, "effect": effect})
