"""Effect manifests, approval envelopes, org policy, the platform and the approval service (P48-01, 02, 03, 05, 06, 07).

A MANIFEST is the normalized effect of an action, derived by trusted code from platform state (never from agent prose): operation, resolved receivers with versions, resource digest and version, scope,
data classification, irreversibility, amount. An ENVELOPE is what an approver approves: exact fields plus optional bounds; the token carries only its digest."""
import hashlib, json
from ..hpolicy.authority import HorizonPolicy

BASE = 1_000_000
def canonical(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def digest(o) -> str: return "sha256:" + hashlib.sha256(canonical(o)).hexdigest()
CLASSES = ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET")


class Clock:
    def __init__(self): self.t = float(BASE)
    def __call__(self): return self.t
    def advance(self, s): self.t += s
    def now(self): return int(self.t)


POLICY = {"version": "pol-c1",
          "prohibitions": [{"id": "ORG1", "classification": ["SECRET"], "external": True}, {"id": "ORG2", "classification": ["CONFIDENTIAL"], "scope": ["public"]}],
          "authority": {"alice": 2, "bob": 1, "carol": 3, "dave": 2, "owen": 2},
          "rules": [{"id": "R1", "when": {"op": "publish", "scope": "public"}, "approvals": 1, "level": 2}, {"id": "R2", "when": {"op": "send", "external": True}, "approvals": 1, "level": 1},
                    {"id": "R3", "when": {"op": "payout"}, "approvals": 1, "level": 1}, {"id": "R4", "when": {"op": "payout", "amount_gt": 1000}, "approvals": 2, "level": 2}]}


def policy_digest(p=POLICY) -> str: return digest(p)[:23]


def matches(when, m):
    for k, v in when.items():
        if k == "amount_gt":
            if not (m.get("amount") is not None and m["amount"] > v): return False
        elif k == "external":
            if bool(m["external"]) != v: return False
        elif m.get(k) != v: return False
    return True


def requirement(m, p=POLICY):
    """-> {'approvals': n, 'level': L, 'rules': [...]} or None when no approval is needed."""
    hit = [r for r in p["rules"] if matches(r["when"], m)]
    return {"approvals": max(r["approvals"] for r in hit), "level": max(r["level"] for r in hit), "rules": [r["id"] for r in hit]} if hit else None


def prohibited(m, p=POLICY):
    out = []
    for r in p["prohibitions"]:
        if m["classification"] in r["classification"] and (("external" not in r) or bool(m["external"]) == r["external"]) and (("scope" not in r) or m["scope"] in r["scope"]): out.append(r["id"])
    return out


class Platform:
    """Artifact store, destination registry and effect sink. `effect_of` is the trusted normalizer; `commit` is the executor and writes the ground-truth sink journal with its own resolution code."""
    def __init__(self):
        self.artifacts = {}; self.dest = {}; self.sink = []; self.log = []
    def add_artifact(self, aid, content, cls="PUBLIC"): self.artifacts[aid] = {"content": content, "version": 1, "classification": cls}
    def add_dest(self, name, host, external): self.dest[name] = {"host": host, "version": 1, "external": external}
    def edit(self, aid, content, bump=True):
        a = self.artifacts[aid]; a["content"] = content
        if bump: a["version"] += 1
    def repoint(self, name, host, bump=True, external=None):
        d = self.dest[name]; d["host"] = host
        if external is not None: d["external"] = external
        if bump: d["version"] += 1
    def content_digest(self, aid): return "sha256:" + hashlib.sha256(self.artifacts[aid]["content"].encode()).hexdigest()[:32]
    def effect_of(self, action, tenant, task):
        op = action["op"]
        if op == "publish": names = [action["destination"]] + list(action.get("mirrors", [])); scope = action.get("audience", "internal"); res = self._res(action["artifact"]); cls = self.artifacts[action["artifact"]]["classification"]; irr = scope == "public"; amt = None
        elif op == "send": names = list(action["recipients"]) + list(action.get("cc", [])); scope = "private"; res = self._res(action["artifact"]); cls = self.artifacts[action["artifact"]]["classification"]; irr = True; amt = None
        else: names = [action["payee"]]; scope = "private"; res = {"id": action["payee"], "digest": None, "version": self.dest[action["payee"]]["version"]}; cls = "INTERNAL"; irr = True; amt = action["amount"]
        recv = sorted({(self.dest[n]["host"], self.dest[n]["version"], self.dest[n]["external"]) for n in names})
        return {"op": op, "receivers": [{"host": h, "version": v, "external": e} for h, v, e in recv], "resource": res, "scope": scope, "classification": cls, "irreversible": irr, "amount": amt, "external": any(e for _, _, e in recv), "count": len(recv), "tenant": tenant, "task": task}
    def _res(self, aid): a = self.artifacts[aid]; return {"id": aid, "digest": self.content_digest(aid), "version": a["version"]}
    def commit(self, action, ctx):
        op = action["op"]; recv = {}
        for n in ([action["destination"]] + list(action.get("mirrors", []))) if op == "publish" else (list(action["recipients"]) + list(action.get("cc", []))) if op == "send" else [action["payee"]]: recv[self.dest[n]["host"]] = self.dest[n]["external"]
        e = {"seq": len(self.sink), "op": op, "hosts": sorted(recv), "external": any(recv.values()), "tenant": ctx["tenant"], "task": ctx["task"], "agent": ctx["agent"], "req": ctx.get("req"), "t": ctx["t"], "policy": ctx["policy"], "scope": action.get("audience", "private") if op == "publish" else "private"}
        if op in ("publish", "send"): a = self.artifacts[action["artifact"]]; e.update(artifact=action["artifact"], content=self.content_digest(action["artifact"]), version=a["version"], classification=a["classification"])
        else: e.update(amount=action["amount"], classification="INTERNAL")
        e["irreversible"] = (op != "publish") or e["scope"] == "public"; self.sink.append(e); return e


def within(actual, env):
    """actual manifest vs envelope {'exact': manifest-subset, 'bounds': {...}}. Returns list of mismatching field names (empty = within)."""
    ex, bd = env["exact"], env.get("bounds", {}); bad = []
    for k in ("op", "scope", "classification", "irreversible", "resource", "tenant", "task"):
        if k in ex and actual[k] != ex[k]: bad.append(k)
    if "receiver_set" in bd:
        allowed = set(bd["receiver_set"]); hosts = [r["host"] for r in actual["receivers"]]
        if not set(hosts) <= allowed or len(hosts) > bd.get("max_receivers", len(allowed)): bad.append("receivers")
        vers = {r["host"]: r["version"] for r in ex.get("receivers", [])}
        if any(r["host"] in vers and vers[r["host"]] != r["version"] for r in actual["receivers"]): bad.append("receiver_versions")
    elif "receivers" in ex and actual["receivers"] != ex["receivers"]: bad.append("receivers")
    if "max_amount" in bd:
        if actual["amount"] is None or actual["amount"] > bd["max_amount"]: bad.append("amount")
    elif "amount" in ex and actual["amount"] != ex["amount"]: bad.append("amount")
    return bad


def envelope_of(m, bounds=None):
    ex = {k: m[k] for k in ("op", "receivers", "resource", "scope", "classification", "irreversible", "amount", "tenant", "task")}
    return {"exact": ex, "bounds": bounds or {}}


def derive_view(m, previous=None):
    """Read-only description derived from the trusted manifest (P48-02, 03). Unknown values are stated as unknown, not guessed."""
    L = []; f = {"op": m["op"], "irreversible": m["irreversible"], "scope": m["scope"], "classification": m["classification"], "receivers_hosts": [r["host"] for r in m["receivers"]], "resource_id": m["resource"]["id"], "resource_digest": m["resource"]["digest"], "amount": m["amount"]}
    L.append("ACTION: %s%s" % (m["op"], " — IRREVERSIBLE" if m["irreversible"] else " (reversible)"))
    L.append("RESOURCE: %s%s" % (m["resource"]["id"], " v%s %s" % (m["resource"]["version"], m["resource"]["digest"]) if m["resource"]["digest"] else ""))
    L.append("DATA CLASSIFICATION: %s" % m["classification"]); L.append("SCOPE: %s" % m["scope"])
    L.append("RECEIVERS (%d): %s" % (m["count"], "; ".join("%s [v%s, %s]" % (r["host"], r["version"], "EXTERNAL" if r["external"] else "internal") for r in m["receivers"])))
    if m["amount"] is not None: L.append("AMOUNT: %s" % m["amount"])
    unknown = [k for k, v in (("classification", m["classification"]), ("scope", m["scope"])) if v in (None, "UNKNOWN")]
    if unknown: L.append("UNKNOWN (not verified): " + ", ".join(unknown))
    diff = None
    if previous is not None:
        diff = []
        if previous["resource"] != m["resource"]: diff.append("resource changed: %s -> %s" % (previous["resource"]["digest"], m["resource"]["digest"]))
        ph, nh = {r["host"] for r in previous["receivers"]}, {r["host"] for r in m["receivers"]}
        for h in sorted(nh - ph): diff.append("receiver added: " + h)
        for h in sorted(ph - nh): diff.append("receiver removed: " + h)
        for k in ("scope", "classification", "amount", "irreversible"):
            if previous[k] != m[k]: diff.append("%s changed: %s -> %s" % (k, previous[k], m[k]))
        L.append("CHANGES SINCE LAST APPROVAL: " + ("; ".join(diff) if diff else "none")); f["diff"] = diff
    return {"fields": f, "text": "\n".join(L)}
