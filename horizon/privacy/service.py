"""Synthetic aggregate-query service (P45-04, 08, 09, 10). Two disjoint paths:

  DP path   (mode "dp")   authorize -> derive the ledger from the dataset (never from the caller) -> compute sensitivity from DATASET-DECLARED bounds -> reserve -> begin -> mechanism with request-keyed noise -> commit -> signed mechanism receipt.
  RAW path  (mode "raw")  authorization, purpose, minimum cell count and a differencing guard. No DP claim; nothing is charged. A row export needs a separate signed approval.  PUBLIC datasets need neither.

The two paths share no accounting code (P45-08). Every released answer is appended to `release_log` at the service boundary; the independent oracle reads that log, not the ledger.
"""
import base64, hashlib, json, threading, time
from ..authz.effect import canonical
from ..authz.keys import Signer
from ..hpolicy.authority import EvidenceError
from . import ledger as LG, mechanisms as MX, units as U

CAP = 1                       # rows per individual that may contribute to any query (adjacency = add/remove one individual)
DEPTS = ("eng", "ops", "fin", "hr", "legal")
OPS = {"==": lambda a, b: a == b, "<": lambda a, b: a < b, ">=": lambda a, b: a >= b}


class Dataset:
    def __init__(self, name, n=200, seed=1, public=False, bounds=None, min_cell=10, include_target=True):
        import random
        r = random.Random("%s:%d" % (name, seed)); self.name, self.public, self.min_cell = name, public, min_cell
        self.bounds = bounds or {"salary": (0, 200000), "age": (18, 80)}
        self.rows = [{"id": "p%04d" % i, "dept": r.choice(DEPTS), "age": r.randint(18, 70), "salary": r.randint(30000, 180000)} for i in range(n)]
        self.rows.append({"id": "target", "dept": "legal", "age": 79, "salary": 199999}) if include_target else None       # one unique individual for membership-inference experiments
    def match(self, where):
        out = []
        for r in self.rows:
            if all(OPS[op](r[col], val) for col, op, val in where): out.append(r)
        return out


def canon_query(q: dict) -> dict: return {k: q[k] for k in ("dataset", "agg", "column", "where", "mode", "eps", "delta", "mech") if k in q}


class Service:
    def __init__(self, datasets, ledger, verifier, secret=b"synthetic-service-secret", ttl=30.0, *, idempotent=True, derive_ledger=True, declared_bounds=True, diff_guard=True, min_cell_on=True):
        self.idempotent, self.derive_ledger, self.declared_bounds, self.diff_guard, self.min_cell_on, self._n = idempotent, derive_ledger, declared_bounds, diff_guard, min_cell_on, 0
        self.ds, self.led, self.v, self.secret, self.ttl = {d.name: d for d in datasets}, ledger, verifier, secret, ttl
        self.signer = Signer.generate("priv-svc", "privacy-service"); self.principals = {}; self.release_log = []; self.raw_sets = {}; self.access_log = []; self.lock = threading.Lock()
    def pub(self): return self.signer.public_raw()
    def add_principal(self, name, tenant, dp=(), raw=(), purposes=()): self.principals[name] = {"tenant": tenant, "dp": set(dp), "raw": set(raw), "purposes": set(purposes)}

    def _deny(self, why, **kw): return {"status": "DENY", "reason": why, **kw}
    def _log(self, **e):
        with self.lock: self.release_log.append({"t": time.time(), **e})

    def query(self, principal, q, ctx=None) -> dict:
        p = self.principals.get(principal)
        if p is None: return self._deny("UNKNOWN_PRINCIPAL")
        d = self.ds.get(q.get("dataset"))
        if d is None: return self._deny("UNKNOWN_DATASET")
        if self.derive_ledger and ctx is not None and ctx.get("ledger") not in (None, U.ledger_id(d.name)): return self._deny("LEDGER_MISMATCH")          # an agent cannot pick or omit the ledger it is charged to
        for col, op, val in q.get("where", []):
            if col not in ("dept", "age", "salary", "id") or op not in OPS: return self._deny("BAD_PREDICATE")
        if q.get("agg") not in ("count", "sum"): return self._deny("UNSUPPORTED_AGGREGATE")
        if q["agg"] == "sum" and q.get("column") not in ("salary", "age"): return self._deny("UNSUPPORTED_COLUMN")
        if self.declared_bounds and q.get("bounds") is not None and tuple(q["bounds"]) != tuple(d.bounds[q["column"]]): return self._deny("CALLER_BOUNDS_REJECTED")        # sensitivity comes from the dataset declaration
        mode = q.get("mode", "dp")
        if d.public: return self._raw(principal, p, d, q, public=True)
        if mode == "dp":
            if d.name not in p["dp"]: return self._deny("NOT_AUTHORIZED_DP")
            return self._dp(principal, p, d, q, ctx or {})
        if mode == "raw":
            if d.name not in p["raw"] or q.get("purpose") not in p["purposes"]: return self._deny("NOT_AUTHORIZED_RAW")
            return self._raw(principal, p, d, q)
        return self._deny("BAD_MODE")

    # ---- DP path ------------------------------------------------------------------------------------------------------------------------------------------------------
    def sensitivity(self, d, q):
        if q["agg"] == "count": return CAP
        lo, hi = (d.bounds[q["column"]] if self.declared_bounds or q.get("bounds") is None else q["bounds"]); return CAP * max(abs(lo), abs(hi))
    def _dp(self, principal, p, d, q, ctx):
        rid = q.get("request_id")
        if not rid: return self._deny("NO_REQUEST_ID")
        if not self.idempotent:
            with self.lock: self._n += 1; rid = "%s#%d" % (rid, self._n)          # ABLATION ONLY: every retry is a brand-new request (new charge, new noise)
        lid = U.ledger_id(d.name) if self.derive_ledger or not ctx.get("ledger") else ctx["ledger"]; sens = self.sensitivity(d, q); eps = str(q.get("eps", "0.25"))
        try:
            if float(eps) <= 0: return self._deny("BAD_EPS")
            charge = MX.gaussian_charge(eps, str(q["delta"]), sens) if q.get("mech") == "gaussian" else MX.laplace_charge(eps, sens)
        except (ValueError, KeyError) as e: return self._deny("BAD_MECHANISM_PARAMS: %s" % e)
        qd = LG.digest(canon_query({**q, "eps": eps}))
        r = self.led.reserve(lid, rid, qd, charge, principal, ctx.get("task", ""), p["tenant"], self.ttl)
        if not r["ok"]: return self._deny(r["reason"])
        if r.get("replayed") and r.get("answer") is not None: return {"status": "OK", "answer": r["answer"], "receipt": r["receipt"], "replayed": True, "charged": False}
        if not self.led.begin(lid, rid)["ok"]: return self._deny("NOT_STARTABLE")
        true = len(d.match(q.get("where", []))) if q["agg"] == "count" else sum(x[q["column"]] if not self.declared_bounds else min(max(x[q["column"]], d.bounds[q["column"]][0]), d.bounds[q["column"]][1]) for x in d.match(q.get("where", [])))
        st = MX.Stream(self.secret, rid)
        ans = true + (MX.discrete_laplace(st, float(eps), sens) if charge["mech"] == "laplace" else MX.gaussian(st, charge["sigma"]))
        if q.get("_fail_after_mechanism"): return {"status": "TIMEOUT", "leaked_answer": ans}          # test hook: the answer escaped (e.g. a log) but the caller saw a timeout
        rec = self._receipt(d, lid, rid, qd, charge, ans); c = self.led.commit(lid, rid, ans, rec)
        if not c["ok"]: return self._deny(c["reason"])
        self._log(kind="dp", principal=principal, dataset=d.name, request_id=rid, mech=charge["mech"], eps=charge["eps"], delta=charge["delta"], sens=charge["sens"], sigma=charge["sigma"], answer=ans, agg=q["agg"], where=q.get("where", []))
        return {"status": "OK", "answer": ans, "receipt": rec, "replayed": bool(c.get("replayed")), "charged": True}
    def _receipt(self, d, lid, rid, qd, charge, ans):
        body = canonical({"dataset": d.name, "ledger": lid, "request_id": rid, "qdigest": qd, "mech": charge["mech"], "eps": charge["eps"], "delta": charge["delta"], "sens": charge["sens"], "answer": ans})
        return base64.b64encode(body).decode() + "." + base64.b64encode(self.signer.sign(b"privacy.receipt.v1\x00" + body)).decode()

    # ---- RAW path ------------------------------------------------------------------------------------------------------------------------------------------------------
    def _raw(self, principal, p, d, q, public=False):
        rows = d.match(q.get("where", [])); ids = frozenset(r["id"] for r in rows)
        if not public:
            if self.min_cell_on and len(rows) < d.min_cell: return self._deny("MIN_CELL_COUNT", n=len(rows))
            if self.diff_guard:
                with self.lock:
                    for prev in self.raw_sets.setdefault(d.name, []):
                        delta_n = len(ids ^ prev)
                        if 0 < delta_n < d.min_cell: return self._deny("DIFFERENCING_RISK", n=delta_n)
        val = len(rows) if q["agg"] == "count" else sum(r[q["column"]] for r in rows)
        if not public:
            with self.lock: self.raw_sets.setdefault(d.name, []).append(ids)
        self._log(kind="public" if public else "raw", principal=principal, dataset=d.name, request_id=q.get("request_id"), answer=val, agg=q["agg"], where=q.get("where", []), n=len(rows))
        return {"status": "OK", "answer": val, "mode": "public" if public else "raw"}
    def export_rows(self, principal, dataset, purpose, approval_token):
        d = self.ds[dataset]
        try: ap = self.v.verify(approval_token, now=None)
        except EvidenceError as e: return self._deny("APPROVAL_" + e.code)
        if ap["kind"] != "APPROVAL" or ap["artifact"] != dataset or ap["principal"] != principal or ap["args_digest"] != LG.digest({"op": "export", "dataset": dataset, "purpose": purpose}):
            return self._deny("APPROVAL_NOT_BOUND_TO_THIS_EXPORT")
        self.access_log.append({"op": "export", "principal": principal, "dataset": dataset, "purpose": purpose, "n": len(d.rows)}); self._log(kind="export", principal=principal, dataset=dataset, n=len(d.rows)); return {"status": "OK", "rows": [dict(r) for r in d.rows], "mode": "export", "dp": False}


def verify_receipt(receipt: str, pub: bytes) -> dict | None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        b, s = receipt.split("."); body = base64.b64decode(b); Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(s), b"privacy.receipt.v1\x00" + body); return json.loads(body)
    except Exception: return None
