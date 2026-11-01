"""Preflight attestation, verdict binding, commit gate with re-validation, independent receipt comparison, deviation severity and rollback (P41-06..11)."""
from __future__ import annotations
import json, os, shutil, sqlite3, subprocess, sys, tempfile
from ..hpolicy.authority import EvidenceError
from .core import dig, decide, Diff, DbAdapter, FileAdapter, PublishAdapter, Contract, diff_digests

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def receipt(kind, path):
    r = subprocess.run([sys.executable, "-m", "horizon.counterfactual.receipt", kind, path], cwd=ROOT, capture_output=True, text=True, timeout=30)
    if r.returncode: raise RuntimeError("receipt process failed: " + r.stderr[-200:])
    return json.loads(r.stdout)


def raw_to_digests(raw): return {t: {k: dig(v) for k, v in rows.items()} for t, rows in raw.items()}


class Preflight:
    """The preview service. Holds the ATTESTATION issuer; the commit gate has only a verifier."""
    def __init__(self, issuer, contract_for): self.issuer, self.contract_for = issuer, contract_for
    def run(self, adapter, op, contract, *, principal, ttl=300, version=0, **kw):
        diff = adapter.preview(*op) if isinstance(op, tuple) else adapter.preview(op); verdict, reasons = decide(diff, contract)
        tok = self.issuer.issue("ATTESTATION", principal=principal, artifact=diff.op_digest, args_digest=diff.digest(), object_version=version, ttl=ttl, claim={"verdict": verdict, "adapter": diff.adapter, "rows": len(diff.changes)})
        return {"diff": diff, "verdict": verdict, "reasons": reasons, "token": tok}


def severity(approved: Diff, got: list, contract: Contract):
    A = {(c["kind"], c["target"], c["key"], c["after"]) for c in approved.changes}; R = {(c["kind"], c["target"], c["key"], c["after"]) for c in got}
    if A == R: return "NONE"
    extra = R - A
    if not extra: return "LOW"
    if all(t in contract.allowed_tables for _, t, _, _ in extra) and contract.expected_rows[0] <= len(R) <= contract.expected_rows[1]: return "MEDIUM"
    return "HIGH"


class Gate:
    def __init__(self, authority, clock, *, verify_in_commit=True):
        self.auth, self.clock, self.ver, self.verify_in_commit = authority, clock, authority.verifier(), verify_in_commit; self.incidents = []; self.frozen = set()
    def commit_db(self, adapter: DbAdapter, sql, params, contract, token, *, requester, approval=None, task="t", expect_version=None):
        try: p = self.ver.verify(token, now=int(self.clock()))
        except EvidenceError as e: return {"committed": False, "why": "ATTESTATION_" + e.code}
        od = dig({"sql": sql, "params": list(params)})
        if p["kind"] != "ATTESTATION" or p["role"] != "preflight": return {"committed": False, "why": "NOT_A_PREFLIGHT_ATTESTATION"}
        if p["artifact"] != od: return {"committed": False, "why": "OPERATION_DIGEST_MISMATCH"}
        v = p["claim"]["verdict"]; dd = p["args_digest"]
        if task in self.frozen: return {"committed": False, "why": "TASK_FROZEN"}
        if v == "BLOCK": return {"committed": False, "why": "VERDICT_BLOCK"}
        if v == "REVIEW" and not self._reviewed(approval, od, dd, requester): return {"committed": False, "why": "REVIEW_REQUIRED"}
        # re-validate authority + resources immediately before commit
        pre_raw = receipt("db", adapter.path); bk = tempfile.mktemp(suffix=".db"); src = adapter.conn(); dst = sqlite3.connect(bk); src.backup(dst); dst.close(); src.close()
        res = adapter.apply_verified(sql, params, dd, od, expect_version) if self.verify_in_commit else adapter.apply_unverified(sql, params)
        out = {"committed": res["committed"], "why": res.get("why"), "severity": None, "response": None}
        post_raw = receipt("db", adapter.path); got = diff_digests(raw_to_digests(pre_raw), raw_to_digests(post_raw))
        out["receipt_changes"] = len(got); out["_got"] = got; out["_pre"] = raw_to_digests(pre_raw)
        if res["committed"]:
            out["_backup"] = bk
        else: os.path.exists(bk) and os.remove(bk)
        return out
    def _reviewed(self, token, od, dd, requester):
        if not token: return False
        try: p = self.ver.verify(token, now=int(self.clock()), consume=True)
        except EvidenceError: return False
        return p["kind"] == "APPROVAL" and p["artifact"] == od and p["args_digest"] == dd and p["iss"] != requester

    def reconcile(self, adapter: DbAdapter, out, approved: Diff, contract, task="t", auto_rollback=True):
        """Compare the independent receipt with the approved diff; classify; respond."""
        sev = severity(approved, out["_got"], contract); out["severity"] = sev; resp = "none"
        if sev == "LOW": resp = "log"
        elif sev == "MEDIUM": self.incidents.append((task, sev)); self.frozen.add(task); resp = "incident+freeze"
        elif sev == "HIGH":
            self.incidents.append((task, sev)); self.frozen.add(task); resp = "incident+freeze"
            if auto_rollback and out.get("_backup"): out["rolled_back"] = self.rollback(adapter, out); resp = "incident+freeze+rollback" + ("" if out["rolled_back"]["verified"] else "(UNVERIFIED)")
        out["response"] = resp; return out
    def rollback(self, adapter, out):
        c = adapter.conn(); c.execute("attach database ? as bk", (out["_backup"],)); c.execute("begin immediate")
        for ch in out["_got"]:
            t = ch["target"]; pk = [r[1] for r in c.execute("pragma main.table_info(%s)" % t) if r[5]] or ["rowid"]; key = json.loads(ch["key"]); where = " and ".join("%s = ?" % k for k in pk)
            if ch["kind"] == "INSERT": c.execute("delete from main.%s where %s" % (t, where), key)
            else: c.execute("delete from main.%s where %s" % (t, where), key); c.execute("insert into main.%s select * from bk.%s where %s" % (t, t, where), key)
        c.execute("commit"); c.execute("detach database bk"); c.close()
        again = diff_digests(out["_pre"], raw_to_digests(receipt("db", adapter.path))); return {"verified": not again, "residual_changes": len(again)}
