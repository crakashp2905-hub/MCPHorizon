"""P54-05: one trusted evidence-receipt service for the 15 modules (the shared HorizonPolicy authority).
The service holds the only issuer; the harness gets a Verifier. A receipt binds a module id to the exact bytes of its recorded result and of its oracle and system files, so a later edit to any of them turns the verdict TAMPERED. Verdicts are about EVIDENCE INTEGRITY only: INTACT does not mean the module is secure."""
import hashlib, json, os, time
from ..hpolicy.authority import HorizonPolicy, EvidenceError
from .registry import MODULES, BY_ID, ROOT
from . import review as RV

def fsha(rel):
    p = os.path.join(ROOT, rel)
    return "sha256:" + hashlib.sha256(open(p, "rb").read()).hexdigest()[:32] if os.path.exists(p) else "missing"
def bundle_hash(files):
    h = hashlib.sha256()
    for f in sorted(files): h.update(f.encode() + b"\0" + fsha(f).encode() + b"\0")
    return "sha256:" + h.hexdigest()[:32]
def facts(m):
    return {"k": "module-receipt", "m": m["id"], "res": fsha("results/v2/%s/result.json" % m["results"]), "orc": bundle_hash(m["oracle"]), "sys": bundle_hash(m["system"])}

class ReceiptService:
    def __init__(self, clock=time.time):
        self.clock = clock; self.auth = HorizonPolicy("pol-1", clock=clock); self._iss = self.auth.register_issuer("receipts", {"ATTESTATION"})
    def verifier(self): return self.auth.verifier()
    def issue(self, mid, ttl=3600):
        c = facts(BY_ID[mid])
        d = "sha256:" + hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest()
        return self._iss.issue("ATTESTATION", principal="p54", artifact=mid, args_digest=d, claim=c, ttl=ttl)
    def issue_all(self, ttl=3600): return {m["id"]: self.issue(m["id"], ttl) for m in MODULES}

def verdict(mid, token, verifier, now=None):
    """INTACT only if the token verifies under the shared authority, names this module, and every recorded hash still matches the bytes on disk, AND the oracle does not import system code. TAMPERED if a hash differs. UNKNOWN if the token cannot be checked (expired, malformed, missing, wrong authority) - never PASS by default."""
    r = []
    if token is None: return {"module": mid, "verdict": "UNKNOWN", "reasons": ["NO_RECEIPT"]}
    try: p = verifier.verify(token, now=now)
    except EvidenceError as e: return {"module": mid, "verdict": "UNKNOWN", "reasons": ["RECEIPT_" + e.code]}
    if p["artifact"] != mid or p["claim"].get("m") != mid: return {"module": mid, "verdict": "UNKNOWN", "reasons": ["RECEIPT_FOR_OTHER_MODULE"]}
    cur = facts(BY_ID[mid])
    for k in ("res", "orc", "sys"):
        if p["claim"].get(k) != cur[k]: r.append({"res": "RESULT_CHANGED", "orc": "ORACLE_CHANGED", "sys": "SYSTEM_CHANGED"}[k])
    if r: return {"module": mid, "verdict": "TAMPERED", "reasons": r}
    ind = RV.independence(BY_ID[mid])
    if not ind["independent"]: return {"module": mid, "verdict": "INTACT", "reasons": ["ORACLE_REACHES_SYSTEM_CODE"], "caveat": True}
    return {"module": mid, "verdict": "INTACT", "reasons": [], "caveat": False}
