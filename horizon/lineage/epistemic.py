"""Verification relations and unverified-consequence policy (P7-16..P7-18). DEPLOYABLE logic uses provenance/trust only. Factual truth lives only in
fixtures/oracle and has no parameter anywhere in this module."""
from __future__ import annotations
from ..core.labels import T


class Ledger:
    def __init__(self, sidecar): self.sc, self.rel, self.audit = sidecar, {}, []

    def add_relation(self, subject: str, verifier: str, evidence: list[str]) -> tuple[bool, str]:
        """A relation counts only if the verifier is independent of the subject: TRUSTED, different origin, no shared ancestry, backed by non-empty
        evidence that is itself independent of the subject. Otherwise it is recorded as rejected, never as verified."""
        sc = self.sc
        why = None
        if subject not in sc.art or verifier not in sc.art: why = "UNKNOWN_HANDLE"
        elif subject == verifier: why = "SELF_VERIFICATION"
        elif sc.art[verifier]["trust"] != "TRUSTED": why = "VERIFIER_NOT_TRUSTED"
        elif sc.art[verifier]["partial_lineage"] or not all(e in sc.art for e in evidence): why = "VERIFIER_LINEAGE_INCOMPLETE"
        elif not evidence: why = "NO_EVIDENCE"
        else:
            sa, va = sc.ancestors(subject), sc.ancestors(verifier)
            ea = set().union(*[sc.ancestors(e) for e in evidence])
            if subject in va or verifier in sa: why = "VERIFIER_DERIVED_FROM_SUBJECT"
            elif sa & va: why = "SHARED_ANCESTRY"
            elif sa & ea: why = "EVIDENCE_DERIVED_FROM_SUBJECT"
            elif _origin(sc, subject) & _origin(sc, verifier): why = "SAME_ORIGIN"
        self.audit.append({"subject": subject, "verifier": verifier, "ok": why is None, "why": why})
        if why is None: self.rel[subject] = {"verifier": verifier, "evidence": list(evidence)}
        return why is None, why or "OK"

    def clean(self, h: str, _seen=None) -> bool:
        """An artifact is epistemically clean if it was independently verified, or it is TRUSTED with complete lineage and every parent is clean."""
        sc = self.sc; _seen = _seen if _seen is not None else set()
        if h in _seen: return False
        _seen.add(h)
        a = sc.art.get(h)
        if a is None: return False
        if h in self.rel: return True
        if a["trust"] != "TRUSTED" or a["partial_lineage"]: return False
        return all(self.clean(p, _seen) for p in a["parents"])

    def consequence(self, inputs: list[str], protected: bool) -> dict:
        """Conservative: a protected action that depends on anything not clean needs REVIEW. Independent of whether the content is factually true."""
        bad = sorted(i for i in inputs if not self.clean(i))
        return {"decision": "REVIEW" if (protected and bad) else "ALLOW", "unverified": bad, "reason_codes": (["UNVERIFIED_DOWNSTREAM_CONSEQUENCE"] if protected and bad else [])}


def _origin(sc, h) -> set:
    return {sc.meta[x].get("source") for x in sc.ancestors(h) if x in sc.meta and sc.meta[x].get("kind") == "ingest"} - {None}
