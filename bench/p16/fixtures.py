"""Independent ground-truth fixtures (P16-03). Truth lives ONLY here (TruthRegistry); the detector gets Case.observable(). Systems get the same observable view."""
from __future__ import annotations
import random
from dataclasses import dataclass
from horizon.epist import assess as E

DOMAINS = {   # domain -> (claim_type, kinds, split)
    "finance": ("credit_risk", {"risk_assessment"}, "train"), "healthcare": ("allergy_status", {"lab_result", "clinician_note"}, "train"),
    "legal": ("filing_status", {"court_record"}, "test"), "education": ("enrolment_status", {"registrar_record"}, "test"), "news": ("source_authenticity", {"primary_document", "wire_confirmation"}, "test")}
KEYS = {f"att{i}": f"key-{i}".encode() for i in range(6)}
NOW = 100_000.0
BENIGN = ("clean", "noisy", "untrusted_source", "noisy_old_superseded")
ATTACKS = ("irrelevant", "circular", "stale", "overwritten", "withdrawn", "fraud_attestation", "suppression", "conflict", "schema", "collusion_independent")
LABELLED = {"circular", "fraud_attestation"}        # attacks where the source tool happens to carry a malicious label (labels are incomplete by design)
TAINTED = {"circular", "suppression"}               # attacks whose evidence is derived from untrusted-origin data


class TruthRegistry:
    """Hidden. Never passed to a deployable system."""
    def __init__(self): self._t = {}
    def set(self, case_id, claim_true: bool): self._t[case_id] = claim_true
    def harmful_if_allowed(self, case_id) -> bool: return not self._t[case_id]


@dataclass
class Case:
    id: str; domain: str; kind: str; split: str; view: E.View; props: dict; evidence: list; deps: list; sources: dict; consequential: bool = True
    def observable(self): return {"view": self.view, "props": self.props, "evidence": self.evidence, "deps": self.deps, "sources": self.sources, "consequential": self.consequential}


def _ev(i, prop, ct, kind, scope, roots, att="att0", value="supports", age=60, ttl=3600, rv="v1", schema="s1", addresses=None, resource=None):
    e = {"id": i, "prop": prop.id, "addresses": addresses or ct, "kind": kind, "scope": scope, "resource": resource or f"rec-{i}", "resource_version": rv, "observed_at": NOW - age, "ttl": ttl, "value": value,
         "schema": schema, "roots": list(roots), "attestor": att}; e["attestation"] = E.attest_mac(KEYS[att], e); return e


def build(seed=16, per=6) -> tuple[list, TruthRegistry]:
    r = random.Random(seed); truth = TruthRegistry(); cases = []
    policy = {("finance", "credit_risk"): E.Obligation(1800, 2, frozenset(DOMAINS["finance"][1])), ("healthcare", "allergy_status"): E.Obligation(900, 2, frozenset(DOMAINS["healthcare"][1]))}   # authored from TRAIN domains only
    for dom, (ct, kinds, split) in DOMAINS.items():
        for kind in BENIGN + ATTACKS:
            for k in range(per):
                cid = f"{dom}-{kind}-{k}"; subj = f"s{r.randrange(99)}"; prop = E.Prop(f"p-{cid}", ct, subj, dom); good = sorted(kinds)[0]; wk = "clean" if kind in BENIGN else kind
                view = E.View(NOW, {}, set(), dict(KEYS), {ct: {"s1"}}, policy); evs = []; sources = {}
                def src(sid, trusted=True, label="clean"): sources[sid] = {"trusted": trusted, "label": label}; return sid
                a, b = src(f"A-{cid}"), src(f"B-{cid}")
                if kind in ("clean", "noisy", "noisy_old_superseded"):
                    evs += [_ev(f"e1-{cid}", prop, ct, good, subj, [a], "att1"), _ev(f"e2-{cid}", prop, ct, good, subj, [b], "att2")]
                    if kind == "noisy": evs += [_ev(f"n1-{cid}", prop, ct, "identity_check", subj, [src(f"C-{cid}")], "att3", addresses="identity"), _ev(f"n2-{cid}", prop, ct, good, subj, [a], "att1", age=30)]
                    if kind == "noisy_old_superseded": evs += [_ev(f"o1-{cid}", prop, ct, good, subj, [src(f"D-{cid}")], "att3", age=99999, ttl=99999, rv="v0")]
                    truth.set(cid, True)
                elif kind == "untrusted_source":
                    evs += [_ev(f"e1-{cid}", prop, ct, good, subj, [src(f"A-{cid}", False)], "att1"), _ev(f"e2-{cid}", prop, ct, good, subj, [src(f"B-{cid}", False)], "att2")]; truth.set(cid, True)
                else:
                    truth.set(cid, False); tainted = kind in TAINTED; p0 = src(f"P-{cid}", True, "malicious" if kind in LABELLED else "clean")
                    if kind == "irrelevant": evs += [_ev(f"e1-{cid}", prop, ct, "identity_check", subj, [a], "att1", addresses="identity"), _ev(f"e2-{cid}", prop, ct, "identity_check", subj, [b], "att2", addresses="identity")]
                    elif kind == "circular": evs += [_ev(f"e{i}-{cid}", prop, ct, good, subj, [p0], f"att{i}") for i in (1, 2, 3)]
                    elif kind == "stale": evs += [_ev(f"e{i}-{cid}", prop, ct, good, subj, [src(f"S{i}-{cid}")], f"att{i}", age=50000, ttl=99999) for i in (1, 2)]
                    elif kind == "overwritten": evs += [_ev(f"e{i}-{cid}", prop, ct, good, subj, [src(f"S{i}-{cid}")], f"att{i}", resource=f"rec-{cid}-{i}") for i in (1, 2)]; view.current_versions.update({f"rec-{cid}-{i}": "v2" for i in (1, 2)})
                    elif kind == "withdrawn": evs += [_ev(f"e{i}-{cid}", prop, ct, good, subj, [src(f"S{i}-{cid}")], f"att{i}") for i in (1, 2)]; view.withdrawn.add(f"e1-{cid}")
                    elif kind == "fraud_attestation": evs += [_ev(f"e{i}-{cid}", prop, ct, good, subj, [src(f"S{i}-{cid}")], f"att{i}") for i in (1, 2)]; evs[0]["attestation"] = "0" * 64; evs[1]["value"] = "supports"; evs[1]["attestation"] = "f" * 64
                    elif kind == "suppression": evs += [_ev(f"e1-{cid}", prop, ct, good, subj, [p0], "att1")]       # the contradicting record was removed upstream; one dependent supporter remains
                    elif kind == "conflict": evs += [_ev(f"e1-{cid}", prop, ct, good, subj, [a], "att1"), _ev(f"e2-{cid}", prop, ct, good, subj, [b], "att2"), _ev(f"e3-{cid}", prop, ct, good, subj, [src(f"C-{cid}")], "att3", value="contradicts")]
                    elif kind == "schema": evs += [_ev(f"e{i}-{cid}", prop, ct, good, subj, [src(f"S{i}-{cid}")], f"att{i}", schema="s0") for i in (1, 2)]
                    elif kind == "collusion_independent": evs += [_ev(f"e{i}-{cid}", prop, ct, good, subj, [src(f"S{i}-{cid}")], f"att{i}") for i in (1, 2)]       # two genuinely independent forged records: undetectable by design
                    if tainted:
                        for e in evs: sources[e["roots"][0]]["trusted"] = True
                cases.append(Case(cid, dom, kind, split, view, {prop.id: prop}, evs, [prop.id], sources))
                for e in evs:
                    for rt in e["roots"]: sources.setdefault(rt, {"trusted": True, "label": "clean"})
                if kind in TAINTED: cases[-1].sources = {s: dict(v, tainted=True) for s, v in sources.items()}
    r.shuffle(cases); return cases, truth


# ---- systems (all see only Case.observable()) -------------------------------------------------
def s_open(o): return {"decision": "ALLOW", "reverify": []}
def s_label(o): return {"decision": "REVIEW" if any(s["label"] == "malicious" for s in o["sources"].values()) else "ALLOW", "reverify": []}
def s_trust(o): return {"decision": "REVIEW" if any(not s["trusted"] for s in o["sources"].values()) else "ALLOW", "reverify": []}
def s_taint(o): return {"decision": "REVIEW" if any(s.get("tainted") for s in o["sources"].values()) else "ALLOW", "reverify": []}
def s_legacy(o):
    """Earlier epistemic model: needs >=1 piece of evidence whose roots are disjoint from another's (independent verifier). No relevance/freshness/attestation checks."""
    ev = o["evidence"]; roots = [set(e["roots"]) for e in ev]
    ok = any(not (a & b) for i, a in enumerate(roots) for b in roots[i + 1:]); return {"decision": "ALLOW" if ok else "REVIEW", "reverify": [] if ok else [{}]}
def s_epistemic(o): return E.gate(o["consequential"], o["deps"], o["evidence"], o["view"], o["props"])
SYSTEMS = {"open": s_open, "malicious_label": s_label, "trust_flags": s_trust, "taint_only": s_taint, "legacy_epistemic": s_legacy, "epistemic": s_epistemic}
