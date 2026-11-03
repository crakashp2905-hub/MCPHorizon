"""HorizonForge finite model (HF-PR02 slice, HF-008/010/011/013). RESEARCH PROTOTYPE, CANDIDATE, outside the trusted kernel.
A Task needs one computation over one labelled datum. A Plan chooses WHERE it runs, WHICH data form leaves the trust boundary, and which controls/witnesses are installed. Unknown values fail closed."""
from __future__ import annotations
from dataclasses import dataclass

LABELS = ("PUBLIC", "INTERNAL", "SECRET")
PLACEMENTS = ("remote", "local_sandbox", "attested_enclave")       # where the computation executes
FORMS = ("raw", "aggregate")                                       # what data form is sent to a non-local placement
REMOTE_TRUST = ("opaque", "contracted")                            # contracted = an independently enforced egress/usage contract exists
CONTROLS = {"local_sandbox": 3, "enclave_attestation": 5, "egress_contract_enforcer": 4}   # control -> cost
WITNESSES = {"receiver_journal": 2, "network_tap": 3}


@dataclass(frozen=True)
class Task:
    data_label: str
    aggregate_ok: bool          # task semantics tolerate computing on an approved aggregate (declared by the owner, not inferred)
    remote_trust: str           # trust assumption about the remote service
    available_controls: tuple   # subset of CONTROLS installable in this environment
    available_witnesses: tuple
    need_effect_witness: bool = False   # claim must include independently VERIFIED effect completion

    def validate(self):
        if self.data_label not in LABELS: raise ValueError("unknown label")
        if self.remote_trust not in REMOTE_TRUST: raise ValueError("unknown remote trust")
        if not set(self.available_controls) <= set(CONTROLS) or not set(self.available_witnesses) <= set(WITNESSES): raise ValueError("unknown control/witness")
        return self


@dataclass(frozen=True)
class Plan:
    placement: str; form: str; controls: tuple; witnesses: tuple

    def cost(self): return sum(CONTROLS[c] for c in self.controls) + sum(WITNESSES[w] for w in self.witnesses)
