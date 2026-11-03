"""Independent plan checker (HF-PR04). Shares NO code with the synthesizer except the IR types. It re-derives admissibility from the rules below; it never trusts a synthesizer verdict.
Rules (conditional, finite model; see docs): protected data (label SECRET) may only leave the local trust boundary as an approved aggregate, or to a placement whose boundary is enforced by an installed control."""
from __future__ import annotations
from .ir import Task, Plan, CONTROLS, WITNESSES, PLACEMENTS, FORMS


def violations(task: Task, plan: Plan) -> list:
    task.validate(); v = []
    if plan.placement not in PLACEMENTS or plan.form not in FORMS: return ["UNKNOWN_PLAN_VALUE"]
    if not set(plan.controls) <= set(task.available_controls): v.append("CONTROL_NOT_AVAILABLE")
    if not set(plan.witnesses) <= set(task.available_witnesses): v.append("WITNESS_NOT_AVAILABLE")
    if plan.form == "aggregate" and not task.aggregate_ok: v.append("AGGREGATE_NOT_PERMITTED_BY_TASK")
    protected = task.data_label != "PUBLIC"
    leaves = plan.placement != "local_sandbox"
    if plan.placement == "local_sandbox" and "local_sandbox" not in plan.controls: v.append("LOCAL_SANDBOX_NOT_INSTALLED")
    if protected and leaves and plan.form == "raw":
        if plan.placement == "attested_enclave":
            if "enclave_attestation" not in plan.controls: v.append("ENCLAVE_NOT_ATTESTED")
        elif not (task.remote_trust == "contracted" and "egress_contract_enforcer" in plan.controls): v.append("RAW_PROTECTED_DATA_TO_UNENFORCED_REMOTE")
    if task.need_effect_witness and plan.placement != "local_sandbox" and not plan.witnesses: v.append("NO_EFFECT_WITNESS")
    return v


def check(task: Task, plan: Plan) -> bool: return not violations(task, plan)
