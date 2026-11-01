"""Trusted policy catalog: obligations for guarded actions (owned by the policy owner, not by an agent or an LLM)."""
from .terms import parse

def catalog(policy_version, now=0, horizon=10 ** 9):
    def o(**k): 
        base = dict(bind_args=True, distinct_from_requester=False, consume=False, order_after=[], deadline_s=None, claim_equals=[], policy_version=policy_version, valid_from=0, valid_until=horizon, issuer="policy-owner"); base.update(k); return parse(base, policy_version=policy_version, now=now)
    return [
        o(id="prod.tests", kind="PRE", action="deploy_prod", evidence_kind="TEST_STATUS", roles=["ci", "ci2"], bind_args=False, claim_equals=[["result", "pass"]]),
        o(id="prod.approval", kind="PRE", action="deploy_prod", evidence_kind="APPROVAL", roles=["approver"], distinct_from_requester=True, consume=True, order_after=["prod.tests"]),
        o(id="prod.sig", kind="PRE", action="deploy_prod", evidence_kind="SIGNATURE", roles=["signer"], bind_args=False),
        o(id="prod.smoke", kind="POST", action="deploy_prod", evidence_kind="SMOKE_TEST", roles=["ci", "ci2"], bind_args=False, deadline_s=600, claim_equals=[["result", "pass"]]),
        o(id="stg.tests", kind="PRE", action="deploy_staging", evidence_kind="TEST_STATUS", roles=["ci", "ci2"], bind_args=False, claim_equals=[["result", "pass"]]),
    ]
UNGUARDED = ("read_logs", "status")
