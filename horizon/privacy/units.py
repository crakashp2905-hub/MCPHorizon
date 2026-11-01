"""Privacy units, threat model and accounting semantics (P45-01).

PROTECTED UNIT   the individual: one person's rows in a dataset. Adjacent datasets differ by adding or removing ALL rows of one individual
                 (unbounded DP). Each query therefore bounds the contribution of one individual (`cap` rows, values clamped to [lo, hi]); the sensitivity
                 used for noise is computed from those bounds by the service, never taken from the caller.
BUDGET SCOPE     the DATASET. One ledger per dataset (and protected unit) is shared by every principal, tenant, task and delegated agent that queries it.
                 Principals are not part of the ledger key, so a fresh identity gets no fresh budget.
SUB-ALLOCATIONS  per-task and per-tenant caps may be set under the dataset ledger. They can only restrict: a charge must fit the dataset ledger AND every
                 allocation that applies to it.
OUT OF SCOPE     disclosure that is not a released DP answer (raw aggregates, row export, model memory, timing/size side channels). Those are governed by
                 separate access-control rules (authz in service.py) and carry no DP claim.

THREAT MODEL     Adversaries: (1) several cooperating agents or one agent using many identities that each issue queries which pass local limits;
                 (2) concurrent requests racing the budget check; (3) retries/replays/cancellations used to obtain extra noise samples or a refund after
                 the noisy answer was produced; (4) a delegated sub-agent that tries to charge a different ledger or none; (5) an agent that supplies its own
                 sensitivity or ledger id. The service, the ledger database file and the policy-owner key are trusted; the ledger is tamper-EVIDENT (hash chain),
                 not tamper-proof against the database owner.
GUARANTEE        If every answer released from a dataset is the output of a mechanism whose (eps, delta) / rho cost was charged to the dataset ledger, and the
                 chosen accountant's composition theorem applies, the released answers jointly satisfy the budget's (eps, delta)-DP bound for the declared
                 adjacency. Nothing is claimed for other outputs of the system.
"""
import hashlib

UNITS = ("individual", "dataset", "task", "tenant")


def ledger_id(dataset: str, unit: str = "individual") -> str:
    if unit not in UNITS: raise ValueError("unknown privacy unit " + unit)
    return "led:" + hashlib.sha256(("horizon.privacy.ledger\x00%s\x00%s" % (dataset, unit)).encode()).hexdigest()[:24]
