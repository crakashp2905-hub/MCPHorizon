import unittest
from research.spectra import pipeline as P
from horizon.assurance.registry import Registry

PROBES = ["net_0", "file_1", "proc_2"]
INSTR = {"fs", "net", "queue"}
FULL = {"controls": ("enclave_attestation", "egress_contract_enforcer", "local_sandbox"), "witnesses": ("receiver_journal",),
        "installed": {"enclave_attestation": "d1", "local_sandbox": "d2", "egress_contract_enforcer": "d3"}, "installed_witnesses": {"receiver_journal": "w1"},
        "remote_trust": {"net": "contracted"}, "labels": {"net_0": "SECRET"}}


def world(graph, extra_hyps=()):
    declared = {p: () for p in PROBES}
    hyps = [{p: frozenset() for p in PROBES}] + [{**{p: frozenset() for p in PROBES}, p: frozenset({s})} for p in PROBES for s in ("fs", "net", "queue")] + list(extra_hyps)
    return declared, hyps, (lambda pr: [(s, f"{pr}->{s}") for s in sorted(graph.get(pr, ()))])


BOTH = {**{p: frozenset() for p in PROBES}, "net_0": frozenset({"net"}), "proc_2": frozenset({"queue"})}


def go(graph, env, extra_hyps=(), instrumented=INSTR, max_rounds=6, only_hyps=None):
    declared, hyps, system = world(graph, extra_hyps); hyps = hyps if only_hyps is None else only_hyps; reg = Registry(lambda: 0)
    P.issue(reg, "c1", (("scope", "x"),), 0, 10**9, {"graph:c1": P.graph_digest(declared)}); reg.set_node("graph:c1", P.graph_digest(declared))
    return P.run(system, PROBES, hyps, declared, instrumented, reg, "c1", env, max_rounds=max_rounds), reg


class Flow(unittest.TestCase):
    def test_discovered_effect_yields_checked_plan_and_new_valid_claim_old_suspended(self):
        r, reg = go({"net_0": {"net"}}, FULL)
        self.assertEqual(r["rounds"][0]["verdict"], "DISCOVERED"); self.assertEqual(r["rounds"][0]["results"], {"net": "CERTIFIED_IN_PLACE"})
        self.assertEqual(r["current_claim"], "c1.r1"); self.assertEqual(r["status"][0], "VALID"); self.assertTrue(r["permit_allowed"])
        self.assertEqual(r["original_claim_status"][0], "SUSPENDED"); self.assertFalse(reg.may_issue_permit("c1", r["epoch"]))
        self.assertIn("egress_contract_enforcer", r["rounds"][0]["plans"]["net"])
    def test_new_claim_is_suspended_when_a_control_it_relies_on_changes(self):
        r, reg = go({"net_0": {"net"}}, FULL); reg.set_node("control:egress_contract_enforcer", "tampered")
        self.assertEqual(reg.status("c1.r1", r["epoch"])[0], "SUSPENDED"); self.assertFalse(reg.may_issue_permit("c1.r1", r["epoch"]))
    def test_missing_installed_control_means_no_claim_and_permits_stay_refused(self):
        env = dict(FULL, installed={"local_sandbox": "d2"})
        r, reg = go({"net_0": {"net"}}, env)
        self.assertIsNone(r["rounds"][0]["claim"]); self.assertIn("not installed", r["rounds"][0]["why"]); self.assertFalse(r["permit_allowed"])
    def test_no_available_control_is_not_certifiable_and_no_claim(self):
        r, reg = go({"net_0": {"net"}}, dict(FULL, controls=(), witnesses=(), installed={}, installed_witnesses={}))
        self.assertEqual(r["rounds"][0]["results"], {"net": "NOT_CERTIFIABLE_WITHIN_MODEL"}); self.assertIsNone(r["rounds"][0]["claim"]); self.assertFalse(r["permit_allowed"])
    def test_relocation_only_plan_is_not_an_enforceable_claim(self):
        env = dict(FULL, controls=("local_sandbox",), witnesses=(), installed={"local_sandbox": "d2"}, installed_witnesses={}, remote_trust={})
        r, reg = go({"net_0": {"net"}}, env)
        self.assertEqual(r["rounds"][0]["results"], {"net": "REQUIRES_RELOCATION"}); self.assertIn("owner action", r["rounds"][0]["why"]); self.assertIsNone(r["rounds"][0]["claim"]); self.assertFalse(r["permit_allowed"])
    def test_local_sink_needs_the_installed_sandbox(self):
        r, _ = go({"file_1": {"fs"}}, FULL); self.assertEqual(r["rounds"][0]["results"], {"fs": "CERTIFIED_LOCAL"}); self.assertTrue(r["permit_allowed"])
        r2, _ = go({"file_1": {"fs"}}, dict(FULL, controls=(), installed={})); self.assertEqual(r2["rounds"][0]["results"], {"fs": "NOT_CERTIFIABLE_WITHIN_MODEL"}); self.assertFalse(r2["permit_allowed"])
    def test_no_discovery_keeps_the_original_claim_valid_with_stated_scope(self):
        r, _ = go({}, FULL); self.assertEqual(r["final_verdict"], "BOUNDED_COVERAGE"); self.assertEqual(r["current_claim"], "c1"); self.assertTrue(r["permit_allowed"])
    def test_unidentifiable_coverage_suspends_the_claim(self):
        hid = {p: frozenset() for p in PROBES}; hid2 = dict(hid, net_0=frozenset({"offhost"}))
        r, _ = go({}, FULL, extra_hyps=[hid2]); self.assertEqual(r["final_verdict"], "UNIDENTIFIABLE"); self.assertFalse(r["permit_allowed"]); self.assertEqual(r["status"][0], "REVOKED")
    def test_two_discoveries_chain_two_claims(self):
        r, reg = go({"net_0": {"net"}, "proc_2": {"queue"}}, dict(FULL, remote_trust={"net": "contracted", "queue": "contracted"}), extra_hyps=[BOTH])
        self.assertEqual([x.get("claim") for x in r["rounds"][:2]], ["c1.r1", "c1.r2"]); self.assertEqual(r["current_claim"], "c1.r2"); self.assertTrue(r["permit_allowed"])
        self.assertFalse(reg.may_issue_permit("c1.r1", r["epoch"]))      # superseded: stale epoch
    def test_a_second_effect_without_a_plan_blocks_the_chain(self):
        r, _ = go({"net_0": {"net"}, "proc_2": {"queue"}}, dict(FULL, remote_trust={"net": "contracted"}, controls=("egress_contract_enforcer",), installed={"egress_contract_enforcer": "d3"}, witnesses=("receiver_journal",)), extra_hyps=[BOTH])
        self.assertEqual(r["rounds"][0]["claim"], "c1.r1"); self.assertIsNone(r["rounds"][1].get("claim")); self.assertEqual(r["current_claim"], "c1.r1")
        self.assertFalse(r["permit_allowed"])                    # c1.r1 does not cover the second effect: its graph digest no longer matches
    def test_missing_witness_blocks_the_claim(self):
        r, _ = go({"net_0": {"net"}}, dict(FULL, installed_witnesses={}))
        self.assertIsNone(r["rounds"][0]["claim"]); self.assertFalse(r["permit_allowed"])
    def test_one_unplannable_sink_blocks_the_whole_claim(self):
        both = {**{p: frozenset() for p in PROBES}, "net_0": frozenset({"fs", "queue"})}
        env = dict(FULL, controls=("local_sandbox",), witnesses=(), installed={"local_sandbox": "d2"}, installed_witnesses={}, remote_trust={})
        r, _ = go({"net_0": {"fs", "queue"}}, env, extra_hyps=[both])
        self.assertEqual(r["rounds"][0]["results"], {"fs": "CERTIFIED_LOCAL", "queue": "REQUIRES_RELOCATION"}); self.assertIsNone(r["rounds"][0]["claim"]); self.assertFalse(r["permit_allowed"])
    def test_unknown_verdict_revokes_the_claim(self):
        r, _ = go({}, FULL, only_hyps=[{p: frozenset({"net"}) for p in PROBES}])
        self.assertEqual(r["final_verdict"], "UNKNOWN"); self.assertFalse(r["permit_allowed"]); self.assertEqual(r["status"][0], "REVOKED")
    def test_claim_digest_binds_the_chosen_plan(self):
        a, ra = go({"net_0": {"net"}}, FULL); b, rb = go({"net_0": {"net"}}, dict(FULL, remote_trust={}))
        da = dict(ra.claims["c1.r1"].digests)["plan:net_0:net"]; db = dict(rb.claims["c1.r1"].digests)["plan:net_0:net"]
        self.assertNotEqual(da, db)
class FailClosed(unittest.TestCase):
    def test_unknown_label_is_secret_and_unknown_sink_is_remote(self):
        t = P.effect_task("zzz", "weird", {"controls": (), "witnesses": ()}); self.assertEqual((t.data_label, t.remote_trust, t.aggregate_ok), ("SECRET", "opaque", False))
        self.assertNotIn("weird", P.LOCAL_SINKS)
    def test_graph_digest_is_order_independent_and_content_sensitive(self):
        self.assertEqual(P.graph_digest({"a": ("x", "y"), "b": ()}), P.graph_digest({"b": (), "a": ("y", "x")})); self.assertNotEqual(P.graph_digest({"a": ("x",)}), P.graph_digest({"a": ("y",)}))
if __name__ == "__main__": unittest.main()
