import json, os, unittest
from horizon.emergence import model as M, baselines as B, summaries as S, legacy as L, experiment as X
from horizon.emergence.oracle import Oracle, free_ports
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RES = json.load(open(os.path.join(ROOT, "results/v2/p39-emergence/result.json")))


def eps(): return M.Endpoints(*free_ports())
def chain(*ops, sink=("get", "A/redir->B")):
    sums = S.library_summaries(); steps, t = [], None
    for i, o in enumerate(ops):
        if o.startswith("read"): t = sums[o].out_taint; steps.append(M.Step(o, (), "", t))
        else: t = M.apply_transform(sums[o], t); steps.append(M.Step(o, (len(steps) - 1,), "", t))
    return steps + [M.Step(sink[0], (len(steps) - 1,), sink[1], S.PUB, t)]


class Legacy(unittest.TestCase):
    def test_frozen_edges_and_semantics(self):
        self.assertEqual(len(L.EDGES), 6)
        self.assertEqual(L.closure({"read_filesystem_credentials"}), {"read_filesystem_credentials", "read_filesystem_user", "credentials_in_context"})
        self.assertIn("credential_exfiltration_setup", L.closure({"read_filesystem_credentials", "network_send_external"}))
    def test_precision_loss_is_demonstrable(self):
        self.assertTrue(L.legacy_alert(["read_secret", "get"])); self.assertTrue(L.legacy_alert(["read_secret", "hash", "get"]))     # sanitization invisible
        self.assertEqual(L.legacy_alert(["get", "read_secret"]), L.legacy_alert(["read_secret", "get"]))                                 # order invisible
    def test_d3_equals_legacy_closure_on_chains(self):
        for c in X.chains(S.library_summaries())[:60]: self.assertEqual(B.d3(c), L.legacy_alert([s.op for s in c]))


class Summaries(unittest.TestCase):
    def test_serialization_deterministic_and_versioned(self):
        a, b = S.serialize_summaries(S.library_summaries()), S.serialize_summaries(S.library_summaries()); self.assertEqual(a, b); self.assertIn(S.ABSTRACTION_VERSION, a)
    def test_unmodeled_op_is_marked(self):
        self.assertFalse(S.library_summaries(unmodeled=("b64",))["b64"].modeled)
    def test_summary_fields(self):
        o = S.library_summaries()["weak_sanitize"]; self.assertTrue(0 < o.confidence < 1); self.assertTrue(o.provenance.startswith("inferred")); self.assertEqual(o.principal, "agent")


class Model(unittest.TestCase):
    def test_search_deterministic_with_seed_and_caps(self):
        e = M.Endpoints(1, 2, 3); s = S.library_summaries()
        a = M.search(s, e, budget=300, seed=7, guided=False); b = M.search(s, e, budget=300, seed=7, guided=False)
        self.assertEqual([c.key() for c in a["candidates"]], [c.key() for c in b["candidates"]])
        r = M.search(s, e, budget=5); self.assertTrue(r["truncated"]); self.assertLessEqual(r["evaluated"], 5)
        full = M.search(s, e, budget=10 ** 6); self.assertFalse(full["truncated"]); self.assertTrue(all(len(c.steps) <= M.MAX_DEPTH for c in full["candidates"]))
    def test_cycle_detection_terminates_and_states_bounded(self):
        e = M.Endpoints(1, 2, 3); r = M.search(S.library_summaries(), e, budget=10 ** 6, max_depth=4); self.assertLess(r["states"], 5000)
    def test_full_search_size_pinned_and_unknowns_reported(self):
        e = M.Endpoints(1, 2, 3); r = M.search(S.library_summaries(), e, budget=10 ** 6)
        self.assertEqual((r["evaluated"], r["states"]), (1888, 404))       # regression pin: duplicate-state pruning is what keeps this finite and small
        self.assertTrue(r["unknowns"]); self.assertTrue(all(c.steps[-1].target.startswith("C/") and c.status == "UNKNOWN" for c in r["unknowns"]))
    def test_trace_preserves_args_endpoint_scope_taint(self):
        e = M.Endpoints(1, 2, 3); r = M.search(S.library_summaries(), e, budget=2000); c = [c for c in r["candidates"] if [s.op for s in c.steps] == ["read_secret", "b64", "get"]][0].d()["steps"][-1]
        self.assertEqual(c["target"], "A/redir->B"); self.assertEqual(c["in_taint"], S.ENC); self.assertIn("/redir?to=http://127.0.0.1:2/c", c["url"]); self.assertEqual([h[0] for h in c["chain"]], [1, 2])
    def test_effect_not_toolname_cooccurrence(self):
        e = M.Endpoints(1, 2, 3); s = S.library_summaries()
        bad, ok_hash, ok_ingest = chain("read_secret"), chain("read_secret", "hash"), chain("read_secret", sink=("get", "A/ingest"))
        self.assertEqual([B.emergence(x, e, s) for x in (bad, ok_hash, ok_ingest)], ["VIOLATION", "SAFE", "SAFE"])
        self.assertTrue(all(B.d3(x) for x in (bad, ok_hash, ok_ingest)))         # same tool names, different effects
    def test_unmodeled_endpoint_is_unknown_not_safe(self):
        e = M.Endpoints(1, 2, 3); self.assertEqual(B.emergence(chain("read_secret", sink=("get", "C/redir->B")), e, S.library_summaries()), "UNKNOWN")
        e2 = M.Endpoints(1, 2, 3, known_c=True); self.assertEqual(B.emergence(chain("read_secret", sink=("get", "C/redir->B")), e2, S.library_summaries()), "VIOLATION")
    def test_all_generated_calls_pass_direct_policy(self):
        e = M.Endpoints(1, 2, 3); r = M.search(S.library_summaries(), e, budget=10 ** 6)
        for c in r["candidates"] + r["unknowns"]: self.assertTrue(all(M.direct_allowed(s.target) for s in c.steps if s.target))
    def test_refinement_is_scoped_and_logged(self):
        s = S.library_summaries(); r = M.refine(s, "weak_sanitize", "ab" * 32); self.assertIn("refined:oracle", r["weak_sanitize"].provenance); self.assertEqual(s["weak_sanitize"].transform, "unknown")
        e = M.Endpoints(1, 2, 3); self.assertFalse(any("weak_sanitize" in [x.op for x in c.steps] for c in M.search(r, e, budget=10 ** 6)["candidates"]))
    def test_oracle_blind_flag(self):
        self.assertTrue(M.oracle_blind(chain("read_secret", "b64", "b64"))); self.assertFalse(M.oracle_blind(chain("read_secret", "b64")))


class LiveOracle(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.e = eps(); cls.o = Oracle(cls.e).__enter__()
    @classmethod
    def tearDownClass(cls): cls.o.__exit__()
    def test_open_redirect_leak_and_matched_controls(self):
        leak = self.o.execute(chain("read_secret", "b64")); self.assertTrue(leak["leak_to_B"]); self.assertEqual(leak["per_endpoint"]["A"]["conns"], 1)
        self.assertFalse(self.o.execute(chain("read_secret", "hash"))["leak_to_B"])                                   # genuine sanitization
        self.assertFalse(self.o.execute(chain("read_secret", sink=("get", "A/ingest")))["leak_to_B"])                  # allowed destination
        self.assertFalse(self.o.execute(chain("read_note"))["leak_to_B"])                                              # benign intermediary use
    def test_unmodeled_hidden_redirector_is_real(self):
        self.assertTrue(self.o.execute(chain("read_secret", sink=("get", "C/redir->B")))["leak_to_B"])
    def test_outcome_comes_from_journal_not_prediction(self):
        r = self.o.execute(chain("read_secret", "weak_sanitize"))
        self.assertEqual(B.emergence(chain("read_secret", "weak_sanitize"), M.Endpoints(*self.e.ports.values()), S.library_summaries()), "VIOLATION"); self.assertFalse(r["leak_to_B"])   # prediction and outcome disagree and are kept apart
        self.assertEqual(len(r["journal_sha256"]), 64)
    def test_loopback_only_redirect_guard(self):
        import urllib.request, urllib.error
        from horizon.emergence.oracle import NoRedirectToUnknownHosts
        with self.assertRaises(urllib.error.URLError): NoRedirectToUnknownHosts().redirect_request(urllib.request.Request("http://127.0.0.1:1/"), None, 302, "", {}, "http://example.invalid/x")
    def test_refinement_loop_end_to_end(self):
        s = S.library_summaries(); r1 = M.search(s, self.e, budget=10 ** 6)
        dis = [c for c in r1["candidates"] if not M.oracle_blind(c.steps) and not self.o.execute(c.steps)["leak_to_B"]]; self.assertTrue(dis)
        ref = M.refine(s, "weak_sanitize", self.o.execute(dis[0].steps)["journal_sha256"]); r2 = M.search(ref, self.e, budget=10 ** 6)
        self.assertTrue(all(self.o.execute(c.steps)["leak_to_B"] or M.oracle_blind(c.steps) for c in r2["candidates"]))


class Results(unittest.TestCase):
    def test_recorded_run_internally_consistent(self):
        rows = RES["corpus"]["rows"]; self.assertEqual(RES["corpus"]["chains"], len(rows)); self.assertEqual(RES["corpus"]["leaks"], sum(r["leak"] for r in rows)); self.assertEqual(len(rows), 252)
        for k, v in RES["baselines"].items(): self.assertEqual(v["tp"] + v["fp"] + v["fn"] + v["tn"] + v["unknown"], sum(1 for r in rows if not r["blind"]), k)
    def test_baseline_shape_honest(self):
        b = RES["baselines"]; self.assertEqual(b["D0"]["tp"], 0); self.assertGreater(b["D3"]["fpr"], .3); self.assertEqual(b["emergence"]["unknown_that_leaked"], 2); self.assertEqual(b["emergence_refined"]["fp"], 0)
    def test_curves_have_cis_and_zero_contradictions(self):
        for m, pts in RES["discovery"]["curves"].items():
            self.assertEqual([p["budget"] for p in pts], list(X.BUDGETS))
            for p in pts: self.assertEqual(p["oracle_contradictions"], 0); self.assertEqual(len(p["recall_ci"]), 2)
            rec = [p["recall"] for p in pts]; self.assertEqual(rec, sorted(rec))        # monotone for the deterministic (guided) modes
        g = RES["discovery"]["curves"]["guided"]; self.assertLess(g[0]["recall"], g[-1]["recall"]); self.assertLess(g[-1]["verified_precision"], 1.0)
    def test_unmodeled_misses_reported(self):
        self.assertEqual(RES["discovery"]["positive_worlds_only_via_unmodeled_C"], ["W28", "W30"]); self.assertLess(RES["discovery"]["curves"]["guided"][-1]["recall"], 1.0)
    def test_witness_and_control(self):
        w = RES["witness"]; self.assertTrue(w["oracle"]["leak_to_B"]); self.assertFalse(w["control_same_endpoint_with_hash"]["oracle"]["leak_to_B"]); self.assertGreaterEqual(w["control_same_endpoint_with_hash"]["oracle"]["per_endpoint"]["B"]["conns"], 1)
    def test_docs_current(self):
        import subprocess, sys
        self.assertEqual(subprocess.run([sys.executable, os.path.join(ROOT, "scripts/p39_report.py"), "--check"], capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run([sys.executable, os.path.join(ROOT, "scripts/p39_run.py"), "--check"], capture_output=True).returncode, 0)


class Completeness(unittest.TestCase):
    def test_every_oracle_leak_on_modeled_endpoints_is_enumerated(self):
        s = S.library_summaries(); e = M.Endpoints(1, 2, 3); full = M.search(s, e, budget=10 ** 6); keys = {[x.op + ":" + x.target for x in c.steps].__repr__() for c in full["candidates"]}
        leaks = [r["chain"] for r in RES["corpus"]["rows"] if r["leak"] and not r["blind"] and "/C" not in r["chain"] and ":C/" not in r["chain"]]; self.assertTrue(leaks)
        for ch in leaks:
            parts = ch.replace("A/redir->B", "A|redir->B").split("/"); ops = [p.replace("A|redir->B", "A/redir->B") for p in parts]
            self.assertIn(repr([o if ":" in o else o + ":" for o in ops]), keys, ch)


if __name__ == "__main__": unittest.main()
