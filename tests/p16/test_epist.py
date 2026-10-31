import ast, json, unittest
from pathlib import Path
from horizon.epist import assess as E
from bench.p16 import fixtures as F, run as R

NOW = 10_000.0; K = {"a1": b"k1", "a2": b"k2"}


def ev(i, roots, att="a1", **o):
    e = {"id": i, "prop": "p", "addresses": "ct", "kind": "k", "scope": "s", "resource": "r" + i, "resource_version": "v1", "observed_at": NOW - 10, "ttl": 1000, "value": "supports", "schema": "s1", "roots": roots, "attestor": att}; e.update(o); e["attestation"] = E.attest_mac(K[att], e); return e


def view(**o): return E.View(NOW, {}, set(), dict(K), {}, {}, **{}) if not o else E.View(**{**dict(now=NOW, attestor_keys=dict(K)), **o})
P = E.Prop("p", "ct", "s", "d")


def st(evs, v=None, prop=P, props=None): return E.assess(prop, evs, v or view(), props)


class Assess(unittest.TestCase):
    def test_verified_needs_two_independent(self):
        self.assertEqual(st([ev("1", ["A"]), ev("2", ["B"], "a2")])["state"], "VERIFIED"); self.assertEqual(st([ev("1", ["A"])])["state"], "UNVERIFIED"); self.assertEqual(st([])["state"], "UNKNOWN")
    def test_circular_shared_root_counts_once_transitively(self):
        self.assertEqual(st([ev("1", ["A"]), ev("2", ["A", "B"], "a2")])["state"], "UNVERIFIED")
        self.assertEqual(st([ev("1", ["A"]), ev("2", ["A", "B"], "a2"), ev("3", ["B"])])["state"], "UNVERIFIED")      # A-B chain collapses all three
        self.assertEqual(st([ev("1", ["A"]), ev("2", ["B"], "a2"), ev("3", ["B"])])["state"], "VERIFIED")
    def test_each_drop_reason(self):
        good = ev("g", ["G"], "a2")
        cases = {"IRRELEVANT": ev("1", ["A"], addresses="other"), "IRRELEVANT ": ev("1", ["A"], scope="other"), "STALE": ev("1", ["A"], observed_at=NOW - 2000), "SCHEMA_INCOMPATIBLE": ev("1", ["A"], schema="s0"), "BAD_ATTESTATION": ev("1", ["A"], attestor="zz")}
        for want, e in cases.items():
            if want == "BAD_ATTESTATION": e["attestor"] = "zz"; 
            r = st([e, good], view(schemas={"ct": {"s1"}})); self.assertIn(want.strip(), [d[1] for d in r["dropped"]], want); self.assertNotEqual(r["state"], "VERIFIED")
        r = st([ev("1", ["A"]), good], view(withdrawn={"1"})); self.assertEqual(r["dropped"], [["1", "WITHDRAWN"]])
        r = st([ev("1", ["A"]), good], view(current_versions={"r1": "v2"})); self.assertEqual(r["dropped"], [["1", "OVERWRITTEN"]])
        e = ev("1", ["A"]); e["value"] = "contradicts"; self.assertEqual(st([e, good])["state"], "UNVERIFIED")      # tamper after MAC: attestation fails
    def test_tampered_after_attestation(self):
        e = ev("1", ["A"]); e["value"] = "contradicts"; r = st([e, ev("2", ["B"], "a2")]); self.assertEqual(r["dropped"], [["1", "BAD_ATTESTATION"]])
    def test_conflict_and_contradiction(self):
        c = ev("3", ["C"], value="contradicts"); self.assertEqual(st([ev("1", ["A"]), ev("2", ["B"], "a2"), c])["state"], "CONFLICTED"); r = st([c]); self.assertEqual(r["state"], "UNVERIFIED"); self.assertIn("claim is contradicted by valid evidence", r["need"])
    def test_stale_state_only_when_nothing_valid(self):
        old = [ev("1", ["A"], observed_at=NOW - 5000), ev("2", ["B"], "a2", observed_at=NOW - 5000)]; self.assertEqual(st(old)["state"], "STALE"); self.assertEqual(st(old + [ev("3", ["C"])])["state"], "UNVERIFIED")
    def test_kinds_and_policy(self):
        v = view(policy={("d", "ct"): E.Obligation(100, 1, frozenset({"k2"}))}); self.assertIn("IRRELEVANT", [d[1] for d in st([ev("1", ["A"])], v)["dropped"]])
        v = view(policy={("d", "ct"): E.Obligation(5, 1, None)}); self.assertEqual(st([ev("1", ["A"])], v)["state"], "STALE")           # obligation max_age tighter than evidence ttl
        v = view(policy={("d", "ct"): E.Obligation(1000, 1, None)}); self.assertEqual(st([ev("1", ["A"])], v)["state"], "VERIFIED")
    def test_dependencies(self):
        q = E.Prop("q", "ct", "s", "d", deps=("p",)); props = {"p": P, "q": q}; e = lambda i, pr, r, att="a1": dict(ev(i, r, att), prop=pr)
        def mk(i, pr, r, att="a1"):
            x = ev(i, r, att); x["prop"] = pr; x["attestation"] = E.attest_mac(K[att], x); return x
        good = [mk("q1", "q", ["Q1"]), mk("q2", "q", ["Q2"], "a2")]
        r = E.assess(q, good, view(), props); self.assertEqual(r["state"], "UNVERIFIED"); self.assertTrue(any("dependency p" in n for n in r["need"]))
        self.assertEqual(E.assess(q, good + [mk("p1", "p", ["P1"]), mk("p2", "p", ["P2"], "a2")], view(), props)["state"], "VERIFIED")
        cyc = {"p": E.Prop("p", "ct", "s", "d", deps=("q",)), "q": q}; self.assertEqual(E.assess(q, good, view(), cyc)["state"], "UNVERIFIED")
    def test_gate_review_with_reverify_and_noop(self):
        props = {"p": P}; g = E.gate(True, ["p"], [ev("1", ["A"])], view(), props); self.assertEqual(g["decision"], "REVIEW"); self.assertTrue(g["reverify"][0]["need"])
        self.assertEqual(E.gate(True, ["p"], [ev("1", ["A"]), ev("2", ["B"], "a2")], view(), props)["decision"], "ALLOW"); self.assertEqual(E.gate(False, [], [], view(), props)["decision"], "ALLOW")
        self.assertEqual(E.gate(True, [], [], view(), props)["decision"], "REVIEW")        # no declared evidentiary basis


class Fixtures(unittest.TestCase):
    def test_detector_is_truth_blind(self):
        src = Path(E.__file__).read_text(); tree = ast.parse(src); mods = {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        self.assertFalse(any("bench" in m or "fixtures" in m for m in mods)); self.assertNotIn("TruthRegistry", src); self.assertNotIn("harmful", src)
    def test_observable_has_no_truth(self):
        cases, truth = F.build(per=1); o = cases[0].observable(); self.assertEqual(set(o), {"view", "props", "evidence", "deps", "sources", "consequential"})
        self.assertNotIn("truth", json.dumps(o, default=str).lower()); self.assertFalse(hasattr(cases[0], "claim_true"))
    def test_deterministic(self):
        a, _ = F.build(per=1); b, _ = F.build(per=1); self.assertEqual([c.id for c in a], [c.id for c in b])
    def test_policy_authored_from_train_only(self):
        cases, _ = F.build(per=1); pol = cases[0].view.policy; self.assertEqual({d for d, _ in pol}, {"finance", "healthcare"})
    def test_results_and_documented_limit(self):
        cases, truth = F.build(per=2); rows = R.evaluate(cases, truth, F.s_epistemic); by = {}
        for r in rows: by.setdefault(r["kind"], []).append(r)
        for k in F.ATTACKS:
            allowed = all(r["allowed"] for r in by[k])
            self.assertEqual(allowed, k == "collusion_independent", k)           # only independent collusion evades; documented limitation
        for k in F.BENIGN: self.assertTrue(all(r["allowed"] for r in by[k]), k)  # no blanket denial of noisy but harmless evidence
        tr = R.evaluate(cases, truth, F.s_trust); self.assertTrue(any(not r["allowed"] for r in tr if not r["harm"]))
        lg = R.summarize(R.evaluate(cases, truth, F.s_legacy)); ep = R.summarize(rows); self.assertLess(ep["harm_allowed"], lg["harm_allowed"])
    def test_committed_result_matches_claims(self):
        r = json.load(open("results/v2/p16-epistemic/result.json")); self.assertEqual(r["deployable"]["epistemic"]["false_blocks"], 0); self.assertEqual(r["by_attack_kind"]["collusion_independent"]["epistemic"], 30)
        self.assertGreater(r["deployable"]["epistemic"]["harm_allowed"], 0)


if __name__ == "__main__": unittest.main()
