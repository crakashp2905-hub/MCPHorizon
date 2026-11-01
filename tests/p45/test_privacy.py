import base64, json, math, os, random, re, shutil, subprocess, sys, tempfile, threading, unittest
from fractions import Fraction
from horizon.hpolicy.authority import HorizonPolicy, EvidenceError
from horizon.privacy import ledger as LG, service as SV, units as U, mechanisms as MX, accountant as AC, reference as REF, carriers as CA, baselines as BL, scenarios as SC, experiment as EX
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); D = os.path.join(ROOT, "results/v2/p45-privacy")
LAP = MX.laplace_charge


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p45t-"); self.now = [1000.0]; self.a = HorizonPolicy("pol-1", clock=lambda: self.now[0]); self.owner = self.a.register_issuer("privacy-owner", {"ATTESTATION"}); self.lid = U.ledger_id("d")
    def tearDown(self): shutil.rmtree(self.tmp, ignore_errors=True)
    def tok(self, eps="2", delta="1e-6", acc="basic", ver=1, ds="d", lid=None, claim_extra=None, **kw):
        c = {"type": "privacy-budget", "dataset": ds, "eps": eps, "delta": delta, "accountant": acc, **(claim_extra or {})}
        return self.owner.issue("ATTESTATION", principal="owner", artifact=lid or U.ledger_id(ds), args_digest=kw.pop("digest", LG.digest(c)), object_version=ver, ttl=kw.pop("ttl", 10 ** 8), claim=c, now=1000)
    def led(self, path=None, **kw):
        l = LG.Ledger(path or os.path.join(self.tmp, "l.db"), self.a.verifier(), lambda: self.now[0], **kw); l.open_budget(self.tok(**{k: v for k, v in kw.items() if k in ()})); return l


class Mechanisms(unittest.TestCase):
    def test_stream_deterministic_and_keyed(self):
        a, b, c = MX.Stream(b"k", "r1"), MX.Stream(b"k", "r1"), MX.Stream(b"k", "r2"); xs = [a.u() for _ in range(5)]; self.assertEqual(xs, [b.u() for _ in range(5)]); self.assertNotEqual(xs, [c.u() for _ in range(5)]); self.assertTrue(all(0 < x < 1 for x in xs))
    def test_discrete_laplace_distribution(self):
        eps, n = 0.5, 20000; zs = [MX.discrete_laplace(MX.Stream(b"k", "s%d" % i), eps, 1) for i in range(n)]; alpha = math.exp(-eps)
        self.assertAlmostEqual(sum(zs) / n, 0.0, delta=0.08); self.assertAlmostEqual(sum(1 for z in zs if z == 0) / n, (1 - alpha) / (1 + alpha), delta=0.012); self.assertAlmostEqual(sum(1 for z in zs if z == 1) / n, (1 - alpha) / (1 + alpha) * alpha, delta=0.012)
    def test_sensitivity_scales_noise(self):
        s1 = sum(abs(MX.discrete_laplace(MX.Stream(b"k", "a%d" % i), 1.0, 1)) for i in range(4000)) / 4000; s5 = sum(abs(MX.discrete_laplace(MX.Stream(b"k", "a%d" % i), 1.0, 5)) for i in range(4000)) / 4000; self.assertGreater(s5, 3 * s1)
    def test_gaussian_calibration_and_rho(self):
        c = MX.gaussian_charge("0.5", "1e-6", 2); self.assertAlmostEqual(c["sigma"], 2 * math.sqrt(2 * math.log(1.25e6)) / 0.5); self.assertAlmostEqual(MX.rho_of(c), 4 / (2 * c["sigma"] ** 2))
        xs = [MX.gaussian(MX.Stream(b"k", "g%d" % i), 3.0) for i in range(8000)]; m = sum(xs) / len(xs); sd = math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs)); self.assertAlmostEqual(sd, 3.0, delta=0.15)
    def test_invalid_parameters_rejected(self):
        for e, d in (("1", "1e-6"), ("0", "1e-6"), ("0.5", "0"), ("0.5", "1")): self.assertRaises(ValueError, MX.gaussian_charge, e, d, 1)
    def test_laplace_rho(self): self.assertAlmostEqual(MX.rho_of(LAP("0.4", 1)), 0.08)


class Accountants(unittest.TestCase):
    B = {"eps": "1", "delta": "1e-6"}
    def test_basic_exact_in_rationals(self):
        self.assertTrue(AC.fits("basic", self.B, [LAP("0.1", 1)] * 10)[0]); self.assertFalse(AC.fits("basic", self.B, [LAP("0.1", 1)] * 11)[0])            # 10 x 0.1 == 1 exactly (floats would say 0.9999999999999999 or 1.0000000000000002)
        self.assertEqual(AC.basic({"eps": "0.3", "delta": "0"}, [LAP("0.1", 1)] * 3)[0], True)
    def test_basic_delta_enforced(self): self.assertFalse(AC.fits("basic", {"eps": "5", "delta": "1e-6"}, [MX.gaussian_charge("0.1", "1e-6", 1)] * 2)[0])
    def test_advanced_known_value(self):
        k, e = 100, 0.01; A = k * e * (math.exp(e) - 1) / (math.exp(e) + 1); B = k * e * e; exp = A + math.sqrt(2 * B * math.log(1e6)); ok, sp = AC.advanced(self.B, [LAP("0.01", 1)] * k)
        self.assertAlmostEqual(sp["eps"], min(k * e, exp), places=9); self.assertEqual(sp["branch"], "advanced" if exp < k * e else "basic")
    def test_advanced_never_looser_than_basic_and_beats_it_for_many_small(self):
        self.assertFalse(AC.fits("basic", self.B, [LAP("0.01", 1)] * 101)[0]); self.assertTrue(AC.fits("advanced", self.B, [LAP("0.01", 1)] * 101)[0])
        for k in range(1, 40): self.assertTrue(not AC.fits("basic", self.B, [LAP("0.1", 1)] * k)[0] or AC.fits("advanced", self.B, [LAP("0.1", 1)] * k)[0])
    def test_advanced_heterogeneous_delta(self):
        ch = [MX.gaussian_charge("0.5", "1e-7", 1)] * 3 + [LAP("0.1", 1)] * 5; ok, sp = AC.advanced({"eps": "10", "delta": "1e-6"}, ch); self.assertTrue(ok)
        self.assertFalse(AC.fits("advanced", {"eps": "10", "delta": "1e-8"}, [MX.gaussian_charge("0.5", "1e-7", 1)] * 3)[0])          # total delta alone exceeds the budget
    def test_zcdp_closed_form(self):
        L = math.log(1e6); rmax = (math.sqrt(L + 1) - math.sqrt(L)) ** 2; n = int(rmax / MX.rho_of(LAP("0.01", 1))); self.assertTrue(AC.fits("zcdp", self.B, [LAP("0.01", 1)] * n)[0]); self.assertFalse(AC.fits("zcdp", self.B, [LAP("0.01", 1)] * (n + 2))[0])
    def test_zcdp_gaussian_beats_basic(self): self.assertGreater(EX._answered_before_denial("zcdp", lambda: MX.gaussian_charge("0.1", "1e-8", 1), {"eps": "2", "delta": "1e-6"}), 5 * EX._answered_before_denial("basic", lambda: MX.gaussian_charge("0.1", "1e-8", 1), {"eps": "2", "delta": "1e-6"}))
    def test_zcdp_needs_delta(self): self.assertRaises(AC.Unsupported, AC.fits, "zcdp", {"eps": "1", "delta": "0"}, [LAP("0.1", 1)])
    def test_unknown_accountant(self): self.assertRaises(AC.Unsupported, AC.fits, "rdp", self.B, [])
    def test_margin_makes_float_accountants_stricter(self):
        L = math.log(1e6); rho = (math.sqrt(L + 1) - math.sqrt(L)) ** 2 * (1 - 1e-11); sigma = math.sqrt(1.0 / (2 * rho)); ch = [{"mech": "gaussian", "sens": 1, "sigma": sigma, "eps": "0.5", "delta": "1e-6"}]
        ok, sp = AC.zcdp({"eps": "1", "delta": "1e-6"}, ch); self.assertLess(sp["eps"], 1.0); self.assertGreater(sp["eps"], 1.0 / (1 + AC.MARGIN)); self.assertFalse(ok)          # below the budget by less than the margin: refused
        self.assertTrue(REF.within([{"op": "charge", "id": "a", **ch[0]}], {"eps": "1", "delta": "1e-6"}, "zcdp"))                                                                 # the exact reference would allow it: the ledger is strictly (and only slightly) stricter
    def test_empty_ledger_fits(self):
        for a in AC.ACCOUNTANTS: self.assertTrue(AC.fits(a, self.B, [])[0])


class Reference(unittest.TestCase):
    def test_independent_of_ledger_code(self):
        src = open(os.path.join(ROOT, "horizon/privacy/reference.py")).read(); self.assertFalse(re.search(r"^\s*(from|import)\s+[.\w]*(horizon|privacy|ledger|accountant|mechanisms)", src, re.M), "reference accountant must not import the code it checks")
    def test_refund_removes_charge(self):
        ev = [{"op": "charge", "id": "a", **LAP("0.5", 1)}, {"op": "charge", "id": "b", **LAP("0.5", 1)}, {"op": "refund", "id": "a"}]; self.assertEqual(REF.costs(ev, "1e-6")["basic"]["eps"], REF.Decimal("0.5"))
    def test_decisions(self):
        ev = [{"op": "charge", "id": str(i), **LAP("0.25", 1)} for i in range(8)]; self.assertTrue(REF.within(ev, {"eps": "2", "delta": "1e-6"}, "basic")); self.assertFalse(REF.within(ev + [{"op": "charge", "id": "z", **LAP("0.25", 1)}], {"eps": "2", "delta": "1e-6"}, "basic"))
    def test_matches_accountant_costs(self):
        ch = [LAP("0.05", 1)] * 30 + [MX.gaussian_charge("0.3", "1e-8", 1)] * 4; ev = [{"op": "charge", "id": str(i), **c} for i, c in enumerate(ch)]; c = REF.costs(ev, "1e-6")
        self.assertAlmostEqual(float(c["zcdp"]["eps"]), AC.zcdp({"eps": "9", "delta": "1e-6"}, ch)[1]["eps"], places=9); self.assertAlmostEqual(float(c["advanced"]["eps"]), AC.advanced({"eps": "9", "delta": "1e-6"}, ch)[1]["eps"], places=9)
    def test_differential_against_ledger(self):
        r = EX.differential(40, 40, seed=7); self.assertTrue(r["agreement"], r); self.assertEqual(r["ledger_allow_ref_deny"], 0); self.assertGreater(r["ledger_allow_ref_allow"], 100); self.assertGreater(r["ledger_deny_ref_deny"], 100)


class LedgerTests(Base):
    def test_budget_requires_valid_owner_token(self):
        l = LG.Ledger(":memory:", self.a.verifier(), lambda: self.now[0])
        other = HorizonPolicy("pol-1"); evil = other.register_issuer("privacy-owner", {"ATTESTATION"}); c = {"type": "privacy-budget", "dataset": "d", "eps": "99", "delta": "0", "accountant": "basic"}
        forged = evil.issue("ATTESTATION", principal="o", artifact=self.lid, args_digest=LG.digest(c), object_version=1, ttl=10 ** 8, claim=c)
        self.assertRaises(EvidenceError, l.open_budget, forged)
        wrong_digest = self.tok(digest="sha256:00"); self.assertRaises(EvidenceError, l.open_budget, wrong_digest)
        self.assertRaises(EvidenceError, l.open_budget, self.tok(acc="rdp"))
        bad_type = self.owner.issue("ATTESTATION", principal="o", artifact=self.lid, args_digest=LG.digest({"type": "x"}), claim={"type": "x"}); self.assertRaises(EvidenceError, l.open_budget, bad_type)
    def test_no_budget_no_release(self):
        l = LG.Ledger(":memory:", self.a.verifier(), lambda: self.now[0]); self.assertEqual(l.reserve(self.lid, "r", "q", LAP("0.1", 1))["reason"], "NO_BUDGET")
    def test_budget_row_tampering_detected(self):
        l = self.led(); l.db.execute("UPDATE budgets SET eps='1000'"); r = l.reserve(self.lid, "r", "q", LAP("0.1", 1)); self.assertEqual(r["reason"], "BUDGET_ROW_TAMPERED")
    def test_version_rollback_refused(self):
        l = self.led(); self.assertRaises(EvidenceError, l.open_budget, self.tok(eps="2", ver=1)); self.assertRaises(EvidenceError, l.open_budget, self.tok(eps="100", ver=1)); l.open_budget(self.tok(eps="1", ver=2)); self.assertEqual(l.spent(self.lid)["n_charged"], 0)
    def test_budget_token_expiry_fails_closed(self):
        l = LG.Ledger(":memory:", self.a.verifier(), lambda: self.now[0]); l.open_budget(self.tok(ttl=100)); self.now[0] += 500; self.assertTrue(l.reserve(self.lid, "r", "q", LAP("0.1", 1))["reason"].startswith("BUDGET_TOKEN_"))
    def test_reserve_begin_commit(self):
        l = self.led(); r = l.reserve(self.lid, "r", "q", LAP("0.5", 1)); self.assertTrue(r["ok"]); self.assertTrue(l.begin(self.lid, "r")["ok"]); c = l.commit(self.lid, "r", 7, "rcpt"); self.assertEqual(c["state"], "COMMITTED"); self.assertEqual(l.states(self.lid)["r"], "COMMITTED")
    def test_commit_requires_start(self): l = self.led(); l.reserve(self.lid, "r", "q", LAP("0.5", 1)); self.assertFalse(l.commit(self.lid, "r", 1, "x")["ok"])
    def test_overcommit_refused(self):
        l = self.led(); self.assertEqual([l.reserve(self.lid, "r%d" % i, "q", LAP("0.5", 1))["ok"] for i in range(5)], [True] * 4 + [False])
    def test_idempotent_reserve_not_double_charged(self):
        l = self.led(); [l.reserve(self.lid, "same", "q", LAP("0.5", 1)) for _ in range(10)]; self.assertEqual(l.spent(self.lid)["n_charged"], 1)
    def test_replay_returns_stored_answer(self):
        l = self.led(); l.reserve(self.lid, "r", "q", LAP("0.5", 1)); l.begin(self.lid, "r"); l.commit(self.lid, "r", 41, "rc"); r = l.reserve(self.lid, "r", "q", LAP("0.5", 1)); self.assertEqual((r["replayed"], r["answer"], r["receipt"]), (True, 41, "rc"))
    def test_request_id_reuse_with_other_query_refused(self):
        l = self.led(); l.reserve(self.lid, "r", "q1", LAP("0.5", 1)); self.assertEqual(l.reserve(self.lid, "r", "q2", LAP("0.5", 1))["reason"], "REQUEST_ID_REUSE")
    def test_cancel_before_start_refunds(self):
        l = self.led(); [l.reserve(self.lid, "r%d" % i, "q", LAP("0.5", 1)) for i in range(4)]; self.assertFalse(l.reserve(self.lid, "x", "q", LAP("0.5", 1))["ok"]); self.assertTrue(l.cancel(self.lid, "r0")["refunded"]); self.assertTrue(l.reserve(self.lid, "y", "q", LAP("0.5", 1))["ok"])
    def test_cancel_after_start_does_not_refund(self):
        l = self.led(); [l.reserve(self.lid, "r%d" % i, "q", LAP("0.5", 1)) for i in range(4)]; l.begin(self.lid, "r0"); self.assertFalse(l.cancel(self.lid, "r0")["refunded"]); self.assertEqual(l.states(self.lid)["r0"], "ABANDONED"); self.assertFalse(l.reserve(self.lid, "y", "q", LAP("0.5", 1))["ok"])
    def test_cancel_after_commit_is_noop(self):
        l = self.led(); l.reserve(self.lid, "r", "q", LAP("0.5", 1)); l.begin(self.lid, "r"); l.commit(self.lid, "r", 1, "x"); self.assertFalse(l.cancel(self.lid, "r").get("refunded")); self.assertEqual(l.states(self.lid)["r"], "COMMITTED")
    def test_timeout_refunds_only_unstarted(self):
        l = self.led(); [l.reserve(self.lid, "r%d" % i, "q", LAP("0.5", 1), ttl=10) for i in range(4)]; l.begin(self.lid, "r0"); self.now[0] += 100
        self.assertTrue(l.reserve(self.lid, "new", "q", LAP("0.5", 1))["ok"]); st = l.states(self.lid); self.assertEqual((st["r0"], st["r1"]), ("STARTED", "EXPIRED"))
        self.assertEqual(l.spent(self.lid)["n_charged"], 2)
    def test_late_commit_of_started_request_allowed_once(self):
        l = self.led(); l.reserve(self.lid, "r", "q", LAP("0.5", 1), ttl=10); l.begin(self.lid, "r"); self.now[0] += 100; self.assertTrue(l.commit(self.lid, "r", 5, "x")["ok"]); self.assertTrue(l.commit(self.lid, "r", 999, "y")["replayed"]); self.assertEqual(l.reserve(self.lid, "r", "q", LAP("0.5", 1))["answer"], 5)
    def test_expired_request_cannot_be_started_or_replayed(self):
        l = self.led(); l.reserve(self.lid, "r", "q", LAP("0.5", 1), ttl=10); self.now[0] += 100; self.assertFalse(l.begin(self.lid, "r")["ok"]); self.assertEqual(l.reserve(self.lid, "r", "q", LAP("0.5", 1))["reason"], "RESERVATION_EXPIRED")
    def test_cancelled_request_id_not_reusable(self): l = self.led(); l.reserve(self.lid, "r", "q", LAP("0.5", 1)); l.cancel(self.lid, "r"); self.assertEqual(l.reserve(self.lid, "r", "q", LAP("0.5", 1))["reason"], "CANCELLED")
    def test_hash_chain_and_audit(self):
        l = self.led(); [l.reserve(self.lid, "r%d" % i, "q", LAP("0.1", 1)) for i in range(5)]; l.cancel(self.lid, "r1"); self.assertTrue(l.verify_chain()); self.assertEqual(l.audit(self.lid), [])
        l.db.execute("UPDATE entries SET body=replace(body,'r2','r9') WHERE seq=4"); self.assertFalse(l.verify_chain())
    def test_audit_detects_state_edit(self):
        l = self.led(); l.reserve(self.lid, "r", "q", LAP("0.1", 1)); l.db.execute("UPDATE res SET state='CANCELLED'"); self.assertEqual(l.audit(self.lid), ["r"])
    def test_task_and_tenant_allocations_only_restrict(self):
        l = self.led(); c = {"type": "privacy-alloc", "kind": "task", "scope": "t1", "eps": "0.5", "delta": "1e-6"}; l.allocate(self.owner.issue("ATTESTATION", principal="o", artifact=self.lid, args_digest=LG.digest(c), ttl=10 ** 8, claim=c, now=1000))
        self.assertTrue(l.reserve(self.lid, "a", "q", LAP("0.5", 1), task="t1")["ok"]); self.assertEqual(l.reserve(self.lid, "b", "q", LAP("0.25", 1), task="t1")["reason"], "TASK_ALLOCATION_EXCEEDED"); self.assertTrue(l.reserve(self.lid, "c", "q", LAP("0.25", 1), task="t2")["ok"])
        c2 = {"type": "privacy-alloc", "kind": "tenant", "scope": "acme", "eps": "5", "delta": "1e-6"}; l.allocate(self.owner.issue("ATTESTATION", principal="o", artifact=self.lid, args_digest=LG.digest(c2), ttl=10 ** 8, claim=c2, now=1000))
        self.assertTrue(l.reserve(self.lid, "d", "q", LAP("1", 1), tenant="acme")["ok"]); self.assertEqual(l.reserve(self.lid, "e", "q", LAP("1", 1), tenant="acme")["reason"], "BUDGET_EXCEEDED")          # a large allocation never lifts the dataset cap
    def test_bad_allocation_rejected(self):
        l = self.led(); c = {"type": "privacy-alloc", "kind": "user", "scope": "x", "eps": "1", "delta": "0"}; self.assertRaises(EvidenceError, l.allocate, self.owner.issue("ATTESTATION", principal="o", artifact=self.lid, args_digest=LG.digest(c), claim=c, now=1000))
    def test_charged_events_match_state(self):
        l = self.led(); [l.reserve(self.lid, "r%d" % i, "q", LAP("0.1", 1), ttl=5) for i in range(4)]; l.cancel(self.lid, "r0"); l.begin(self.lid, "r1"); self.now[0] += 50; l.begin(self.lid, "none")
        live = {e["id"] for e in REF._live(l.charged_events(self.lid))}; self.assertEqual(live, {"r1"})
    def test_concurrent_threads_never_overcommit(self):
        r = EX.concurrency(procs=6, per=25, trials=2)
        for t in r["trials"]:
            if t["atomic"]: self.assertEqual(t["overcommit"], 0, t); self.assertEqual(t["granted"], r["max_allowed"]); self.assertEqual(t["audit"], []); self.assertTrue(t["chain_ok"])
    def test_non_atomic_ablation_does_overcommit(self):
        r = EX.concurrency(procs=6, per=25, trials=2); self.assertTrue(any(t["overcommit"] > 0 for t in r["trials"] if not t["atomic"]))
    def test_multiprocess_no_overcommit(self):
        path = os.path.join(self.tmp, "mp.db"); l = self.led(path); l.close()
        import multiprocessing as mp
        ctx = mp.get_context("fork"); q = ctx.Queue()
        def work(w):
            lg = LG.Ledger(path, self.a.verifier(), lambda: 1000.0); n = 0
            for i in range(30): n += lg.reserve(self.lid, "p%d-%d" % (w, i), "q", LAP("0.25", 1))["ok"]
            q.put(n)
        ps = [ctx.Process(target=work, args=(w,)) for w in range(5)]; [p.start() for p in ps]; [p.join() for p in ps]; tot = sum(q.get() for _ in ps)
        self.assertEqual(tot, 8); l2 = LG.Ledger(path, self.a.verifier(), lambda: 1000.0); self.assertTrue(l2.verify_chain()); self.assertEqual(l2.audit(self.lid), [])


class ServiceTests(Base):
    def mk(self, **kw):
        self.led_ = self.led(); self.approver = self.a.register_issuer("data-approver", {"APPROVAL"}); self.d = SV.Dataset("d", seed=3); self.pub = SV.Dataset("pub", public=True)
        s = SV.Service([self.d, self.pub], self.led_, self.a.verifier(), **kw); s.add_principal("ag", "t1", dp=["d"], raw=["d"], purposes=["audit"]); s.add_principal("noraw", "t1", dp=["d"]); return s
    Q = {"dataset": "d", "agg": "count", "where": [["dept", "==", "eng"]], "eps": "0.5"}
    def test_dp_answer_and_receipt(self):
        s = self.mk(); r = s.query("ag", {**self.Q, "request_id": "r1"}); self.assertEqual(r["status"], "OK"); rec = SV.verify_receipt(r["receipt"], s.pub()); self.assertEqual((rec["eps"], rec["mech"], rec["answer"]), ("0.5", "laplace", r["answer"]))
        tampered = r["receipt"][:-4] + "AAAA"; self.assertIsNone(SV.verify_receipt(tampered, s.pub())); self.assertIsNone(SV.verify_receipt(r["receipt"], Signer_pub()))
    def test_replay_same_answer_charged_once(self):
        s = self.mk(); rs = [s.query("ag", {**self.Q, "request_id": "r1"}) for _ in range(5)]; self.assertEqual({r["answer"] for r in rs}, {rs[0]["answer"]}); self.assertEqual(self.led_.spent(self.lid)["n_charged"], 1)
    def test_budget_shared_across_principals(self):
        s = self.mk(); s.add_principal("ag2", "t2", dp=["d"]); out = [s.query("ag" if i % 2 else "ag2", {**self.Q, "eps": "0.5", "request_id": "r%d" % i})["status"] for i in range(6)]; self.assertEqual(out, ["OK"] * 4 + ["DENY"] * 2)
    def test_unknown_principal_dataset_and_authz(self):
        s = self.mk(); self.assertEqual(s.query("ghost", {**self.Q, "request_id": "r"})["reason"], "UNKNOWN_PRINCIPAL"); self.assertEqual(s.query("ag", {**self.Q, "dataset": "x", "request_id": "r"})["reason"], "UNKNOWN_DATASET")
        s.add_principal("nodp", "t", raw=["d"], purposes=["audit"]); self.assertEqual(s.query("nodp", {**self.Q, "request_id": "r"})["reason"], "NOT_AUTHORIZED_DP")
    def test_ledger_is_derived_not_chosen(self):
        s = self.mk(); self.assertEqual(s.query("ag", {**self.Q, "request_id": "r"}, ctx={"ledger": U.ledger_id("other")})["reason"], "LEDGER_MISMATCH"); self.assertEqual(s.query("ag", {**self.Q, "request_id": "r2"}, ctx={"ledger": self.lid, "task": "t"})["status"], "OK")
    def test_caller_bounds_and_bad_input_rejected(self):
        s = self.mk(); q = {"dataset": "d", "agg": "sum", "column": "salary", "where": [], "eps": "0.5", "request_id": "r"}
        self.assertEqual(s.query("ag", {**q, "bounds": [0, 1]})["reason"], "CALLER_BOUNDS_REJECTED"); self.assertEqual(s.query("ag", {**q, "request_id": "r2", "bounds": list(self.d.bounds["salary"])})["status"], "OK")
        self.assertEqual(s.query("ag", {**q, "agg": "max"})["reason"], "UNSUPPORTED_AGGREGATE"); self.assertEqual(s.query("ag", {**q, "column": "dept"})["reason"], "UNSUPPORTED_COLUMN"); self.assertEqual(s.query("ag", {**q, "where": [["x", "==", 1]]})["reason"], "BAD_PREDICATE")
        self.assertEqual(s.query("ag", {**q, "request_id": None})["reason"], "NO_REQUEST_ID"); self.assertEqual(s.query("ag", {**q, "request_id": "r9", "eps": "-1"})["reason"], "BAD_EPS")
    def test_sum_sensitivity_is_declared_bound(self):
        s = self.mk(); self.assertEqual(s.sensitivity(self.d, {"agg": "count"}), 1); self.assertEqual(s.sensitivity(self.d, {"agg": "sum", "column": "salary"}), 200000)
    def test_public_dataset_needs_no_budget(self):
        s = self.mk(); self.assertTrue(all(s.query("noraw", {"dataset": "pub", "agg": "count", "where": [["id", "==", "target"]], "eps": "9", "request_id": "p%d" % i})["status"] == "OK" for i in range(50))); self.assertEqual(self.led_.spent(self.lid)["n_charged"], 0)
    def test_gaussian_path(self):
        s = self.mk(); r = s.query("ag", {**self.Q, "mech": "gaussian", "eps": "0.5", "delta": "1e-7", "request_id": "g1"}); self.assertEqual(r["status"], "OK"); self.assertEqual(SV.verify_receipt(r["receipt"], s.pub())["mech"], "gaussian")
        self.assertEqual(s.query("ag", {**self.Q, "mech": "gaussian", "eps": "2", "delta": "1e-7", "request_id": "g2"})["reason"].split(":")[0], "BAD_MECHANISM_PARAMS")
    def test_timeout_hook_charges_and_leaks(self):
        s = self.mk(); r = s.query("ag", {**self.Q, "request_id": "t1", "_fail_after_mechanism": True}); self.assertEqual(r["status"], "TIMEOUT"); self.assertEqual(self.led_.states(self.lid)["t1"], "STARTED"); self.assertFalse(self.led_.cancel(self.lid, "t1")["refunded"])
    def test_raw_requires_authorization_purpose_and_min_cell(self):
        s = self.mk(); q = {"dataset": "d", "agg": "count", "where": [["dept", "==", "eng"]], "mode": "raw", "purpose": "audit", "request_id": "w"}
        self.assertEqual(s.query("noraw", q)["reason"], "NOT_AUTHORIZED_RAW"); self.assertEqual(s.query("ag", {**q, "purpose": "marketing"})["reason"], "NOT_AUTHORIZED_RAW"); self.assertEqual(s.query("ag", q)["status"], "OK")
        r = s.query("ag", {**q, "where": [["id", "==", "target"]]}); self.assertEqual((r["reason"], r["n"]), ("MIN_CELL_COUNT", 1)); self.assertEqual(self.led_.spent(self.lid)["n_charged"], 0)          # raw answers are never charged to the DP ledger
    def test_differencing_guard(self):
        s = self.mk(); q = {"dataset": "d", "agg": "sum", "column": "salary", "mode": "raw", "purpose": "audit", "request_id": "w"}; self.assertEqual(s.query("ag", {**q, "where": [["dept", "==", "legal"]]})["status"], "OK")
        self.assertEqual(s.query("ag", {**q, "where": [["dept", "==", "legal"], ["salary", "<", 199999]]})["reason"], "DIFFERENCING_RISK")
    def test_export_needs_bound_approval(self):
        s = self.mk(); dg = LG.digest({"op": "export", "dataset": "d", "purpose": "audit"}); tok = self.approver.issue("APPROVAL", principal="ag", artifact="d", args_digest=dg, ttl=600, claim={"purpose": "audit"}, now=1000)
        r = s.export_rows("ag", "d", "audit", tok); self.assertEqual((r["status"], r["dp"]), ("OK", False)); self.assertEqual(self.led_.spent(self.lid)["n_charged"], 0)
        self.assertEqual(s.export_rows("noraw", "d", "audit", tok)["reason"], "APPROVAL_NOT_BOUND_TO_THIS_EXPORT"); self.assertEqual(s.export_rows("ag", "d", "marketing", tok)["reason"], "APPROVAL_NOT_BOUND_TO_THIS_EXPORT")
        self.assertTrue(s.export_rows("ag", "d", "audit", "junk")["reason"].startswith("APPROVAL_")); self.assertEqual(len(s.access_log), 1)
    def test_dp_and_raw_paths_share_no_accounting(self):
        import inspect
        raw = inspect.getsource(SV.Service._raw); self.assertNotIn("led", raw.replace("lead", "")); self.assertNotIn("charge", raw); self.assertNotIn("AC.", raw); dp = inspect.getsource(SV.Service._dp); self.assertNotIn("raw_sets", dp)
    def test_release_log_records_every_dp_answer(self):
        s = self.mk(); [s.query("ag", {**self.Q, "request_id": "r%d" % i}) for i in range(3)]; self.assertEqual(len([e for e in s.release_log if e["kind"] == "dp"]), 3)


def Signer_pub():
    from horizon.authz.keys import Signer
    return Signer.generate("x", "y").public_raw()


class Carriers(Base):
    def test_roundtrip(self):
        c = CA.make("d", "task-9", ["root"])
        self.assertEqual(CA.from_mcp(CA.to_mcp(c, {"name": "q", "_meta": {"progressToken": 1}})), c); self.assertEqual(CA.from_utcp(CA.to_utcp(c, {"X-Other": "1"})), c); self.assertEqual(CA.from_codemode(CA.to_codemode(c, {"x": 1})), c)
        self.assertIsNone(CA.from_mcp({})); self.assertIsNone(CA.from_utcp({}))
    def test_delegation_chain_and_depth(self):
        c = CA.make("d", "t")
        for i in range(CA.MAX_DEPTH): c = CA.delegate(c, "a%d" % i)
        self.assertRaises(ValueError, CA.delegate, c, "too-deep"); self.assertEqual(c["chain"], ["a0", "a1", "a2", "a3"])
    def test_same_ledger_charged_through_every_carrier(self):
        led = self.led(); s = SV.Service([SV.Dataset("d", seed=2)], led, self.a.verifier()); s.add_principal("ag", "t", dp=["d"]); ctx = CA.make("d", "t1"); q = {"dataset": "d", "agg": "count", "where": [], "eps": "0.25"}
        for i, (enc, dec, carrier) in enumerate(((CA.to_mcp, CA.from_mcp, {"name": "q"}), (CA.to_utcp, CA.from_utcp, {}), (CA.to_codemode, CA.from_codemode, {}))):
            c = dec(enc(CA.delegate(ctx, "sub%d" % i), carrier)); self.assertEqual(s.query("ag", {**q, "request_id": "c%d" % i}, c)["status"], "OK")
        self.assertEqual(led.spent(self.lid)["n_charged"], 3); self.assertEqual(led.spent(self.lid)["eps"], 0.75)
    def test_forged_ledger_in_any_carrier_refused(self):
        led = self.led(); s = SV.Service([SV.Dataset("d", seed=2)], led, self.a.verifier()); s.add_principal("ag", "t", dp=["d"]); bad = {**CA.make("d", "t"), "ledger": U.ledger_id("zzz")}
        for enc, dec, carrier in ((CA.to_mcp, CA.from_mcp, {}), (CA.to_utcp, CA.from_utcp, {}), (CA.to_codemode, CA.from_codemode, {})): self.assertEqual(s.query("ag", {"dataset": "d", "agg": "count", "where": [], "request_id": "x%s" % enc.__name__}, dec(enc(bad, carrier)))["reason"], "LEDGER_MISMATCH")
    def test_unit_ids(self):
        self.assertNotEqual(U.ledger_id("a"), U.ledger_id("b")); self.assertNotEqual(U.ledger_id("a"), U.ledger_id("a", "task")); self.assertRaises(ValueError, U.ledger_id, "a", "galaxy")


class Scenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.rows = {}
    def r(self, sid, sy, rep=0):
        k = (sid, sy, rep)
        if k not in self.rows: self.rows[k] = SC.run_one(sid, sy, rep)
        return self.rows[k]
    def test_horizon_blocks_every_attack_for_each_accountant(self):
        for sy in ("horizon-basic", "horizon-advanced", "horizon-zcdp"):
            for sid, kind, _f, _n in SC.SCENARIOS:
                if kind == "attack": self.assertFalse(self.r(sid, sy)["over_budget"], (sid, sy))
    def test_horizon_benign_completes(self):
        for sy in ("horizon-basic", "horizon-advanced"):
            for sid, kind, _f, _n in SC.SCENARIOS:
                if kind == "benign": r = self.r(sid, sy); self.assertEqual(r["completed"], r["total"], (sid, sy))
    def test_zcdp_has_a_cost_in_pure_dp_workloads(self): self.assertLess(self.r("B02", "horizon-zcdp")["completed"], 8)
    def test_baselines_each_lose_somewhere(self):
        self.assertTrue(self.r("A01", "per-agent-limit")["over_budget"]); self.assertTrue(self.r("A02", "per-agent-limit")["over_budget"]); self.assertTrue(self.r("A02", "per-principal-accountant")["over_budget"])
        self.assertTrue(self.r("A03", "non-transactional")["over_budget"]); self.assertTrue(self.r("A07", "dlp")["over_budget"]); self.assertTrue(self.r("A10", "token-limit")["over_budget"]); self.assertTrue(self.r("A01", "dlp")["over_budget"])
    def test_each_ablation_loses_its_scenario(self):
        for sy, sid in (("horizon-no-transaction", "A03"), ("horizon-no-abandon", "A06"), ("horizon-no-ledger-derivation", "A04"), ("horizon-no-ledger-derivation", "A09"), ("horizon-no-declared-bounds", "A08"), ("horizon-no-diff-guard", "A07"), ("horizon-no-min-cell", "A10")):
            self.assertTrue(self.r(sid, sy)["over_budget"], (sid, sy))
    def test_no_idempotency_resamples_and_disrupts(self):
        self.assertGreater(self.r("A05", "horizon-no-idempotency")["distinct_answers_one_id"], 1); self.assertEqual(self.r("A05", "horizon-basic")["distinct_answers_one_id"], 1); self.assertLess(self.r("B04", "horizon-no-idempotency")["completed"], 9)
    def test_leaked_answers_count_even_when_cancelled(self):
        r = self.r("A06", "horizon-basic"); self.assertEqual(r["n_observed"], 8); self.assertEqual(r["answered"], 0); self.assertFalse(r["over_budget"])
    def test_chain_and_audit_clean(self):
        for sid in ("A01", "A03", "A06", "B04"): r = self.r(sid, "horizon-basic"); self.assertTrue(r["chain_ok"]); self.assertEqual(r["audit"], [])
    def test_oracle_independent_of_ledger_tables(self):
        import inspect
        for fn in (SC.oracle_dp, SC.dp_observations, SC.llr_target): src = inspect.getsource(fn); self.assertNotIn("env.led", src); self.assertNotIn("sqlite", src)
        self.assertIn("REF.", inspect.getsource(SC.oracle_dp))
    def test_oracle_flags_resampled_request_ids(self): self.assertTrue(self.r("A05", "horizon-no-idempotency")["resampled"]); self.assertFalse(self.r("A05", "horizon-basic")["resampled"])
    def test_per_agent_baseline_limits_sensitive_queries_only(self): self.assertEqual(self.r("B01", "per-agent-limit")["completed"], 60); self.assertLess(self.r("A01", "per-agent-limit")["answered"], 32 + 1)
    def test_oracle_counts_overscaled_noise(self):
        r = self.r("A08", "horizon-no-declared-bounds"); self.assertGreater(r["cost_eps"], 1000)
    def test_matched_public_structure_unrestricted(self): self.assertEqual(self.r("B07", "horizon-basic")["completed"], 32); self.assertEqual(self.r("B01", "horizon-basic")["completed"], 60)
    def test_export_not_dp(self): self.assertTrue(self.r("B03", "horizon-basic")["not_dp"])


class Modules(unittest.TestCase):
    def test_no_self_signing_of_evidence(self):
        for f in ("units", "mechanisms", "accountant", "ledger", "service", "carriers", "baselines", "reference", "experiment"):
            src = open(os.path.join(ROOT, "horizon/privacy", f + ".py")).read(); self.assertNotIn("register_issuer(", src.replace("auth.register_issuer", "")), f; self.assertNotIn(".issue(", src.replace("owner.issue", "").replace("approver.issue", "")), f
    def test_accountant_comparison_claims(self):
        a = EX.accountant_comparison(); l = a["laplace_queries_answered"]
        for e, v in l.items(): self.assertGreaterEqual(v["advanced"], v["basic"], e)
        self.assertGreater(l["0.01"]["advanced"], l["0.01"]["basic"]); self.assertLess(l["0.25"]["zcdp"], l["0.25"]["basic"]); self.assertGreater(list(a["gaussian_queries_answered"].values())[0]["zcdp"], list(a["gaussian_queries_answered"].values())[0]["basic"])
    def test_composition_experiment_bounded_for_horizon(self):
        r = EX.composition(trials=6, system="horizon-basic"); self.assertEqual(r["runs_over_budget"], 0); self.assertLessEqual(r["max_cost"], 2.0); w = EX.composition(trials=6, system="per-agent-limit"); self.assertGreater(w["max_cost"], 2.0)
    def test_composition_is_repeatable(self): self.assertEqual(EX.composition(seed=3, trials=4), EX.composition(seed=3, trials=4))


class Recorded(unittest.TestCase):
    def setUp(self): self.r = json.load(open(os.path.join(D, "result.json")))
    def test_runner_check(self): self.assertEqual(subprocess.run([sys.executable, "scripts/p45_run.py", "--check"], cwd=ROOT, capture_output=True, text=True).returncode, 0)
    def test_report_current(self): self.assertEqual(subprocess.run([sys.executable, "scripts/p45_report.py", "--check"], cwd=ROOT, capture_output=True, text=True).returncode, 0)
    def test_systems_complete(self): self.assertEqual(self.r["systems"], list(SC.SYSTEMS)); self.assertEqual(self.r["runs"], len(SC.SCENARIOS) * len(SC.SYSTEMS) * SC.REPS)
    def test_headline_claims(self):
        s = self.r["summary"]; self.assertEqual(s["horizon-basic"]["attacks_over_budget"]["k"], 0); self.assertEqual(s["horizon-basic"]["benign_completed"]["rate"], 1.0)
        for b in ("per-agent-limit", "per-principal-accountant", "dlp", "token-limit", "non-transactional"): self.assertGreater(s[b]["attacks_over_budget"]["k"], 0, b)
        self.assertEqual(self.r["differential"]["ledger_allow_ref_deny"], 0); self.assertTrue(self.r["differential"]["agreement"])
    def test_limits_recorded(self): self.assertTrue(any("raw-query differencing" in x for x in self.r["limits"])); self.assertTrue(any("not claimed to be exactly DP" in x for x in self.r["limits"]))
    def test_chains_and_audits_clean(self):
        for sy, v in self.r["summary"].items():
            if sy == "horizon-no-transaction": self.assertFalse(v["chain_ok_all"]); continue          # without serialisation the hash chain itself is corrupted by interleaved appends: recorded, not hidden
            self.assertTrue(v["chain_ok_all"], sy); self.assertEqual(v["audit_mismatches"], 0, sy)


if __name__ == "__main__": unittest.main()
