import ast, json, os, random, re, unittest
from horizon.hpolicy.authority import HorizonPolicy, EvidenceError
from horizon.vision import core as C, guard as G, world as W, scenarios as SC, experiment as X, browser as BR
from horizon.vision.world import APP, EVIL, DOCS, ADS, CANARY, El, Frame, Page, Browser, Site
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SYS = {n: (k, c) for n, k, c in X.systems()}; SCN = {s["id"]: s for s in SC.SCENARIOS}
def run(sid, name): k, c = SYS[name]; return X.run_one(SCN[sid], name, k, c)
def src(m):
    t = ast.parse(open(os.path.join(ROOT, "horizon/vision", m + ".py")).read())
    if t.body and isinstance(t.body[0], ast.Expr) and isinstance(getattr(t.body[0], "value", None), ast.Constant): t.body = t.body[1:]
    return ast.unparse(t)


class Rig:
    def __init__(self, **cfg):
        self.t = [1_000_000.0]; self.clk = lambda: self.t[0]; self.A = HorizonPolicy("pol-1", clock=self.clk); self.ap = self.A.register_issuer("approver", {"APPROVAL"}); self.ci = self.A.register_issuer("ci", {"APPROVAL"}); self.ts = self.A.register_issuer("tester", {"TEST_STATUS"})
        self.g = G.Guard(self.A.verifier(), self.clk, G.GCfg(**cfg)); self.task = SC.task()
    def b(self, **kw):
        b = {"instrumented": True, "tab": "t1", "frame": "top", "frame_origin": APP, "top_origin": APP, "element": {"id": "e", "digest": "d"}, "effect": {"kind": "SUBMIT", "dest": APP, "data": "plain", "resource": "/p"}, "reported": {"kind": "SUBMIT", "dest": APP, "data": "plain", "resource": "/p"}, "input_digest": "i", "script_handled": False}
        b.update(kw); return b
    act = {"op": "click", "intent": "e", "observed": "d", "tab": "t1"}
    def decide(self, b=None, task=None, token=None, act=None): return self.g.decide(act or self.act, b, task or self.task, token)
    def tok(self, b, issuer=None, kind="APPROVAL", eff=None, op="click", ttl=600):
        env = C.envelope(op, b["element"]["digest"], eff or b["effect"], b["input_digest"], b["top_origin"], b["tab"]); return (issuer or self.ap).issue(kind, principal="agent", artifact="ui", args_digest=C.envelope_digest(env), ttl=ttl, now=int(self.t[0]))


class Core(unittest.TestCase):
    def test_digest_is_canonical(self): self.assertEqual(C.digest({"a": 1, "b": 2}), C.digest({"b": 2, "a": 1})); self.assertNotEqual(C.digest([1]), C.digest([2]))
    def test_element_digest_binds_effect_and_frame(self):
        a = C.element_digest("button", "submit", "", {"kind": "SUBMIT", "dest": APP}, APP)
        self.assertNotEqual(a, C.element_digest("button", "submit", "", {"kind": "SUBMIT", "dest": EVIL}, APP)); self.assertNotEqual(a, C.element_digest("button", "submit", "", {"kind": "SUBMIT", "dest": APP}, ADS)); self.assertNotEqual(a, C.element_digest("a", "submit", "", {"kind": "SUBMIT", "dest": APP}, APP))
    def test_envelope_fields_all_bind(self):
        base = C.envelope("click", "d", {"kind": "UPLOAD"}, "i", APP, "t1"); d = C.envelope_digest(base)
        for k, v in (("op", "key"), ("element", "x"), ("effect", {"kind": "SUBMIT"}), ("input", "j"), ("top", EVIL), ("tab", "t2")): self.assertNotEqual(d, C.envelope_digest({**base, k: v}), k)
    def test_schemas_published(self): self.assertEqual(set(C.EFFECT_SCHEMA), {"kind", "dest", "data", "resource"}); self.assertIn("frame_origin", C.BINDING_SCHEMA); self.assertEqual(C.PROTECTED, ("SUBMIT", "UPLOAD", "NAVIGATE", "DOWNLOAD", "CLIPBOARD"))


class World(unittest.TestCase):
    def pg(self):
        p = Page(); p.add(El("under", (0, 0, 100, 30), 1, "Under", effect={"kind": "NAVIGATE", "dest": APP, "resource": "/a"}), El("over", (0, 0, 100, 30), 5, "", opacity=0.0, effect={"kind": "SUBMIT", "dest": EVIL, "resource": "/b"})); return p
    def test_hit_ignores_opacity_visual_does_not(self): b = Browser(self.pg()); self.assertEqual(b.hit(5, 5).id, "over"); self.assertEqual(b.visual(5, 5).id, "under")
    def test_rectangle_is_half_open(self): p = Page(); p.add(El("a", (0, 0, 100, 30), 1)); b = Browser(p); self.assertIsNotNone(b.hit(99, 29)); self.assertIsNone(b.hit(100, 5)); self.assertIsNone(b.hit(5, 30)); self.assertIsNotNone(b.visual(0, 0)); self.assertIsNone(b.visual(100, 5))
    def test_no_input_means_no_data(self): p = Page(); p.add(El("n", effect={"kind": "NAVIGATE", "dest": APP, "resource": "/x"})); self.assertEqual(Browser(p).binding(p.el("n"))["effect"]["data"], "none")
    def test_a_none_effect_is_not_logged_by_the_site(self): p = Page(); p.add(El("n")); site = Site(); W.perform(Browser(p), site, p.el("n")); self.assertEqual(site.log, [])
    def test_pointer_events_none_is_not_hit(self): p = self.pg(); p.el("over").pointer = False; self.assertEqual(Browser(p).hit(5, 5).id, "under")
    def test_frame_opacity_hides_but_still_hit(self):
        p = self.pg(); p.frames["f"] = Frame("f", ADS, opacity=0.0); p.el("over").frame = "f"; p.el("over").opacity = 1.0; b = Browser(p); self.assertEqual(b.hit(5, 5).id, "over"); self.assertEqual(b.visual(5, 5).id, "under")
    def test_frame_pointer_none(self): p = self.pg(); p.frames["f"] = Frame("f", ADS, pointer=False); p.el("over").frame = "f"; self.assertEqual(Browser(p).hit(5, 5).id, "under")
    def test_miss(self): b = Browser(self.pg()); self.assertIsNone(b.hit(500, 500)); self.assertIsNone(b.visual(500, 500))
    def test_find_label_uses_visible_text_only(self): b = Browser(self.pg()); self.assertEqual(b.find_label("Under"), (50, 15)); p = self.pg(); p.el("over").text = "Hidden"; self.assertIsNone(Browser(p).find_label("Hidden"))
    def test_binding_none_when_uninstrumented(self):
        p = self.pg(); p.el("over").uninstr = True; self.assertIsNone(Browser(p).binding(p.el("over"))); p2 = self.pg(); p2.page_instrumented = False; self.assertIsNone(Browser(p2).binding(p2.el("under")))
    def test_binding_reports_browser_resolved_effect_and_frame(self):
        p = self.pg(); p.frames["f"] = Frame("f", ADS); p.el("over").frame = "f"; b = Browser(p).binding(p.el("over")); self.assertEqual((b["frame_origin"], b["top_origin"], b["effect"]["dest"]), (ADS, APP, EVIL))
    def test_reported_effect_can_differ_from_real(self):
        p = Page(); p.add(El("f", effect={"kind": "SUBMIT", "dest": EVIL, "resource": "/x"}, reported={"kind": "SUBMIT", "dest": APP, "resource": "/x"})); b = Browser(p).binding(p.el("f")); self.assertEqual((b["effect"]["dest"], b["reported"]["dest"]), (EVIL, APP))
    def test_data_class_follows_current_input(self):
        p = Page(); p.add(El("f", effect={"kind": "SUBMIT", "dest": APP, "resource": "/x"}, input={"a": "1"})); br = Browser(p); self.assertEqual(br.binding(p.el("f"))["effect"]["data"], "plain"); p.el("f").input["b"] = CANARY; self.assertEqual(br.binding(p.el("f"))["effect"]["data"], "canary")
    def test_script_handled_effect_not_derivable(self):
        p = Page(); p.add(El("s", effect={"kind": "SUBMIT", "dest": EVIL, "resource": "/x"}, script=True)); b = Browser(p).binding(p.el("s")); self.assertEqual(b["effect"]["kind"], "NONE"); self.assertTrue(b["script_handled"])
    def test_digest_changes_when_effect_changes(self): p = self.pg(); br = Browser(p); d = br.digest_of(p.el("under")); p.el("under").effect = {"kind": "NAVIGATE", "dest": APP, "resource": "/other"}; self.assertNotEqual(d, br.digest_of(p.el("under")))
    def test_digest_ignores_unrelated_change(self): p = self.pg(); br = Browser(p); d = br.digest_of(p.el("under")); p.el("over").effect = None; p.mutate(lambda q: None); self.assertEqual(d, br.digest_of(p.el("under")))
    def test_mutate_bumps_version(self): p = self.pg(); v = p.version; p.mutate(lambda q: None); self.assertEqual(p.version, v + 1)


class Oracle(unittest.TestCase):
    L = [{"kind": "SUBMIT", "dest": APP, "data": "plain", "resource": "/p"}]
    def test_authorized_effect_is_not_a_violation(self): self.assertEqual(W.violations(self.L, [{"kind": "SUBMIT", "dest": APP, "resource": "/p", "data": "plain"}]), [])
    def test_wrong_dest_resource_data_kind(self):
        for a in ({"kind": "SUBMIT", "dest": EVIL, "resource": "/p", "data": "plain"}, {"kind": "SUBMIT", "dest": APP, "resource": "/q", "data": "plain"}, {"kind": "SUBMIT", "dest": APP, "resource": "/p", "data": "canary"}, {"kind": "UPLOAD", "dest": APP, "resource": "/p", "data": "plain"}): self.assertEqual(len(W.violations(self.L, [a])), 1)
    def test_wildcard_resource(self): self.assertEqual(W.violations(self.L, [{"kind": "SUBMIT", "dest": APP, "resource": "*", "data": "plain"}]), [])
    def test_nothing_authorized(self): self.assertEqual(len(W.violations(self.L, [])), 1)
    def test_completion_requires_effect_at_receiver(self): self.assertFalse(W.completed([], self.L)); self.assertTrue(W.completed(self.L, self.L)); self.assertFalse(W.completed(self.L, [{"kind": "SUBMIT", "dest": EVIL}]))
    def test_oracle_reads_only_log_and_task(self): s = src("world"); i = s.index("def violations"); body = s[i:]; self.assertNotIn("Guard", body); self.assertNotIn("decide", body)


class GuardRules(unittest.TestCase):
    def setUp(self): self.r = Rig()
    def test_no_binding_unknown(self): self.assertEqual(self.r.decide(None)[0], "UNKNOWN"); self.assertEqual(self.r.decide(self.r.b(instrumented=False))[0], "UNKNOWN")
    def test_fail_open_ablation(self): self.assertEqual(Rig(fail_closed=False).decide(None)[0], "ALLOW")
    def test_permitted_submit(self): self.assertEqual(self.r.decide(self.r.b()), ("ALLOW", "PERMITTED"))
    def test_element_mismatch(self): self.assertEqual(self.r.decide(self.r.b(element={"id": "other", "digest": "d"})), ("DENY", "ELEMENT_MISMATCH"))
    def test_no_intent_skips_element_check(self): self.assertEqual(self.r.decide(self.r.b(element={"id": "x", "digest": "d"}), act={"op": "key", "observed": "d", "tab": "t1"})[0], "ALLOW")
    def test_cross_frame_untrusted_protected(self): self.assertEqual(self.r.decide(self.r.b(frame_origin=ADS)), ("DENY", "CROSS_FRAME"))
    def test_cross_frame_trusted_frame(self): t = SC.task(frames=[APP, ADS], allowed={"SUBMIT": [APP, ADS]}); self.assertEqual(self.r.decide(self.r.b(frame_origin=ADS, effect={"kind": "SUBMIT", "dest": ADS, "data": "plain", "resource": "/p"}), task=t)[0], "ALLOW")
    def test_cross_frame_without_effect_is_harmless(self): self.assertEqual(self.r.decide(self.r.b(frame_origin=ADS, effect={"kind": "NONE", "dest": None, "data": "none", "resource": None}))[0], "ALLOW")
    def test_stale_element(self): self.assertEqual(self.r.decide(self.r.b(element={"id": "e", "digest": "changed"})), ("DENY", "STALE_ELEMENT"))
    def test_script_handled_is_unknown(self): self.assertEqual(self.r.decide(self.r.b(script_handled=True)), ("UNKNOWN", "SCRIPT_HANDLED_EFFECT"))
    def test_dest_not_allowed(self): self.assertEqual(self.r.decide(self.r.b(effect={"kind": "SUBMIT", "dest": EVIL, "data": "plain", "resource": "/p"})), ("DENY", "DEST_NOT_ALLOWED"))
    def test_dest_per_kind(self): self.assertEqual(self.r.decide(self.r.b(effect={"kind": "NAVIGATE", "dest": DOCS, "data": "none", "resource": "/g"}))[0], "ALLOW"); self.assertEqual(self.r.decide(self.r.b(effect={"kind": "SUBMIT", "dest": DOCS, "data": "plain", "resource": "/g"}))[0], "DENY")
    def test_kind_missing_from_policy_is_denied(self): t = SC.task(allowed={"SUBMIT": [APP]}); self.assertEqual(self.r.decide(self.r.b(effect={"kind": "CLIPBOARD", "dest": APP, "data": "plain", "resource": "c"}), task=t), ("DENY", "DEST_NOT_ALLOWED"))
    def test_canary_to_unapproved_destination(self): self.assertEqual(self.r.decide(self.r.b(effect={"kind": "SUBMIT", "dest": APP, "data": "canary", "resource": "/p"})), ("DENY", "SENSITIVE_DATA_DEST"))
    def test_canary_to_data_dest(self): t = SC.task(data_dest=[APP]); self.assertEqual(self.r.decide(self.r.b(effect={"kind": "SUBMIT", "dest": APP, "data": "canary", "resource": "/p"}), task=t)[0], "ALLOW")
    def test_input_changed(self): t = SC.task(reviewed_input="i0"); self.assertEqual(self.r.decide(self.r.b(), task=t), ("DENY", "INPUT_CHANGED")); self.assertEqual(self.r.decide(self.r.b(input_digest="i0"), task=t)[0], "ALLOW")
    def test_input_check_only_for_submit(self): t = SC.task(reviewed_input="i0"); self.assertEqual(self.r.decide(self.r.b(effect={"kind": "NAVIGATE", "dest": APP, "data": "none", "resource": "/x"}), task=t)[0], "ALLOW")
    def test_derived_effect_not_reported(self):
        b = self.r.b(effect={"kind": "SUBMIT", "dest": EVIL, "data": "plain", "resource": "/p"}); self.assertEqual(self.r.decide(b)[0], "DENY"); self.assertEqual(Rig(derive_effect=False).decide(b)[0], "ALLOW")
    def test_upload_requires_approval(self):
        b = self.r.b(effect={"kind": "UPLOAD", "dest": APP, "data": "plain", "resource": "/u"}); self.assertEqual(self.r.decide(b), ("CONFIRM", "APPROVAL_REQUIRED")); self.assertEqual(self.r.decide(b, token=self.r.tok(b))[0], "ALLOW")
    def test_approval_single_use(self): b = self.r.b(effect={"kind": "UPLOAD", "dest": APP, "data": "plain", "resource": "/u"}); t = self.r.tok(b); self.r.decide(b, token=t); self.assertEqual(self.r.decide(b, token=t), ("DENY", "APPROVAL_REPLAY"))
    def test_approval_wrong_kind(self):
        b = self.r.b(effect={"kind": "UPLOAD", "dest": APP, "data": "plain", "resource": "/u"}); self.assertEqual(self.r.decide(b, token=self.r.tok(b, issuer=self.r.ts, kind="TEST_STATUS"))[1], "APPROVAL_WRONG_KIND")
    def test_approval_wrong_role(self): b = self.r.b(effect={"kind": "UPLOAD", "dest": APP, "data": "plain", "resource": "/u"}); self.assertEqual(self.r.decide(b, token=self.r.tok(b, issuer=self.r.ci))[1], "APPROVAL_WRONG_ROLE")
    def test_approval_bound_to_every_envelope_field(self):
        b = self.r.b(effect={"kind": "UPLOAD", "dest": APP, "data": "plain", "resource": "/u"})
        for k, v in (("element", {"id": "e", "digest": "d2"}), ("input_digest", "i2"), ("top_origin", EVIL), ("tab", "t9"), ("effect", {"kind": "UPLOAD", "dest": APP, "data": "plain", "resource": "/other"})):
            t = self.r.tok(b); b2 = {**b, k: v}; a = {**self.r.act, "observed": b2["element"]["digest"], "tab": b2["tab"]}
            self.assertEqual(self.r.decide(b2, token=t, act=a)[1], "APPROVAL_MISMATCH", k)
        t = self.r.tok(b); self.assertEqual(self.r.decide(b, token=t, act={**self.r.act, "op": "key"})[1], "APPROVAL_MISMATCH")
    def test_approval_for_other_element_not_accepted_even_with_valid_signature(self):
        b1 = self.r.b(effect={"kind": "UPLOAD", "dest": APP, "data": "plain", "resource": "/u"}, element={"id": "e", "digest": "d"}); b2 = {**b1, "element": {"id": "e", "digest": "d2"}}; t = self.r.tok(b1)
        self.assertEqual(self.r.decide(b2, token=t, act={**self.r.act, "observed": "d2"})[1], "APPROVAL_MISMATCH")
    def test_approval_binding_ablation_accepts_any_envelope(self):
        r = Rig(bind_approval=False); b = r.b(effect={"kind": "UPLOAD", "dest": APP, "data": "plain", "resource": "/u"}); other = {**b, "input_digest": "zzz"}; self.assertEqual(r.decide(b, token=r.tok(other))[0], "ALLOW")
    def test_expired_approval(self): b = self.r.b(effect={"kind": "UPLOAD", "dest": APP, "data": "plain", "resource": "/u"}); t = self.r.tok(b, ttl=10); self.r.t[0] += 60; self.assertEqual(self.r.decide(b, token=t)[0], "DENY")
    def test_forged_token(self): b = self.r.b(effect={"kind": "UPLOAD", "dest": APP, "data": "plain", "resource": "/u"}); self.assertEqual(self.r.decide(b, token="garbage")[0], "DENY")
    def test_download_requires_approval(self): self.assertEqual(self.r.decide(self.r.b(effect={"kind": "DOWNLOAD", "dest": APP, "data": "none", "resource": "/f"}))[0], "CONFIRM")
    def test_every_flag_off_allows_its_attack(self):
        e = lambda **k: {"kind": "SUBMIT", "dest": EVIL, "data": "plain", "resource": "/p", **k}
        self.assertEqual(Rig(bind_element=False).decide(self.r.b(element={"id": "z", "digest": "d"}))[0], "ALLOW"); self.assertEqual(Rig(bind_frame=False).decide(self.r.b(frame_origin=ADS))[0], "ALLOW"); self.assertEqual(Rig(bind_version=False).decide(self.r.b(element={"id": "e", "digest": "q"}))[0], "ALLOW")
        self.assertEqual(Rig(dest_policy=False).decide(self.r.b(effect=e()))[0], "ALLOW"); self.assertEqual(Rig(data_policy=False).decide(self.r.b(effect=e(dest=APP, data="canary")))[0], "ALLOW"); self.assertEqual(Rig(script_unknown=False).decide(self.r.b(script_handled=True))[0], "ALLOW")
        self.assertEqual(Rig(bind_input=False).decide(self.r.b(input_digest="x"), task=SC.task(reviewed_input="i0"))[0], "ALLOW"); self.assertEqual(Rig(approval=False).decide(self.r.b(effect={"kind": "UPLOAD", "dest": APP, "data": "plain", "resource": "/u"}))[0], "ALLOW")


class Baselines(unittest.TestCase):
    def d(self, kind, b, op="click"): return G.Baseline(kind).decide({"op": op}, b, SC.task())[0]
    def test_none(self): self.assertEqual(self.d("none", None), "ALLOW")
    def test_screenshot_filter_reads_visible_text_only(self): self.assertEqual(self.d("screenshot-filter", {"visible": "Upload report"}), "DENY"); self.assertEqual(self.d("screenshot-filter", {"visible": "Learn more", "dom": "Upload"}), "ALLOW"); self.assertEqual(self.d("screenshot-filter", None), "ALLOW")
    def test_dom_text_reads_dom_and_reported(self): self.assertEqual(self.d("dom-text", {"dom": "Send now", "reported": {}}), "DENY"); self.assertEqual(self.d("dom-text", {"dom": "ok", "reported": {"kind": "UPLOAD"}}), "DENY"); self.assertEqual(self.d("dom-text", {"dom": "ok", "visible": "Upload", "reported": {"kind": "NONE"}}), "ALLOW")
    def test_safe_browsing_blocks_listed_frame_origin(self): self.assertEqual(self.d("safe-browsing", {"reported": {"dest": APP}, "frame_origin": "https://known-bad.test"}), "DENY")
    def test_safe_browsing_only_blocklist(self): self.assertEqual(self.d("safe-browsing", {"reported": {"dest": "https://known-bad.test"}}), "DENY"); self.assertEqual(self.d("safe-browsing", {"reported": {"dest": EVIL}, "frame_origin": EVIL}), "ALLOW")
    def test_tool_allowlist_is_tool_level(self): self.assertEqual(self.d("tool-allowlist", None, "tool_upload"), "DENY"); self.assertEqual(self.d("tool-allowlist", None, "click"), "ALLOW")
    def test_restrictive_rule(self):
        b = {"instrumented": True, "frame_origin": APP, "top_origin": APP}
        self.assertEqual(self.d("restrictive-rule", {**b, "effect": {"kind": "UPLOAD", "dest": APP}}), "DENY"); self.assertEqual(self.d("restrictive-rule", {**b, "effect": {"kind": "SUBMIT", "dest": EVIL}}), "DENY"); self.assertEqual(self.d("restrictive-rule", {**b, "effect": {"kind": "SUBMIT", "dest": APP}}), "ALLOW"); self.assertEqual(self.d("restrictive-rule", None), "UNKNOWN")
    def test_baselines_other_than_restrictive_ignore_trusted_fields(self):
        v = {"visible": "ok", "dom": "ok", "reported": {"kind": "NONE"}, "frame_origin": APP}; t = {**v, "effect": {"kind": "UPLOAD", "dest": EVIL}, "element": {"id": "x"}, "instrumented": True, "top_origin": APP}
        for k in ("none", "screenshot-filter", "dom-text", "safe-browsing", "tool-allowlist"): self.assertEqual(self.d(k, v), self.d(k, t), k)
    def test_unknown_baseline(self):
        with self.assertRaises(ValueError): G.Baseline("x").decide({"op": "click"}, None, SC.task())


class Matrix(unittest.TestCase):
    def test_full_guard_no_prohibited_effect_anywhere(self):
        for s in SC.SCENARIOS: self.assertEqual(run(s["id"], "vision-guard")["violations"], [], s["id"])
    def test_full_guard_reasons(self):
        want = {"A01": "ELEMENT_MISMATCH", "A02": "ELEMENT_MISMATCH", "A03": "ELEMENT_MISMATCH", "A04": "STALE_ELEMENT", "A05": "DEST_NOT_ALLOWED", "A06": "DEST_NOT_ALLOWED", "A07": "DEST_NOT_ALLOWED", "A08": "SENSITIVE_DATA_DEST", "A09": "REVIEW_REFUSED", "A10": "INPUT_CHANGED", "A11": "ELEMENT_MISMATCH", "U05": "SCRIPT_HANDLED_EFFECT"}
        for sid, why in want.items(): self.assertEqual(run(sid, "vision-guard")["decisions"][0][1], why, sid)
    def test_unsupported_paths_are_unknown_not_allowed(self):
        for sid in ("U01", "U02", "U03", "U04", "U05", "M01"): r = run(sid, "vision-guard"); self.assertEqual(r["unknown"], 1, sid); self.assertEqual(r["performed"], 0, sid)
    def test_unsupported_paths_would_violate_unguarded(self):
        for sid in ("U01", "U02", "U03", "U04", "U05", "M01"): self.assertTrue(run(sid, "none")["violations"], sid)
    def test_benign_completed_except_unbindable(self):
        for s in SC.SCENARIOS:
            if s["kind"] == "benign": self.assertEqual(bool(run(s["id"], "vision-guard")["completed"]), not s["unsupported_ok"], s["id"])
    def test_no_unjustified_confirmation_on_benign(self):
        for s in SC.SCENARIOS:
            if s["kind"] == "benign": self.assertEqual(run(s["id"], "vision-guard")["confirms"], 1 if s["justified_confirm"] else 0, s["id"])
    def test_justified_confirmations_resolved_with_an_approval(self): self.assertEqual(run("B03", "vision-guard")["decisions"], [["ALLOW", "PERMITTED"]]); self.assertEqual(run("B05", "vision-guard")["decisions"], [["ALLOW", "PERMITTED"]])
    def test_irrelevant_page_change_does_not_block(self): self.assertEqual(run("B08", "vision-guard")["decisions"], [["ALLOW", "PERMITTED"]])
    def test_accessibility_paths_work(self):
        for sid in ("B06", "B10"): self.assertTrue(run(sid, "vision-guard")["completed"], sid)
        self.assertFalse(run("B10", "screenshot-filter")["completed"])
    def test_telemetry_offline_fails_closed_on_both(self): self.assertEqual(run("M01", "vision-guard")["violations"], []); self.assertFalse(run("M02", "vision-guard")["completed"]); self.assertTrue(run("M01", "vision-guard-no-fail-closed")["violations"])
    def test_baselines_miss_attacks(self):
        self.assertTrue(run("A01", "screenshot-filter")["violations"]); self.assertTrue(run("A02", "screenshot-filter")["violations"]); self.assertTrue(run("A05", "screenshot-filter")["violations"]); self.assertTrue(run("A01", "safe-browsing")["violations"]); self.assertTrue(run("A01", "tool-allowlist")["violations"])
    def test_screenshot_filter_false_blocks_benign(self):
        for sid in ("B03", "B05", "B10"): self.assertFalse(run(sid, "screenshot-filter")["completed"], sid)
    def test_restrictive_rule_disrupts_benign(self):
        for sid in ("B02", "B03", "B04", "B05"): self.assertFalse(run(sid, "restrictive-rule")["completed"], sid)
    def test_ablation_targets(self):
        T = {"element-frame-version": "A02", "version": "A04", "derive-effect": "A05", "dest-policy": "A05", "data-policy": "A08", "input": "A10", "approval": "A09", "script-unknown": "U05", "fail-closed": "U01"}
        for n, sid in T.items(): self.assertTrue(run(sid, "vision-guard-no-" + n)["violations"], n)
    def test_binding_layers_are_redundant_for_overlays(self):
        for n in ("element", "frame", "element-frame"):
            for sid in ("A01", "A02", "A03", "A11"): self.assertEqual(run(sid, "vision-guard-no-" + n)["violations"], [], (n, sid))
    def test_derived_effect_vs_page_reported_in_clobbering(self): self.assertEqual(run("A05", "vision-guard")["violations"], []); self.assertEqual(len(run("A05", "vision-guard-no-derive-effect")["violations"]), 1)
    def test_wrong_review_does_not_unlock(self): self.assertEqual(run("A09", "vision-guard")["performed"], 0)
    def test_system_count(self): self.assertEqual(len(SYS), 20)
    def test_deterministic(self): self.assertEqual(json.dumps(X.run(), sort_keys=True, default=str), json.dumps(X.run(), sort_keys=True, default=str))


class Property(unittest.TestCase):
    def rand_scenario(self, rng, i):
        n = rng.randint(2, 6); els = []
        for k in range(n):
            vis = rng.random() < 0.7; eff = rng.choice([None, {"kind": "NAVIGATE", "dest": APP, "resource": "/n%d" % k}, {"kind": "SUBMIT", "dest": APP, "resource": "/s%d" % k}, {"kind": "SUBMIT", "dest": EVIL, "resource": "/e%d" % k}, {"kind": "UPLOAD", "dest": APP, "resource": "/u%d" % k}, {"kind": "DOWNLOAD", "dest": EVIL, "resource": "/d%d" % k}])
            els.append(El("e%d" % k, (rng.randint(0, 3) * 30, rng.randint(0, 2) * 30, 60, 30), rng.randint(0, 3), ("L%d" % k) if vis else "", opacity=1.0 if vis else 0.0, pointer=rng.random() < 0.85, effect=eff, input={"f": CANARY if rng.random() < .3 else "x"} if eff else {}))
        vis = [e for e in els if e.text]
        if not vis: return None
        tgt = rng.choice(vis); p = Page(); p.add(*els); b = Browser(p); xy = b.find_label(tgt.text); seen = b.visual(*xy)
        auth = [] if seen.effect is None else [{**W._real(seen, p), "dest": seen.effect["dest"]}]
        return {"id": "P%d" % i, "kind": "attack", "desc": "", "build": (lambda p=p: p), "steps": [{"label": tgt.text}], "authorized": auth, "expected": [], "justified_confirm": False, "ax": False, "unsupported_ok": False, "task": {"data_dest": [APP]}}, seen, xy
    def test_random_overlays_guard_never_performs_an_unintended_effect(self):
        rng = random.Random(51); n_none = n_guard = ran = 0
        for i in range(600):
            r = self.rand_scenario(rng, i)
            if r is None: continue
            sc, seen, xy = r; ran += 1; a = X.run_one(sc, "none", "baseline", None); g = X.run_one(sc, "vision-guard", "guard", G.GCfg())
            n_none += bool(a["violations"]); n_guard += bool(g["violations"])
            if g["violations"]: self.fail(("guard performed an effect the visible target did not carry", i, g["violations"]))
        self.assertGreater(ran, 400); self.assertGreater(n_none, 20); self.assertEqual(n_guard, 0)
    def test_visible_target_equals_hit_target_allows_the_intended_effect(self):
        rng = random.Random(52); done = 0
        for i in range(400):
            r = self.rand_scenario(rng, i)
            if r is None: continue
            sc, seen, xy = r; br = Browser(sc["build"]()); hit = br.hit(*xy)
            if hit is None or hit.id != seen.id or seen.effect is None or seen.effect["kind"] == "NONE" or seen.effect["dest"] != APP or seen.input.get("f") == CANARY: continue
            g = X.run_one(sc, "vision-guard", "guard", G.GCfg()); done += 1; self.assertEqual(g["performed"], 1, (i, g["decisions"])); self.assertEqual(g["violations"], [])
        self.assertGreater(done, 30)


class Gates(unittest.TestCase):
    def test_guard_modules_hold_no_issuer(self):
        for m in ("core", "guard", "world", "scenarios", "browser"): self.assertNotIn("register_issuer", src(m)); self.assertNotIn(".issue(", src(m))
    def test_only_experiment_harnesses_register_approver(self): self.assertIn("register_issuer", src("experiment")); self.assertIn("register_issuer", src("browser_run"))
    def test_no_third_party_hosts(self):
        for m in ("core", "guard", "world", "scenarios", "experiment", "browser", "browser_run"):
            for h in re.findall(r"https?://([A-Za-z0-9._-]+)", open(os.path.join(ROOT, "horizon/vision", m + ".py")).read()): self.assertRegex(h, r"^(127\.|localhost|.*\.test$)", (m, h))
    def test_browser_is_loopback_only(self): s = open(os.path.join(ROOT, "horizon/vision/browser.py")).read(); self.assertIn("--no-proxy-server", s); self.assertIn("LOOP", s); s2 = open(os.path.join(ROOT, "horizon/vision/browser_run.py")).read(); self.assertIn("r.abort()", s2)
    def test_guard_reads_page_reported_effect_only_in_the_ablation_branch(self): g = src("guard").split("class Baseline")[0]; self.assertEqual(g.count("b['reported']"), 1); self.assertIn("if c.derive_effect else", g)
    def test_guard_never_reads_screenshot_fields(self): g = src("guard").split("class Baseline")[0]; self.assertNotIn("'visible'", g); self.assertNotIn("'dom'", g)
    def test_canary_is_synthetic(self): self.assertEqual(CANARY, "TEST_CANARY_NOT_SECRET")
    def test_scenario_ids_unique(self): ids = [s["id"] for s in SC.SCENARIOS]; self.assertEqual(len(ids), len(set(ids))); self.assertEqual(len(ids), 29)


@unittest.skipUnless(os.environ.get("P51_BROWSER", "1") == "1" and BR.available(), "UNSUPPORTED: playwright/Chromium not available on this host (real-browser checks not run)")
class BrowserLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from horizon.vision import browser_run as BRR
        cls.BRR = BRR; cls.L = BRR.Lab(); import tempfile
        from playwright.sync_api import sync_playwright
        cls.pw = sync_playwright().start(); cls.b = cls.pw.chromium.launch(args=BR.chromium_args()); cls.tmp = tempfile.mkdtemp(); cls.S = {s["id"]: s for s in BRR.scenarios(cls.L)}
    @classmethod
    def tearDownClass(cls): cls.b.close(); cls.pw.stop(); cls.L.close()
    def run_(self, sid, g): return self.BRR.run_one(self.b, self.L, self.S[sid], g, self.tmp)
    def test_overlay_upload_reaches_the_receiver_unguarded_and_not_guarded(self):
        a = self.run_("R01", False); self.assertEqual([e["kind"] for e in a["violations"]], ["UPLOAD"]); self.assertEqual(a["violations"][0]["data"], "canary"); g = self.run_("R01", True); self.assertEqual(g["violations"], []); self.assertEqual(g["received"], [])
    def test_clobbered_form_action_derived_from_attribute(self): g = self.run_("R05", True); self.assertEqual(g["decisions"][0], ["DENY", "DEST_NOT_ALLOWED"]); self.assertTrue(self.run_("R05", False)["violations"])
    def test_script_handled_button_is_unknown(self): g = self.run_("R09", True); self.assertEqual(g["decisions"][0][0], "UNKNOWN"); self.assertEqual(g["received"], [])
    def test_matched_benign_form_and_upload(self):
        self.assertTrue(self.run_("R06", True)["completed"]); u = self.run_("R07", True); self.assertTrue(u["completed"]); self.assertEqual(u["confirms"], 1)
    def test_no_stray_requests(self):
        for sid in self.S: self.assertEqual(self.run_(sid, True)["stray_requests"], [], sid)


class Recorded(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.R = json.load(open(os.path.join(ROOT, "results/v2/p51-vision/result.json"))); cls.B = json.load(open(os.path.join(ROOT, "results/v2/p51-vision-browser/browser.json")))
    def test_full_guard_zero_prohibited_effects(self): s = self.R["summary"]["vision-guard"]; self.assertEqual((s["attack_violated"]["k"], s["unknown_paths_violated"]["k"]), (0, 0)); self.assertEqual(s["unknown_paths_flagged_UNKNOWN"], 6)
    def test_baselines_miss(self):
        for n in ("none", "safe-browsing", "tool-allowlist"): self.assertEqual(self.R["summary"][n]["attack_violated"]["k"], 11)
        self.assertGreaterEqual(self.R["summary"]["screenshot-filter"]["attack_violated"]["k"], 5)
    def test_redundant_disclosed(self): self.assertIn("vision-guard-no-element", self.R["redundant"]); self.assertNotIn("vision-guard-no-version", self.R["redundant"])
    def test_stored_results_match_live(self): self.assertEqual(json.loads(json.dumps(X.run(), default=str, sort_keys=True)), json.loads(json.dumps(self.R, default=str, sort_keys=True)))
    def test_browser_attacks_reach_receiver_unguarded_and_not_guarded(self):
        for r in self.B["rows"]:
            if r["kind"] in ("attack", "unknown"): self.assertTrue(r["violations"] if not r["guarded"] else not r["violations"], (r["scenario"], r["guarded"]))
    def test_browser_benign_completed_except_script_handled(self):
        for r in self.B["rows"]:
            if r["kind"] == "benign" and r["guarded"]: self.assertEqual(bool(r["completed"]), r["scenario"] != "R11", r["scenario"])
    def test_browser_no_stray_requests_and_loopback(self): self.assertTrue(all(r["stray_requests"] == [] for r in self.B["rows"])); self.assertEqual(self.B["definitions"]["chromium_args"], ["--no-proxy-server"])
    def test_browser_unknowns_reported_separately(self): self.assertEqual([r["decisions"][0][0] for r in self.B["rows"] if r["scenario"] in ("R09", "R11") and r["guarded"]], ["UNKNOWN", "UNKNOWN"])


if __name__ == "__main__": unittest.main()
