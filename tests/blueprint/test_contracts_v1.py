import ast, dataclasses, itertools, os, re, unittest
from horizon.contracts.v1 import *
from horizon.contracts.v1 import effect as EF, errors as ER, messages as MS, protocols as PR, states as ST
from horizon.contracts.v1.legacy import from_legacy, same_effect
from horizon.effects.canonical import CanonicalEffect

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
H = "sha256:" + "0" * 64
MASTERPLAN_FIELDS = ("schema_version effect_id tenant_id agent_id session_id principal_id delegation_chain_digest tool_server_id tool_id transport effect_class target_kind target_canonical arguments_digest "
                     "artifact_lineage_digests purpose policy_digest policy_epoch assurance_claim_id assurance_epoch approval_id budget_reservation_id deadline idempotency_key nonce trace_id").split()


def eff(**kw):
    d = dict(schema_version="1", effect_id="e1", tenant_id="t1", agent_id="a1", session_id="s1", principal_id="p1", delegation_chain_digest=EMPTY_CHAIN, tool_server_id="srv", tool_id="write_file",
             transport="mcp-stdio", effect_class="write", target_kind="file", target_canonical="/w/a.txt", arguments_digest=H, artifact_lineage_digests=(), purpose="summarise", policy_digest=H, policy_epoch=1,
             assurance_claim_id="c1", assurance_epoch=1, approval_id=None, budget_reservation_id=None, deadline=1000, idempotency_key="k1", nonce="n1", trace_id="tr1")
    d.update(kw); return CanonicalEffectV1(**d)


def code(f, *a, **k):
    try: f(*a, **k)
    except (ContractError, StateError) as e: return getattr(e, "code", "STATE")
    return None


class States(unittest.TestCase):
    def test_transition_table_is_exactly_the_specified_one(self):
        S = EffectState; allowed = {(S.REQUESTED, S.AUTHORIZED), (S.REQUESTED, S.BLOCKED), (S.AUTHORIZED, S.STARTED), (S.AUTHORIZED, S.BLOCKED), (S.STARTED, S.COMMITTED), (S.STARTED, S.BLOCKED),
                                    (S.STARTED, S.UNKNOWN), (S.UNKNOWN, S.RECONCILED_COMMITTED), (S.UNKNOWN, S.RECONCILED_BLOCKED)}
        for a, b in itertools.product(S, S): self.assertEqual(code(transition, a, b) is None, (a, b) in allowed, (a, b))
    def test_strings_are_not_silently_coerced(self):
        self.assertEqual(code(transition, "REQUESTED", EffectState.AUTHORIZED), "STATE"); self.assertEqual(code(transition, EffectState.REQUESTED, "AUTHORIZED"), "STATE")
        self.assertEqual(code(commit_authorising, "ALLOW_CANDIDATE"), "STATE"); self.assertEqual(code(may_retry, "UNKNOWN"), "STATE"); self.assertEqual(code(outcome, "COMMITTED"), "STATE")
    def test_no_decision_authorises_a_commit(self):
        for d in Decision: self.assertIs(commit_authorising(d), False)
    def test_unknown_is_undetermined_and_never_retried(self):
        self.assertEqual(outcome(EffectState.UNKNOWN), "UNDETERMINED"); self.assertFalse(may_retry(EffectState.UNKNOWN)); self.assertFalse(may_retry(EffectState.STARTED))
        self.assertEqual({s: outcome(s) for s in EffectState}, {EffectState.REQUESTED: "UNDETERMINED", EffectState.AUTHORIZED: "UNDETERMINED", EffectState.STARTED: "UNDETERMINED", EffectState.COMMITTED: "HAPPENED",
                         EffectState.BLOCKED: "DID_NOT_HAPPEN", EffectState.UNKNOWN: "UNDETERMINED", EffectState.RECONCILED_COMMITTED: "HAPPENED", EffectState.RECONCILED_BLOCKED: "DID_NOT_HAPPEN"})
        self.assertTrue(may_retry(EffectState.REQUESTED)); self.assertTrue(may_retry(EffectState.AUTHORIZED)); self.assertFalse(any(may_retry(s) for s in ST.TERMINAL))
    def test_vocabularies_match_the_masterplan(self):
        self.assertEqual({d.value for d in Decision}, {"ALLOW_CANDIDATE", "DENY", "REQUIRE_APPROVAL", "UNKNOWN", "UNSUPPORTED"})
        self.assertEqual(len(EffectState), 8); self.assertEqual({a.value for a in Assurance}, {"CANDIDATE", "VALID_FOR_SCOPE", "SUSPENDED", "REVOKED", "EXPIRED", "UNIDENTIFIABLE"})
        self.assertEqual(len(Coverage), 4); self.assertEqual(len(ModuleStatus), 7); self.assertEqual(ST.TERMINAL, {EffectState.COMMITTED, EffectState.BLOCKED, EffectState.RECONCILED_COMMITTED, EffectState.RECONCILED_BLOCKED})


class Errors(unittest.TestCase):
    def test_every_code_in_the_source_is_in_the_table(self):
        seen = set(); pats = (re.compile(r"(?:ProofError|DurableError|EffectError|NetBrokerError|ProcBrokerError)\(\"([A-Z_]+)\""), re.compile(r"\"code\": \"([A-Z_]+)\""))
        for base in ("horizon/authz", "horizon/effects", "horizon/assurance"):
            for dp, _, fs in os.walk(os.path.join(ROOT, base)):
                for f in fs:
                    if f.endswith(".py"):
                        for p in pats: seen |= set(p.findall(open(os.path.join(dp, f)).read()))
        self.assertEqual(sorted(seen - set(ER.ERRORS)), [])
    def test_unlisted_or_non_string_codes_fail_closed(self):
        for c in ("NOPE", None, 5, b"x", ""):
            i = ER.lookup(c); self.assertEqual((i.category, i.retryable, i.effect), ("UNKNOWN", False, "UNDETERMINED"))
    def test_nothing_is_auto_retryable_and_ambiguous_codes_are_undetermined(self):
        self.assertFalse(any(e.retryable for e in ER.ERRORS.values()))
        for c in ("TIMEOUT", "CONNECT_FAILED", "RESPONSE_TOO_LARGE", "UPSTREAM_FAILED"): self.assertEqual(ER.lookup(c).effect, "UNDETERMINED")
        for c in ("POLICY_DENIED", "REPLAY", "EFFECT_MISMATCH"): self.assertEqual(ER.lookup(c).effect, "DID_NOT_HAPPEN")
        for c in ("REDIRECT_REFUSED", "TLS_ERROR", "LEDGER_MOVED_ON", "TIMEOUT"): self.assertEqual(ER.lookup(c).effect, "UNDETERMINED", c)      # PR-04 correction: these can follow a completed or partial effect
        self.assertEqual(ER.lookup("JOURNAL_TAMPERED").category, "INTEGRITY")


class Effect(unittest.TestCase):
    def test_field_set_is_exactly_the_masterplan_list(self): self.assertEqual(list(FIELD_NAMES), MASTERPLAN_FIELDS); self.assertEqual(len(FIELD_NAMES), 26)
    def test_baseline_is_valid_and_digest_is_deterministic(self): self.assertEqual(eff().digest(), eff().digest()); self.assertRegex(eff().digest(), r"sha256:[0-9a-f]{64}")
    def test_changing_any_single_field_changes_the_digest(self):
        base = eff(); alt = {"schema_version": None, "effect_id": "e2", "tenant_id": "t2", "agent_id": "a2", "session_id": "s2", "principal_id": "p2", "delegation_chain_digest": "sha256:" + "1" * 64, "tool_server_id": "srv2",
                             "tool_id": "t2", "transport": "utcp", "effect_class": "modify", "target_kind": "url", "target_canonical": "/w/b.txt", "arguments_digest": "sha256:" + "2" * 64, "artifact_lineage_digests": ("sha256:" + "3" * 64,),
                             "purpose": "other", "policy_digest": "sha256:" + "4" * 64, "policy_epoch": 2, "assurance_claim_id": "c2", "assurance_epoch": 2, "approval_id": "ap1", "budget_reservation_id": "b1", "deadline": 1001,
                             "idempotency_key": "k2", "nonce": "n2", "trace_id": "tr2"}
        for k, v in alt.items():
            if v is None: continue
            self.assertNotEqual(eff(**{k: v}).digest(), base.digest(), k)
        self.assertEqual(set(alt) - {"schema_version"}, set(FIELD_NAMES) - {"schema_version"})
    def test_unknown_security_critical_values_are_rejected_not_defaulted(self):
        self.assertEqual(code(eff(schema_version="2").validate), "VERSION"); self.assertEqual(code(eff(effect_class="teleport").validate), "UNKNOWN_EFFECT")
        self.assertEqual(code(eff(transport="carrier-pigeon").validate), "UNSUPPORTED"); self.assertEqual(code(eff(target_kind="brain").validate), "UNSUPPORTED")
    def test_mutating_classes_need_key_and_claim_but_reads_do_not(self):
        for c in MUTATING:
            for k in ("idempotency_key", "assurance_claim_id"): self.assertIn(code(eff(effect_class=c, artifact_lineage_digests=(), **{k: None}).validate), ("MISSING_FIELD", "MALFORMED"), (c, k))
        self.assertEqual(code(eff(effect_class="write", assurance_claim_id="c1", assurance_epoch=None).validate), "MALFORMED")
        r = eff(effect_class="read", idempotency_key=None, assurance_claim_id=None, assurance_epoch=None, artifact_lineage_digests=None); self.assertIsNone(code(r.validate))
    def test_send_needs_an_explicit_lineage_statement(self):
        self.assertEqual(code(eff(effect_class="send", artifact_lineage_digests=None).validate), "MISSING_FIELD"); self.assertIsNone(code(eff(effect_class="send", artifact_lineage_digests=()).validate))
        self.assertEqual(code(eff(artifact_lineage_digests=["sha256:" + "0" * 64]).validate), "MALFORMED"); self.assertEqual(code(eff(artifact_lineage_digests=("bad",)).validate), "MALFORMED")
    def test_string_hygiene(self):
        for bad in ("", "a\x00b", "a\nb", "a\x7fb", "x" * 2049, 5, None, b"x"):
            self.assertEqual(code(eff(tenant_id=bad).validate), "MALFORMED", repr(bad))
        self.assertEqual(code(eff(idempotency_key="").validate), "MALFORMED")
    def test_digest_and_integer_formats(self):
        for bad in ("sha256:" + "0" * 63, "SHA256:" + "0" * 64, "sha256:" + "G" * 64, "0" * 64, None):
            for k in ("arguments_digest", "policy_digest", "delegation_chain_digest"): self.assertEqual(code(eff(**{k: bad}).validate), "MALFORMED", (k, bad))
        for bad in (-1, True, 1.0, "1", None):
            for k in ("policy_epoch", "deadline"): self.assertEqual(code(eff(**{k: bad}).validate), "MALFORMED", (k, bad))
        self.assertEqual(code(eff(assurance_epoch=True).validate), "MALFORMED")
    def test_no_delegation_is_an_explicit_marker_not_an_absent_field(self):
        self.assertTrue(EMPTY_CHAIN.startswith("sha256:")); self.assertNotEqual(eff().digest(), eff(delegation_chain_digest="sha256:" + "5" * 64).digest()); self.assertEqual(code(eff(delegation_chain_digest=None).validate), "MALFORMED")


def req(**kw):
    e = eff(); i = TrustedIdentity("t1", "p1", "a1", "s1", "authn-1"); d = dict(identity=i, effect=e, provenance=(), requested_by=DelegatedPrincipal("p1"), trace_id="tr1"); d.update(kw); return EffectRequestV1(**d)


class Messages(unittest.TestCase):
    def test_request_binds_effect_to_the_authenticated_identity(self):
        self.assertIsNone(code(req().validate))
        for k, v in (("tenant_id", "tX"), ("principal_id", "pX"), ("agent_id", "aX"), ("session_id", "sX")): self.assertEqual(code(req(effect=eff(**{k: v})).validate), "BINDING_MISMATCH", k)
        self.assertEqual(code(req(trace_id="other").validate), "BINDING_MISMATCH")
    def test_provenance_must_match_declared_lineage(self):
        a = ArtifactRef("sha256:" + "7" * 64, "SECRET"); self.assertEqual(code(req(provenance=(a,)).validate), "BINDING_MISMATCH")
        self.assertIsNone(code(req(effect=eff(artifact_lineage_digests=(a.digest,)), provenance=(a,)).validate)); self.assertEqual(code(req(provenance=("x",)).validate), "MALFORMED")
        self.assertEqual(ArtifactRef("sha256:" + "7" * 64).label, "UNKNOWN")
    def permit(self, e=None, **kw):
        e = e or eff(); d = dict(effect_digest=e.digest(), nonce="n1", issuer_role="authority", policy_epoch=1, assurance_claim_id="c1", assurance_epoch=1, not_after=900, token="tok"); d.update(kw); return PermitV1(**d)
    def test_permit_covers_only_the_exact_effect_in_force(self):
        e = eff(); ok = lambda p, **k: permit_covers(p, e, **{"now": 10, "current_policy_epoch": 1, "current_assurance_epoch": 1, **k})
        self.assertIsNone(ok(self.permit()))
        self.assertEqual(ok(self.permit(effect_digest="sha256:" + "9" * 64)), "EFFECT_MISMATCH"); self.assertEqual(ok(self.permit(), now=901), "EXPIRED"); self.assertEqual(ok(self.permit(), now=1001), "EXPIRED")
        self.assertEqual(ok(self.permit(not_after=5)), "EXPIRED"); self.assertEqual(ok(self.permit(), current_policy_epoch=2), "STALE_POLICY"); self.assertEqual(ok(self.permit(policy_epoch=2)), "STALE_POLICY")
        self.assertEqual(ok(self.permit(), current_assurance_epoch=2), "ASSURANCE_DENIED"); self.assertEqual(ok(self.permit(), current_assurance_epoch=None), "ASSURANCE_DENIED")
        self.assertEqual(ok(self.permit(assurance_claim_id="c2")), "ASSURANCE_DENIED"); self.assertEqual(ok(self.permit(assurance_epoch=2)), "ASSURANCE_DENIED")
        self.assertEqual(ok(self.permit(token="")), "MALFORMED")
    def test_permit_with_a_claim_cannot_cover_an_effect_without_one(self):
        r = eff(effect_class="read", idempotency_key=None, assurance_claim_id=None, assurance_epoch=None, artifact_lineage_digests=None)
        self.assertEqual(permit_covers(self.permit(r), r, now=1, current_policy_epoch=1, current_assurance_epoch=None), "ASSURANCE_DENIED")
        self.assertIsNone(permit_covers(self.permit(r, assurance_claim_id=None, assurance_epoch=None), r, now=1, current_policy_epoch=1, current_assurance_epoch=None))
    def test_invalid_effect_makes_the_permit_check_fail_closed(self): self.assertEqual(permit_covers(self.permit(), eff(effect_class="x"), now=1, current_policy_epoch=1, current_assurance_epoch=1), "UNKNOWN_EFFECT")
    def test_receipts_must_name_a_witness_when_they_claim_an_outcome(self):
        d = eff().digest()
        for s in (EffectState.COMMITTED, EffectState.RECONCILED_COMMITTED, EffectState.RECONCILED_BLOCKED): self.assertEqual(code(EffectReceiptV1("e1", d, s).validate), "MISSING_FIELD", s)
        self.assertIsNone(code(EffectReceiptV1("e1", d, EffectState.COMMITTED, witness="sink-1").validate)); self.assertIsNone(code(EffectReceiptV1("e1", d, EffectState.UNKNOWN).validate))
        self.assertEqual(code(EffectReceiptV1("e1", d, "COMMITTED", witness="w").validate), "MALFORMED")
    def test_decision_requires_enum_and_digests(self):
        self.assertIsNone(code(DecisionV1(Decision.DENY, H, H, 1).validate)); self.assertEqual(code(DecisionV1("DENY", H, H, 1).validate), "MALFORMED"); self.assertEqual(code(DecisionV1(Decision.DENY, "x", H, 1).validate), "MALFORMED")
    def test_identity_fields_are_required(self):
        for k in ("tenant_id", "principal_id", "agent_id", "session_id", "authenticated_by"): self.assertEqual(code(dataclasses.replace(TrustedIdentity("t1", "p1", "a1", "s1", "x"), **{k: ""}).validate), "MALFORMED")


class Legacy(unittest.TestCase):
    def kw(self, **o): d = dict(effect_id="e1", agent_id="a1", tool_id="write_file", transport="mcp-stdio", purpose="p", policy_digest=H, policy_epoch=1, deadline=99, nonce="n1", trace_id="tr", idempotency_key="k", assurance_claim_id="c1", assurance_epoch=1); d.update(o); return d
    def test_round_trip_describes_the_same_effect(self):
        ce = CanonicalEffect("t1", "srv", "s1", "p1", "write", "file", "/w/a.txt", {"sha256": "ab"}); v = from_legacy(ce, **self.kw()); self.assertTrue(same_effect(ce, v))
        self.assertFalse(same_effect(CanonicalEffect("t1", "srv", "s1", "p1", "write", "file", "/w/a.txt", {"sha256": "ac"}), v))      # one byte of args
        for k, val in (("tenant", "t2"), ("server_id", "x"), ("session_id", "s2"), ("principal", "p2"), ("target_raw", "/w/b.txt")): self.assertFalse(same_effect(dataclasses.replace(ce, **{k: val}), v), k)
    def test_unmapped_trust_fields_are_never_defaulted(self):
        ce = CanonicalEffect("t1", "srv", "s1", "p1", "write", "file", "/w/a.txt", {})
        for k in ("agent_id", "tool_id", "transport", "purpose", "policy_digest", "policy_epoch", "deadline", "nonce", "trace_id", "effect_id"):
            kw = self.kw(); del kw[k]; self.assertRaises(TypeError, from_legacy, ce, **kw)
    def test_legacy_validation_still_applies(self):
        self.assertRaises(Exception, from_legacy, CanonicalEffect("t1", "srv", "s1", "p1", "teleport", "file", "/x", {}), **self.kw())


class Static(unittest.TestCase):
    def test_core_contract_modules_import_nothing_from_the_repo(self):
        d = os.path.join(ROOT, "horizon/contracts/v1")
        for f in sorted(os.listdir(d)):
            if not f.endswith(".py") or f == "legacy.py": continue
            for n in ast.walk(ast.parse(open(os.path.join(d, f)).read())):
                if isinstance(n, ast.ImportFrom): self.assertTrue(n.level == 1 or (n.module or "").split(".")[0] not in ("horizon", "research", "bench", "security_hardening"), (f, n.module))
                if isinstance(n, ast.Import):
                    for a in n.names: self.assertNotIn(a.name.split(".")[0], ("horizon", "research", "bench", "security_hardening"), f)
    def test_forbidden_prefixes_name_modules_that_exist(self):
        for p in PR.UNTRUSTED_ROLE_FORBIDDEN_IMPORT_PREFIXES: self.assertTrue(os.path.exists(os.path.join(ROOT, p.replace(".", "/") + ".py")), p)
    def test_protocols_declare_the_five_roles(self): self.assertEqual({n for n in dir(PR) if n[0].isupper() and n not in ("Protocol", "CanonicalEffectV1", "DecisionV1", "EffectReceiptV1", "EffectRequestV1", "PermitV1", "UNTRUSTED_ROLE_FORBIDDEN_IMPORT_PREFIXES")}, {"TrustedEffectKernel", "ProtectedSink", "Analyzer", "BoundaryProposer", "IndependentPlanChecker"})
if __name__ == "__main__": unittest.main()
