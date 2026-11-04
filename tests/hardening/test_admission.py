import copy, hashlib, json, os, tempfile, time, unittest
from horizon.authz.keys import TrustStore, Signer
from security_hardening import admission as A

PLAT = "linux-x86_64"


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.ev = os.path.join(self.d, "ev"); os.makedirs(self.ev)
        open(os.path.join(self.d, "tm.md"), "w").write("threat model v1\n")
        self.ed = b"evidence bytes"; self.evd = hashlib.sha256(self.ed).hexdigest(); open(os.path.join(self.ev, self.evd), "wb").write(self.ed)
        self.rev = Signer.generate("rev1", A.REVIEW_ISSUER); self.trust = TrustStore(); now = time.time()
        self.trust.add("rev1", A.REVIEW_ISSUER, self.rev.public_raw(), not_before=now - 10, not_after=now + 3600)
        self.adm = A.Admission(self.trust, root=self.d, evidence_root=self.ev, platform_id=PLAT)

    def man(self, **kw):
        m = dict(name="file-sink", version="1.0.0", contract_version="1", authored_by="author1", effects={"file.write": "protected"}, dependencies={},
                 supported_platforms=[PLAT], signer={"kid": "rev1", "issuer": A.REVIEW_ISSUER}, threat_model={"path": "tm.md", "sha256": A.file_sha(os.path.join(self.d, "tm.md"))},
                 evidence_digest=self.evd, feature_flags={}, track="adapter"); m.update(kw); return m

    def ok(self, **kw): return self.adm.admit(A.sign(self.man(**kw), self.rev))
    def why(self, r): return " ".join(r["reasons"])


class Admit(Base):
    def test_valid_admitted(self): self.assertEqual(self.ok()["decision"], "ADMIT")
    def test_unsigned_denied(self): self.assertIn("UNSIGNED", self.adm.admit(self.man())["reasons"])
    def test_tampered_after_signing_denied(self):
        m = A.sign(self.man(), self.rev); m["effects"] = {"file.write": "protected", "net.send": "protected"}
        self.assertIn("BAD_SIGNATURE", self.adm.admit(m)["reasons"])
    def test_unknown_signer_denied(self):
        o = Signer.generate("evil", A.REVIEW_ISSUER); self.assertIn("SIGNER_UNKNOWN_KID", self.adm.admit(A.sign(self.man(), o))["reasons"])
    def test_wrong_issuer_denied(self):
        o = Signer.generate("rev1", "agent-runtime"); self.assertIn("SIGNER_NOT_A_REVIEW_ISSUER", self.why(self.adm.admit(A.sign(self.man(), o))))
    def test_self_approval_denied(self): self.assertIn("AUTHOR_CANNOT_APPROVE_OWN_MODULE", self.ok(authored_by="rev1")["reasons"])
    def test_revoked_signer_denied(self):
        self.trust.revoke("rev1"); self.assertIn("SIGNER_KEY_REVOKED", self.ok()["reasons"])
    def test_expired_signer_denied(self):
        self.assertIn("SIGNER_KEY_OUT_OF_WINDOW", self.adm.admit(A.sign(self.man(), self.rev), at=time.time() + 99999)["reasons"])
    def test_duplicate_denied(self):
        self.ok(); self.assertIn("ALREADY_ADMITTED", self.ok()["reasons"])


class Shape(Base):
    def test_unknown_field_denied(self):
        m = self.man(); m["extra"] = 1; self.assertIn("UNKNOWN_FIELD:extra", self.adm.admit(A.sign(m, self.rev))["reasons"])
    def test_missing_field_denied(self):
        m = self.man(); del m["effects"]; self.assertIn("MISSING_FIELD:effects", self.adm.admit(m)["reasons"])
    def test_future_contract_denied(self): self.assertIn("UNSUPPORTED_CONTRACT_VERSION", self.ok(contract_version="2")["reasons"])
    def test_bad_coverage_value_denied(self): self.assertIn("BAD_COVERAGE:file.write", self.ok(effects={"file.write": "safe"})["reasons"])
    def test_empty_effects_denied(self): self.assertIn("BAD_EFFECTS", self.ok(effects={})["reasons"])
    def test_bad_version_denied(self): self.assertIn("BAD_VERSION", self.ok(version="1.0")["reasons"])
    def test_non_object_denied(self): self.assertEqual(self.adm.admit([1])["decision"], "DENY")
    def test_non_bool_flag_denied(self): self.assertIn("BAD_FEATURE_FLAGS", self.ok(feature_flags={"x": "yes"})["reasons"])
    def test_bad_track_denied(self): self.assertIn("BAD_TRACK", self.ok(track="core")["reasons"])
    def test_garbage_fails_closed(self):
        m = A.sign(self.man(), self.rev); m["signature"] = "zz"; self.assertEqual(self.adm.admit(m)["decision"], "DENY")


class Evidence(Base):
    def test_unsupported_platform_denied(self): self.assertIn("UNSUPPORTED_PLATFORM", self.ok(supported_platforms=["darwin-arm64"])["reasons"])
    def test_threat_model_digest_mismatch_denied(self):
        open(os.path.join(self.d, "tm.md"), "w").write("changed\n"); self.assertIn("THREAT_MODEL_DIGEST_MISMATCH", self.adm.admit(A.sign(self.man(threat_model={"path": "tm.md", "sha256": "0" * 64}), self.rev))["reasons"])
    def test_threat_model_path_escape_denied(self):
        self.assertIn("THREAT_MODEL_MISSING_OR_OUTSIDE_ROOT", self.ok(threat_model={"path": "../../etc/passwd", "sha256": "0" * 64})["reasons"])
    def test_symlink_escape_denied(self):
        os.symlink("/etc/hostname", os.path.join(self.d, "ln.md")); self.assertIn("THREAT_MODEL_MISSING_OR_OUTSIDE_ROOT", self.ok(threat_model={"path": "ln.md", "sha256": "0" * 64})["reasons"])
    def test_missing_evidence_denied(self): self.assertIn("EVIDENCE_NOT_FOUND_OR_DIGEST_MISMATCH", self.ok(evidence_digest="1" * 64)["reasons"])
    def test_evidence_content_swap_denied(self):
        open(os.path.join(self.ev, self.evd), "wb").write(b"swapped"); self.assertIn("EVIDENCE_NOT_FOUND_OR_DIGEST_MISMATCH", self.ok()["reasons"])


class Extra(Base):
    def test_nonexistent_threat_model_inside_root_denied(self):
        self.assertIn("THREAT_MODEL_MISSING_OR_OUTSIDE_ROOT", self.ok(threat_model={"path": "nope.md", "sha256": "0" * 64})["reasons"])
    def test_threat_model_directory_denied(self):
        os.makedirs(os.path.join(self.d, "sub")); self.assertIn("THREAT_MODEL_MISSING_OR_OUTSIDE_ROOT", self.ok(threat_model={"path": "sub", "sha256": "0" * 64})["reasons"])
    def test_internal_error_fails_closed(self):
        class Boom(TrustStore):
            def resolve(self, *a, **k): raise RuntimeError("boom")
        a = A.Admission(Boom(), root=self.d, evidence_root=self.ev, platform_id=PLAT); r = a.admit(A.sign(self.man(), self.rev))
        self.assertEqual(r["decision"], "DENY"); self.assertTrue(r["reasons"][0].startswith("INTERNAL_ERROR_FAIL_CLOSED"))
    def test_constructor_allow_elevation_honoured(self):
        a = A.Admission(self.trust, root=self.d, evidence_root=self.ev, platform_id=PLAT, allow_elevation={"file-sink": ["kernel_patch"]})
        self.assertEqual(a.admit(A.sign(self.man(feature_flags={"kernel_patch": True}), self.rev))["decision"], "ADMIT")


class Policy(Base):
    def test_missing_dependency_denied(self): self.assertIn("DEPENDENCY_NOT_ADMITTED:ledger", self.ok(dependencies={"ledger": "1.0.0"})["reasons"])
    def test_dependency_version_mismatch_denied(self):
        self.ok(name="ledger"); self.assertIn("DEPENDENCY_VERSION_MISMATCH:ledger", self.ok(name="sink", dependencies={"ledger": "2.0.0"})["reasons"])
    def test_dependency_satisfied(self):
        self.ok(name="ledger"); self.assertEqual(self.ok(name="sink", dependencies={"ledger": "1.0.0"})["decision"], "ADMIT")
    def test_elevation_denied_by_default(self): self.assertIn("ELEVATION_NOT_ALLOWED:kernel_patch", self.ok(feature_flags={"kernel_patch": True})["reasons"])
    def test_elevation_allowed_only_for_named_module(self):
        self.adm.allow["other"] = {"kernel_patch"}; self.assertIn("ELEVATION_NOT_ALLOWED:kernel_patch", self.ok(feature_flags={"kernel_patch": True})["reasons"])
        self.adm.allow["file-sink"] = {"kernel_patch"}; self.assertEqual(self.ok(feature_flags={"kernel_patch": True})["decision"], "ADMIT")
    def test_false_elevated_flag_needs_no_allow(self): self.assertEqual(self.ok(feature_flags={"kernel_patch": False})["decision"], "ADMIT")
    def test_research_cannot_join_enforcement(self):
        self.adm.allow["xx"] = {"mandatory_enforcement"}; self.assertIn("RESEARCH_MODULE_CANNOT_JOIN_ENFORCEMENT_PATH", self.ok(name="xx", track="research", effects={"e": "observed_only"}, feature_flags={"mandatory_enforcement": True})["reasons"])
    def test_research_cannot_claim_protected(self): self.assertIn("RESEARCH_MODULE_CANNOT_CLAIM_PROTECTED", self.ok(track="research")["reasons"])
    def test_kernel_cannot_depend_on_research(self):
        self.ok(name="spectra", track="research", effects={"probe": "observed_only"})
        self.assertIn("NONRESEARCH_DEPENDS_ON_RESEARCH:spectra", self.ok(name="sink", dependencies={"spectra": "1.0.0"})["reasons"])


class Lifecycle(Base):
    def test_revoke_cascades_to_dependents(self):
        self.ok(name="a"); self.ok(name="b", dependencies={"a": "1.0.0"}); self.ok(name="c", dependencies={"b": "1.0.0"}); self.ok(name="d")
        self.assertEqual(self.adm.revoke("a"), ["a", "b", "c"]); self.assertEqual(list(self.adm.admitted), ["d"])
    def test_revoke_unknown_is_noop(self): self.assertEqual(self.adm.revoke("zz"), [])
    def test_reinstall_after_revoke_requires_dependency_again(self):
        self.ok(name="a"); self.ok(name="b", dependencies={"a": "1.0.0"}); self.adm.revoke("a")
        self.assertIn("DEPENDENCY_NOT_ADMITTED:a", self.ok(name="b", dependencies={"a": "1.0.0"})["reasons"])

    def test_coverage_map_has_no_aggregate_score(self):
        self.ok(name="a", effects={"file.write": "protected", "net.send": "unknown"}); self.ok(name="b", effects={"file.write": "observed_only"})
        cm = self.adm.coverage_map(); s = json.dumps(cm).lower()
        for bad in ("score", "safe_percent", "overall"): self.assertNotIn(bad, s.replace("'safe'", ""))
        self.assertEqual(cm["effects"]["file.write"]["protected"], ["a"]); self.assertEqual(cm["effects"]["net.send"]["unknown"], ["a"]); self.assertEqual(cm["effects"]["file.write"]["observed_only"], ["b"])

    def test_unknown_not_counted_as_protected(self):
        self.ok(effects={"x": "unknown"}); self.assertEqual(self.adm.coverage_map()["effects"]["x"]["protected"], [])

if __name__ == "__main__": unittest.main()
