import copy, json, os, tempfile, time, unittest
from horizon.authz.keys import Signer, TrustStore
from horizon.weights import intake as I
REV = "a" * 40; REG = "hz-registry/models/toy@sha256:" + "b" * 64
IMG = "sha256:" + "c" * 64; LAUNCH = {"entry": "serve", "args": ["--no-remote-code"], "net": "none"}

def files_for(d, spec):
    out = []
    for path, role, data in spec:
        os.makedirs(os.path.dirname(os.path.join(d, path)) or d, exist_ok=True); open(os.path.join(d, path), "wb").write(data)
        out.append({"path": path, "role": role, "sha256": I.sha(data), "size": len(data)})
    return out
def manifest(d, kind="base", base_digest=None, extra_files=()):
    spec = [("model-00001.safetensors", "weight", b"W1" * 50), ("model-00002.safetensors", "weight", b"W2" * 50), ("tokenizer.json", "tokenizer", b'{"v":1}'), ("config.json", "config", b'{"layers":2}')] if kind == "base" else [("adapter.safetensors", "adapter", b"A" * 40)]
    m = {"schema": I.SCHEMA, "model_id": "toy-1" if kind == "base" else "toy-1-lora", "kind": kind, "source": {"repo": "hz-registry/models/toy", "revision": REV, "registry_uri": REG}, "files": files_for(d, spec + list(extra_files)),
         "license": {"spdx": "UNKNOWN", "redistribution": "not-asserted", "notes": "no rights invented"}, "dependencies": {"safetensors": "0.4.5"}, "runtime": {"image_digest": IMG, "launch_config_sha256": I.sha(I.canon(LAUNCH))}}
    if kind == "adapter": m["base"] = {"manifest_digest": base_digest}
    return m
class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.d = self.tmp.name; self.sg = Signer.generate("k1", "model-authority"); self.ts = TrustStore(); now = time.time(); self.ts.add("k1", "model-authority", self.sg.public_raw(), not_before=now - 100, not_after=now + 3600)
        self.m = I.sign(manifest(self.d), self.sg); self.q = I.Quarantine()
    def tearDown(self): self.tmp.cleanup()
    def admit(self, m=None, **kw):
        kw.setdefault("trust", self.ts); kw.setdefault("image_digest", IMG); kw.setdefault("launch_config", LAUNCH); return I.admit(m or self.m, self.d, quarantine=self.q, **kw)

class Schema(unittest.TestCase):
    def test_valid_and_closed_world(self):
        with tempfile.TemporaryDirectory() as d:
            m = I.sign(manifest(d), Signer.generate("k", "i")); self.assertEqual(I.validate_schema(m), [])
            c0 = copy.deepcopy(m); c0.pop("signer"); self.assertIn("BAD_SIGNER", I.validate_schema(c0))
            for mut, code in [(lambda x: x.update(extra=1), "UNKNOWN_KEY:extra"), (lambda x: x.update(schema="v0"), "BAD_SCHEMA"), (lambda x: x.update(files=[]), "NO_FILES"), (lambda x: x["files"][0].update(sha256="xyz"), "BAD_FILE"), (lambda x: x["files"][0].update(path="../x"), "BAD_PATH"), (lambda x: x["files"][0].update(role="exec"), "BAD_FILE"),
                              (lambda x: x.pop("license"), "BAD_LICENSE"), (lambda x: x.update(kind="adapter"), "ADAPTER_WITHOUT_BASE_DIGEST")]:
                c = copy.deepcopy(m); mut(c); self.assertTrue(any(p.startswith(code) for p in I.validate_schema(c)), code)
class Admission(Base):
    def test_good_manifest_admitted_with_separate_verdicts(self):
        r = self.admit(); self.assertEqual(r["decision"], "ADMIT", r["reasons"]); self.assertEqual(r["report"]["metadata_authenticity"], "AUTHENTIC"); self.assertEqual(r["report"]["behavioral_trust"], "UNASSESSED"); self.assertIn("NOTHING about dormant", r["report"]["note"])
    def test_altered_single_shard_with_correct_name_denied(self):      # P31-10
        open(os.path.join(self.d, "model-00002.safetensors"), "wb").write(b"W2" * 49 + b"XX")
        r = self.admit(); self.assertEqual(r["decision"], "DENY"); self.assertTrue(any("FILE_ALTERED:model-00002.safetensors" in x for x in r["reasons"])); self.assertEqual(r["report"]["metadata_authenticity"], "NOT_AUTHENTIC")
    def test_missing_and_extra_files(self):
        os.remove(os.path.join(self.d, "config.json")); open(os.path.join(self.d, "extra.safetensors"), "wb").write(b"z"); r = self.admit(); self.assertTrue(any(x.startswith("FILE_MISSING") for x in r["reasons"])); self.assertTrue(any(x.startswith("FILE_EXTRA") for x in r["reasons"]))
    def test_unsigned_tampered_or_wrong_key_denied(self):
        m = copy.deepcopy(self.m); m["model_id"] = "other"; self.assertIn("BAD_SIGNATURE", self.admit(m)["reasons"])
        m = copy.deepcopy(self.m); m.pop("signature"); self.assertEqual(self.admit(m)["decision"], "DENY")
        rogue = Signer.generate("k1", "model-authority"); m = I.sign(manifest(self.d), rogue); self.assertIn("BAD_SIGNATURE", self.admit(m)["reasons"])      # same kid, different key: registry decides, not the manifest
        m = I.sign(manifest(self.d), Signer.generate("k9", "model-authority")); self.assertTrue(any(x.startswith("SIGNER_") for x in self.admit(m)["reasons"]))
    def test_revoked_and_expired_signer(self):
        self.ts.revoke("k1"); self.assertTrue(any("REVOKED" in x for x in self.admit()["reasons"]))
        ts2 = TrustStore(); ts2.add("k1", "model-authority", self.sg.public_raw(), not_before=time.time() - 100, not_after=time.time() + 100); self.assertTrue(any(x.startswith("SIGNER_") for x in self.admit(trust=ts2, at=time.time() + 1000)["reasons"]))
    def test_fail_closed_when_trust_root_missing_or_broken(self):
        self.assertEqual(self.admit(trust=None)["decision"], "DENY"); self.assertIn("TRUST_ROOT_UNAVAILABLE", self.admit(trust=None)["reasons"])
        class Broken(TrustStore):
            def resolve(self, *a, **k): raise RuntimeError("store offline")
        r = self.admit(trust=Broken()); self.assertEqual(r["decision"], "DENY"); self.assertTrue(any("VERIFICATION_UNAVAILABLE:signature" in x for x in r["reasons"]))
    def test_pins_reject_mutable_refs(self):
        for field, val in [("revision", "main"), ("revision", "latest"), ("revision", "abc123"), ("registry_uri", "hz-registry/models/toy:latest"), ("registry_uri", "hz-registry/models/toy"), ("repo", "evil.example/models/toy")]:
            m = copy.deepcopy(self.m); m["source"][field] = val; m = I.sign(m, self.sg); self.assertTrue(I.check_pins(m), (field, val)); self.assertEqual(self.admit(m)["decision"], "DENY")
        m = copy.deepcopy(self.m); m["source"]["revision"] = "main"; self.assertEqual(I.check_pins(m, protected=False), [])       # only protected profiles insist
    def test_unsafe_formats_and_disguised_pickle(self):
        import pickle
        m = manifest(self.d, extra_files=[("weights.pt", "weight", b"\x80\x02}q\x00."), ("hook.py", "config", b"import os\n")]); m = I.sign(m, self.sg); r = self.admit(m); self.assertTrue(any("FILE_UNSAFE_FORMAT" in x and "weights.pt" in x and "hook.py" in x for x in r["reasons"]))
        m = manifest(self.d, extra_files=[("sneaky.safetensors", "weight", pickle.dumps({"x": 1}, protocol=4))]); m = I.sign(m, self.sg); self.assertTrue(any("FILE_DISGUISED_EXECUTABLE:sneaky.safetensors" in x for x in self.admit(m)["reasons"]))
    def test_runtime_image_and_launch_config_bound(self):
        self.assertIn("RUNTIME_IMAGE_NOT_APPROVED", self.admit(image_digest="sha256:" + "d" * 64)["reasons"]); self.assertIn("LAUNCH_CONFIG_NOT_APPROVED", self.admit(launch_config={**LAUNCH, "args": ["--trust-remote-code"]})["reasons"])
class Adapters(Base):
    def test_unauthorized_adapter_replacement(self):      # P31-11
        a = I.sign(manifest(self.d, kind="adapter", base_digest=I.digest(self.m)), self.sg)
        r = I.admit(a, self.d, trust=self.ts, quarantine=self.q, image_digest=IMG, launch_config=LAUNCH, approved_base=self.m); self.assertNotIn("ADAPTER_BASE_MISMATCH", r["reasons"])
        evil = copy.deepcopy(self.m); evil["files"][0]["sha256"] = "e" * 64; evil = I.sign(evil, self.sg)       # a different base model under the same name
        r = I.admit(a, self.d, trust=self.ts, quarantine=self.q, image_digest=IMG, launch_config=LAUNCH, approved_base=evil); self.assertIn("ADAPTER_BASE_MISMATCH", r["reasons"])
        r = I.admit(a, self.d, trust=self.ts, quarantine=self.q, image_digest=IMG, launch_config=LAUNCH); self.assertIn("ADAPTER_WITHOUT_APPROVED_BASE", r["reasons"])
        swapped = I.sign(manifest(self.d, kind="adapter", base_digest=I.digest(self.m)), self.sg); open(os.path.join(self.d, "adapter.safetensors"), "wb").write(b"B" * 40)
        self.assertTrue(any("FILE_ALTERED:adapter.safetensors" in x for x in I.admit(swapped, self.d, trust=self.ts, quarantine=self.q, image_digest=IMG, launch_config=LAUNCH, approved_base=self.m)["reasons"]))      # same base, same names, swapped adapter bytes
class Drift(Base):
    def test_tokenizer_config_drift_and_approved_upgrade(self):     # P31-12
        open(os.path.join(self.d, "tokenizer.json"), "wb").write(b'{"v":2}'); new = copy.deepcopy(self.m); new["files"][2]["sha256"] = I.sha(b'{"v":2}'); new["files"][2]["size"] = 7; new = I.sign(new, self.sg)
        self.assertEqual(I.drift(self.m, new), {"tokenizer": ["tokenizer.json"]})
        r = self.admit(new, approved=self.m); self.assertEqual(r["decision"], "DENY"); self.assertTrue(any(x.startswith("DRIFT_WITHOUT_UPGRADE:tokenizer") for x in r["reasons"]))
        up = I.issue_upgrade(self.sg, old_digest=I.digest(self.m), new_digest=I.digest(new), reason="tokenizer fix CVE-less test"); r = self.admit(new, approved=self.m, upgrade=up); self.assertEqual(r["decision"], "ADMIT", r["reasons"])      # control: approved upgrade passes
        other = I.issue_upgrade(self.sg, old_digest="0" * 64, new_digest=I.digest(new), reason="x"); self.assertIn("UPGRADE_NOT_FOR_THESE_DIGESTS", self.admit(new, approved=self.m, upgrade=other)["reasons"])
        old = I.issue_upgrade(self.sg, old_digest=I.digest(self.m), new_digest=I.digest(new), reason="x", ttl_s=-10); self.assertIn("UPGRADE_EXPIRED", self.admit(new, approved=self.m, upgrade=old)["reasons"])
        forged = dict(up, new="f" * 64); self.assertIn("UPGRADE_BAD_SIGNATURE", self.admit(new, approved=self.m, upgrade=forged)["reasons"])
class Quarantining(Base):
    def test_revoked_source_quarantine_and_chain(self):
        self.q.revoke_source("hz-registry/models/toy", "compromised upstream"); self.assertIn("SOURCE_REVOKED", self.admit()["reasons"])
        q2 = I.Quarantine(); q2.quarantine(I.digest(self.m), "suspected tamper", {"case": 1}); r = I.admit(self.m, self.d, trust=self.ts, quarantine=q2, image_digest=IMG, launch_config=LAUNCH); self.assertIn("MANIFEST_QUARANTINED", r["reasons"])
        q2.revoke_source("x", "y"); self.assertTrue(q2.verify_chain()); q2.chain[0]["data"]["why"] = "edited"; self.assertFalse(q2.verify_chain())
        q3 = I.Quarantine(); q3.revoke_source("a", "1"); q3.revoke_source("b", "2"); del q3.chain[0]; self.assertFalse(q3.verify_chain())
class Receipts(Base):
    def test_receipt_signed_and_attached(self):
        r = self.admit(); rc = I.receipt(r, self.sg, run_id="run-1", source=self.m["source"]); self.assertTrue(I.verify_receipt(rc, self.sg.public_raw()))
        t = I.attach_to_trace({"run_id": "run-1"}, rc); self.assertEqual(t["model_manifest_digest"], I.digest(self.m)); rc2 = dict(rc, decision="ADMIT" if rc["decision"] == "DENY" else "DENY"); self.assertFalse(I.verify_receipt(rc2, self.sg.public_raw()))
        d = self.admit(trust=None); self.assertEqual(I.receipt(d, self.sg, run_id="r", source=self.m["source"])["decision"], "DENY")
class Inventory(unittest.TestCase):
    def test_inventory_finds_patterns_and_repo_has_no_model_loading(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "horizon")); open(os.path.join(d, "horizon", "x.py"), "w").write("import torch\nm=torch.load('a.pt')\nx=AutoModel.from_pretrained('o/m', revision='main')\nimport pickle; pickle.load(f)\n")
            inv = I.inventory(d); self.assertTrue(inv["torch_load"] and inv["hf_from_pretrained"] and inv["pickle_load"] and inv["remote_model_ref"])
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); real = I.inventory(root)
        for k in ("hf_from_pretrained", "torch_load", "pickle_load", "joblib_load", "adapter_load", "remote_model_ref"): self.assertEqual(real[k], [], k)
class MG(Base):
    def test_mg_g3_altered_unknown_revoked_unapproved_never_admitted(self):
        """MG-G3: every way an artifact can be wrong must DENY at the protected-runner admission point."""
        cases = []
        open(os.path.join(self.d, "model-00001.safetensors"), "wb").write(b"evil"); cases.append(("altered", self.admit()))
        cases.append(("unknown signer", self.admit(I.sign(manifest(self.d), Signer.generate("zz", "model-authority")))))
        cases.append(("no trust root", self.admit(trust=None)))
        self.ts.revoke("k1"); cases.append(("revoked", self.admit()))
        for name, r in cases: self.assertEqual(r["decision"], "DENY", name); self.assertNotEqual(r["report"]["metadata_authenticity"], "AUTHENTIC", name)
    def test_mg_g4_limits_disclosed_and_trust_never_implied(self):
        t = open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "docs/evidence/p31/DORMANT_TRIGGER_LIMITS.md")).read(); self.assertIn("dormant", t); self.assertIn("UNASSESSED", t); self.assertIn("free of backdoors", t)
        r = self.admit(); self.assertEqual(r["decision"], "ADMIT"); self.assertEqual(r["report"]["behavioral_trust"], "UNASSESSED")
    def test_inventory_doc_is_current(self):
        import subprocess, sys
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); self.assertEqual(subprocess.run([sys.executable, "scripts/p31_inventory.py", "--check"], cwd=root, capture_output=True).returncode, 0)
if __name__ == "__main__": unittest.main()
