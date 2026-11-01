import json, os, shutil, tempfile, unittest
from horizon.agents import isolation as I
from horizon.authz.keys import Signer
from horizon.runtime import sandbox as S
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OK = os.geteuid() == 0 and S.landlock_abi() >= 4
class Clock:
    def __init__(s): s.t = 1000.0
    def __call__(s): return s.t
def world(clock=None):
    clk = clock or Clock(); auth = I.IdentityAuthority(clock=clk); pol = I.CommPolicy(); st = I.MediatedStore(auth, pol, clock=clk)
    for t in ("T1", "T2"):
        for op in ("read", "write"): pol.allow(src_tenant=t, dst_tenant=t, resource="notes", op=op)          # explicit same-tenant sharing (P34-07)
    tok = lambda tenant, run, pr="agent", ttl=300: auth.issue(tenant=tenant, run_id=run, principal=pr, ttl_s=ttl)
    return clk, auth, pol, st, tok

class Inventory(unittest.TestCase):
    def test_enumerates_and_flags_unmediated_or_unscoped(self):
        cfg = {"cache": [{"name": "kv", "writable_by": ["a", "b"], "mediated": False, "tenant_scoped": False}], "artifact_store": [{"name": "arts", "writable_by": ["a"], "mediated": True, "tenant_scoped": True}], "writable_mount": [{"name": "/scratch", "mediated": False, "tenant_scoped": True}], "message_bus": []}
        inv = I.inventory(cfg); self.assertEqual(len(inv), 3); self.assertEqual({s["name"] for s in I.unmediated_or_unscoped(inv)}, {"kv", "/scratch"})
    @unittest.skipUnless(OK, "UNSUPPORTED: needs root + Landlock")
    def test_sandbox_has_exactly_one_writable_shared_surface(self):      # measured, not assumed
        d = tempfile.mkdtemp(); os.chmod(d, 0o777)
        try:
            r = S.launch("import os\nw=[]\nfor p in ('/tmp/mk','/var/tmp/mk','/dev/shm/mk','/run/mk','/mk','s.txt'):\n  try: open(p,'w').write('x');w.append(p)\n  except OSError: pass\nprint(w)", run_id="inv", scratch=d); self.assertEqual(r.stdout.strip(), "['s.txt']")
        finally: shutil.rmtree(d, ignore_errors=True)
class Identity(unittest.TestCase):
    def test_agent_supplied_identity_strings_are_ignored_and_forged_tokens_fail(self):
        clk, auth, pol, st, tok = world(); t1 = tok("T1", "r1"); self.assertTrue(st.write(t1, "notes", "k", "v")["ok"])
        forged = json.loads(json.dumps(t1)); forged["body"]["tenant"] = "T2"; self.assertEqual(st.read(forged, "notes", "k")["code"], "INVALID_IDENTITY_TOKEN")
        other = I.IdentityAuthority(clock=clk).issue(tenant="T1", run_id="r1", principal="agent"); self.assertEqual(st.read(other, "notes", "k")["code"], "INVALID_IDENTITY_TOKEN")      # different authority key
        for bad in (None, {}, {"body": {}, "sig": "zz"}, "x", {"body": {"tenant": "T1"}, "sig": "00"}): self.assertEqual(st.read(bad, "notes", "k")["code"], "INVALID_IDENTITY_TOKEN")      # P34-08: invalid token
        self.assertTrue(st.read(t1, "notes", "k")["ok"])
    def test_unknown_recipient_and_unregistered_resource(self):
        clk, auth, pol, st, tok = world(); self.assertEqual(st.write(tok("T9", "r9"), "notes", "k", "v")["code"], "RESOURCE_NOT_REGISTERED_FOR_SCOPE"); self.assertEqual(st.write(tok("T1", "r1"), "secret_bus", "k", "v")["code"], "RESOURCE_NOT_REGISTERED_FOR_SCOPE")
class Containment(unittest.TestCase):
    def test_unmediated_shared_store_leaks_marker_negative_control(self):      # P34-05: the threat is real in the unsafe configuration
        raw = I.RawSharedStore(); m = I.marker("r1"); raw.write("msg", m); self.assertIn(m, raw.read("msg")); self.assertTrue(I.VisibilityOracle(m).visible_in_handles([raw]))
    def test_mediated_store_blocks_cross_tenant_marker(self):
        clk, auth, pol, st, tok = world(); m = I.marker("r1"); a, b = tok("T1", "r1"), tok("T2", "r2"); self.assertTrue(st.write(a, "notes", "msg", m)["ok"])
        reads = [st.read(b, "notes", "msg"), st.read(b, "notes", "msg", owner_tenant="T1"), st.read(b, "notes", "other")]
        self.assertEqual(reads[1]["code"], "CROSS_TENANT_DENIED"); self.assertIsNone(reads[0]["val"]); o = I.VisibilityOracle(m)
        self.assertFalse(o.visible_in_reads(reads)); self.assertFalse(o.visible_in_handles([]))      # the recipient holds no handle onto the backing data
        self.assertTrue(any(m in json.dumps(v) for v in st._backing_values()))      # marker exists: the sender's write really happened; the block is not a missing-write artefact
    def test_oracle_is_independent_of_broker_log(self):
        clk, auth, pol, st, tok = world(); m = I.marker("r1"); st.write(tok("T1", "r1"), "notes", "msg", m); st.log.clear(); st.log.append({"decision": "DENY", "fake": True})      # tamper the broker's log
        reads = [st.read(tok("T2", "r2"), "notes", "msg", owner_tenant="T1")]; self.assertFalse(I.VisibilityOracle(m).visible_in_reads(reads))
        leaky = I.RawSharedStore(); leaky.write("k", m); self.assertTrue(I.VisibilityOracle(m).visible_in_handles([leaky]))      # a broker whose log said DENY would still be caught by the oracle
    def test_same_tenant_collaboration_is_not_overblocked(self):
        clk, auth, pol, st, tok = world(); m = I.marker("r1"); st.write(tok("T1", "r1", "planner"), "notes", "plan", m); r = st.read(tok("T1", "r2", "worker"), "notes", "plan"); self.assertTrue(r["ok"]); self.assertEqual(r["val"], m)
    def test_runner_restart_no_cross_run_propagation(self):      # P34-12
        clk, auth, pol, st, tok = world(); m = I.marker("r1"); st.write(tok("T1", "r1"), "notes", "msg", m); restarted = tok("T2", "r2-restarted")
        self.assertFalse(I.VisibilityOracle(m).visible_in_reads([st.read(restarted, "notes", "msg"), st.read(restarted, "notes", "msg", owner_tenant="T1")])); st2 = I.MediatedStore(auth, pol, clock=clk)      # broker restart: a fresh store
        self.assertFalse(I.VisibilityOracle(m).visible_in_reads([st2.read(tok("T2", "r3"), "notes", "msg", owner_tenant="T1")]))
    def test_policy_change_and_explicit_approved_collaboration(self):
        clk, auth, pol, st, tok = world(); m = I.marker("r1"); a, b = tok("T1", "r1"), tok("T2", "r2"); st.write(a, "notes", "shared", m); self.assertFalse(st.read(b, "notes", "shared", owner_tenant="T1")["ok"])
        rule = pol.allow(src_tenant="T2", dst_tenant="T1", resource="notes", op="read", run_id="r2", approved_by="alice"); r = st.read(b, "notes", "shared", owner_tenant="T1"); self.assertTrue(r["ok"]); self.assertEqual(r["val"], m); self.assertEqual(st.log[-1]["approved_by"], "alice")
        self.assertFalse(st.read(tok("T2", "r-other"), "notes", "shared", owner_tenant="T1")["ok"])      # run-scoped: another T2 run is still denied
        self.assertFalse(st.write(b, "notes", "shared", "x", owner_tenant="T1")["ok"])      # read grant is not a write grant
        pol.revoke(rule); self.assertFalse(st.read(b, "notes", "shared", owner_tenant="T1")["ok"])
class Detection(unittest.TestCase):
    def test_repeated_rejections_alert_and_unregistered_writes(self):
        clk, auth, pol, st, tok = world(); b = tok("T2", "r2")
        for i in range(5): st.write(b, "covert_cache", f"k{i}", "x", owner_tenant="T1")
        al = [a for a in st.alerts if a["kind"] == "REPEATED_REJECTED_COMMUNICATION"]; self.assertEqual(len(al), 1); self.assertEqual(al[0]["run_id"], "r2"); self.assertEqual(al[0]["count"], 3)
        self.assertFalse([a for a in st.alerts if a["run_id"] == "r1"])
    def test_benign_run_raises_no_alert(self):
        clk, auth, pol, st, tok = world(); a = tok("T1", "r1")
        for i in range(10): st.write(a, "notes", f"k{i}", "v"); st.read(a, "notes", f"k{i}")
        self.assertEqual(st.alerts, [])
class Lifecycle(unittest.TestCase):
    def test_deadline_cancellation_and_emergency_revocation(self):
        clk, auth, pol, st, tok = world(); a = tok("T1", "r1", ttl=60); self.assertTrue(st.write(a, "notes", "k", "v")["ok"]); clk.t += 61; self.assertEqual(st.read(a, "notes", "k")["code"], "TOKEN_EXPIRED")
        b = tok("T1", "r2"); self.assertTrue(st.read(b, "notes", "k")["ok"]); auth.cancel("r2"); self.assertEqual(st.read(b, "notes", "k")["code"], "RUN_CANCELLED")
        c = tok("T1", "r3"); self.assertTrue(st.write(c, "notes", "k2", "v")["ok"]); auth.revoke("r3"); self.assertEqual(st.write(c, "notes", "k3", "v")["code"], "WORKLOAD_REVOKED"); self.assertTrue(st.write(tok("T1", "r4"), "notes", "k4", "v")["ok"])      # other runs unaffected
class Provenance(unittest.TestCase):
    def test_communication_edges_form_flow_graph(self):
        clk, auth, pol, st, tok = world(); pol.allow(src_tenant="T1", src_principal="*", dst_tenant="T1", resource="notes", op="read"); st.write(tok("T1", "r1"), "notes", "plan", "p"); st.read(tok("T1", "r2"), "notes", "plan")
        g = I.flow_graph(st.edges); self.assertEqual(g["received_from"], {"r2": ["r1"]}); self.assertIn("T1/notes/plan", g["nodes"]); st.read(tok("T2", "r9"), "notes", "plan", owner_tenant="T1"); self.assertNotIn("r9", I.flow_graph(st.edges)["received_from"])      # denied reads add no edge
@unittest.skipUnless(OK, "UNSUPPORTED: needs root + Landlock")
class RealProcesses(unittest.TestCase):
    """Two real sandboxed processes. The only writable shared surface is the scratch mount (measured above)."""
    def _pair(self, shared: bool):
        m = I.marker("real-run"); d1 = tempfile.mkdtemp(); d2 = d1 if shared else tempfile.mkdtemp()
        for d in (d1, d2): os.chmod(d, 0o777)
        try:
            S.launch(f"open('msg.txt','w').write({m!r})", run_id="sender", scratch=d1)
            r = S.launch("import os\nprint([open(f).read() for f in os.listdir('.')])", run_id="recipient", scratch=d2); return m, r.stdout
        finally: shutil.rmtree(d1, ignore_errors=True); shutil.rmtree(d2, ignore_errors=True)
    def test_unmediated_shared_mount_carries_marker_negative_control(self):
        m, out = self._pair(True); self.assertIn(m, out)
    def test_mediated_per_run_mounts_carry_nothing(self):
        m, out = self._pair(False); self.assertNotIn(m, out); self.assertEqual(out.strip(), "[]")
    def test_recipient_cannot_reach_sender_scratch_by_path(self):
        m = I.marker("path-run"); d1 = tempfile.mkdtemp(); d2 = tempfile.mkdtemp()
        for d in (d1, d2): os.chmod(d, 0o777)
        try:
            S.launch(f"open('msg.txt','w').write({m!r})", run_id="s", scratch=d1)
            r = S.launch(f"import os\nr=[]\nfor p in ({os.path.join(d1, 'msg.txt')!r},):\n  try: r.append(open(p).read())\n  except OSError as e: r.append('ERR%d' % e.errno)\nprint(r)", run_id="r", scratch=d2); self.assertNotIn(m, r.stdout); self.assertIn("ERR", r.stdout)
        finally: shutil.rmtree(d1, ignore_errors=True); shutil.rmtree(d2, ignore_errors=True)
class MG(unittest.TestCase):
    def test_mg_g8_limits_documented(self):
        t = open(os.path.join(ROOT, "docs/evidence/p34/LIMITS.md")).read()
        for k in ("covert timing", "does not prove", "in-process", "MG-G8"): self.assertIn(k, t)
if __name__ == "__main__": unittest.main()
