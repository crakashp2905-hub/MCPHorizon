import json, os, subprocess, sys, tempfile, unittest
R = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, R)
class Client:
    def __init__(self, root, journal, db):
        self.p = subprocess.Popen([sys.executable, "-B", "-m", "horizon.effects.mcp_gateway", root, journal, db], cwd=R, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1); self.n = 0
    def rpc(self, method, params=None, notify=False):
        self.n += 1; m = {"jsonrpc": "2.0", "method": method, **({"params": params} if params is not None else {})}
        if not notify: m["id"] = self.n
        self.p.stdin.write(json.dumps(m) + "\n"); self.p.stdin.flush()
        return None if notify else json.loads(self.p.stdout.readline())
    def call(self, **a): return self.rpc("tools/call", {"name": "write_file", "arguments": a})
    def close(self): self.p.stdin.close(); self.p.wait(timeout=10)
class E2E(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp()); self.root = os.path.join(self.d, "ws"); os.makedirs(self.root); self.out = os.path.join(self.d, "outside"); os.makedirs(self.out)
        self.j = os.path.join(self.d, "journal.jsonl"); self.db = os.path.join(self.d, "l.db"); self.c = Client(self.root, self.j, self.db)
    def tearDown(self): self.c.close()
    def test_handshake_and_tool_list(self):
        r = self.c.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}); self.assertEqual(r["result"]["serverInfo"]["name"], "horizon-effect-gateway")
        self.c.rpc("notifications/initialized", notify=True); t = self.c.rpc("tools/list"); self.assertEqual([x["name"] for x in t["result"]["tools"]], ["write_file"])
    def test_real_write_goes_through_permit_ledger_sink_and_receipt(self):
        r = self.c.call(path="a.txt", content="TEST_CANARY_NOT_SECRET hello", effect_id="e1")["result"]; sc = r["structuredContent"]
        self.assertFalse(r["isError"]); self.assertEqual((sc["status"], sc["ledger_state"]), ("ALLOW_COMMITTED", "COMMITTED"))
        self.assertEqual(open(os.path.join(self.root, "a.txt")).read(), "TEST_CANARY_NOT_SECRET hello")
        rows = [json.loads(x) for x in open(self.j)]; self.assertEqual([x.get("effect_id") for x in rows if "effect_id" in x], ["e1"]); self.assertEqual(sc["sink_receipt"]["sha256"], [x for x in rows if x.get("effect_id") == "e1"][0]["sha256"])
    def test_duplicate_effect_id_is_not_rewritten(self):
        self.c.call(path="a.txt", content="one", effect_id="e1"); r = self.c.call(path="a.txt", content="two", effect_id="e1")["result"]
        self.assertTrue(r["isError"]); self.assertEqual(r["structuredContent"]["status"], "DUPLICATE"); self.assertEqual(open(os.path.join(self.root, "a.txt")).read(), "one")
    def test_policy_denies_traversal_absolute_and_hidden_and_nothing_is_written(self):
        for path in ("../outside/x.txt", os.path.join(self.out, "y.txt"), ".hidden", "sub/z.txt"):
            r = self.c.call(path=path, content="x", effect_id="e-" + str(abs(hash(path))))["result"]; self.assertTrue(r["isError"], path); self.assertEqual(r["structuredContent"]["code"], "POLICY_DENIED")
        self.assertEqual(os.listdir(self.out), []); self.assertEqual(os.listdir(self.root), []); self.assertFalse(os.path.exists(self.j) and open(self.j).read().strip())
    def test_symlink_escape_blocked_even_if_policy_looks_fine(self):
        os.symlink(self.out, os.path.join(self.root, "lnk")); r = self.c.call(path="lnk", content="x", effect_id="e9")["result"]
        self.assertTrue(r["isError"]); self.assertEqual(os.listdir(self.out), [])
    def test_symlink_alias_inside_root_is_denied_by_policy(self):     # real path looks fine (lands in root) but the requested path is not the real path
        os.symlink(self.root, os.path.join(self.root, "alias")); r = self.c.call(path="alias/f.txt", content="x", effect_id="ea")["result"]
        self.assertEqual(r["structuredContent"]["code"], "POLICY_DENIED"); self.assertFalse(os.path.exists(os.path.join(self.root, "f.txt")))
        self.assertFalse(r["structuredContent"]["retryable"]); self.assertIn("will not succeed", r["content"][0]["text"]); self.assertIn("allowed path", r["content"][0]["text"])   # tells a model the denial is final and what to do instead
    def test_malformed_requests_fail_closed(self):
        for args in ({}, {"path": "a", "content": "b"}, {"path": "a", "content": 5, "effect_id": "e"}, {"path": "a", "content": "b", "effect_id": "e", "extra": 1}):
            r = self.c.call(**args)["result"]; self.assertTrue(r["isError"]); self.assertIn("INVALID_ARGUMENTS", r["content"][0]["text"])
        self.assertEqual(self.c.rpc("tools/call", {"name": "rm_rf", "arguments": {}})["error"]["code"], -32602); self.assertEqual(self.c.rpc("resources/read", {})["error"]["code"], -32601)
        self.c.p.stdin.write("not json\n"); self.c.p.stdin.flush(); self.assertEqual(json.loads(self.c.p.stdout.readline())["error"]["code"], -32700); self.assertEqual(os.listdir(self.root), [])
    def test_restart_keeps_ledger_and_prevents_double_write(self):
        self.c.call(path="a.txt", content="one", effect_id="e1"); self.c.close(); self.c = Client(self.root, self.j, self.db)
        r = self.c.call(path="a.txt", content="two", effect_id="e1")["result"]; self.assertEqual(r["structuredContent"]["status"], "DUPLICATE"); self.assertEqual(open(os.path.join(self.root, "a.txt")).read(), "one")
    def test_sink_journal_records_exactly_the_committed_effects(self):
        for i in range(3): self.c.call(path=f"f{i}.txt", content=str(i), effect_id=f"e{i}")
        self.c.call(path="../outside/q", content="no", effect_id="eq"); ids = [json.loads(x)["effect_id"] for x in open(self.j) if "effect_id" in json.loads(x)]; self.assertEqual(sorted(ids), ["e0", "e1", "e2"])
if __name__ == "__main__": unittest.main()
