"""P6 Code Mode tests: static preview, mediated runtime, isolation, limits, lineage, mixed MCP+UTCP through the REAL gates, semantic equivalence."""
import json, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from horizon.codemode.exec import Executor, scan, diff_report, CodeModeError, HERE
from tests.p4 import test_mcp_adapter as T4
from tests.p5 import test_utcp_adapter as T5
from horizon.adapters.mcp import wire as W

HAVE_NODE = bool(shutil.which("node")) and (HERE / "node_modules" / "isolated-vm").exists()


def ok_mediator(log):
    def m(c): log.append(c); return {"ok": True, "result": {"echo": c["args"], "tool": c["tool"]}}
    return m


@unittest.skipUnless(HAVE_NODE, "node + codemode/node_modules required (npm ci in codemode/)")
class Static(unittest.TestCase):
    def test_direct_calls_found_and_never_exhaustive(self):
        r = scan("const a = await tools.mcp.get_doc({id:'1'}); await tools.utcp.get({id:'2'}); return a;")
        self.assertEqual(sorted(c["name"] for c in r["calls"]), ["mcp.get_doc", "utcp.get"]); self.assertEqual((r["verdict"], r["exhaustive"], r["has_unknown"]), ("PARTIAL_PREVIEW", False, False))

    def test_unknown_constructs_flagged(self):
        for code in ("const t = tools; await t.mcp.get_doc({})", "const {mcp} = tools; await mcp.get_doc({})", "const k='get_doc'; await tools.mcp[k]({})", "const f = tools.mcp.get_doc; await f({})", "const g = (x)=>x; g(tools)",
                     "eval('tools.mcp.get_doc({})')", "await (async()=>{}).constructor('return tools')()", "return this", "await import('fs')", "with ({}) {}", "const x = ;"):
            r = scan(code); self.assertTrue(r["has_unknown"], code); self.assertFalse(r["exhaustive"])

    def test_no_misleading_complete_verdict_even_for_empty_program(self):
        self.assertEqual(scan("return 1")["verdict"], "PARTIAL_PREVIEW")


@unittest.skipUnless(HAVE_NODE, "node required")
class Runtime(unittest.TestCase):
    def setUp(self): self.log = []; self.ex = Executor(ok_mediator(self.log))
    def run_(self, code, tools=("mcp.get_doc", "utcp.get"), **kw): kw.setdefault("timeout_s", 30); return self.ex.run(code, list(tools), principal="agent-a", **kw)      # generous: tests assert behaviour, not speed

    def test_basic_result_and_trusted_context(self):
        r = self.run_("const a = await tools.mcp.get_doc({id:'1', principal:'admin'}); return a;"); self.assertTrue(r["ok"], r)
        c = self.log[0]; self.assertEqual((c["principal"], c["tool"], c["parent_execution_id"]), ("agent-a", "mcp.get_doc", None)); self.assertEqual(c["args"]["principal"], "admin")      # stays DATA inside args
        self.assertTrue(c["call_id"].startswith(r["exec_id"]))

    def test_aliases_closures_destructuring_and_dynamic_selection_are_all_mediated(self):
        code = """
          const t = tools; const {mcp} = tools; const f = tools.mcp.get_doc; const k = 'get_' + 'doc';
          const mk = (n) => () => tools.mcp[n]({via:'closure'});
          const out = [await t.mcp.get_doc({via:'alias'}), await mcp.get_doc({via:'destructure'}), await f({via:'fn'}), await tools.mcp[k]({via:'computed'}), await mk('get_doc')()];
          return out.map(o => o.echo.via);"""
        r = self.run_(code); self.assertTrue(r["ok"], r); self.assertEqual(r["result"], ["alias", "destructure", "fn", "computed", "closure"]); self.assertEqual(len(self.log), 5)
        st = scan(code); rep = diff_report(st, r["calls"]); self.assertTrue(rep["static_flagged_unknown"]); self.assertEqual(len(rep["runtime_names"]), 1)

    def test_static_false_negative_is_measured_and_reported(self):
        code = "const k = ['get','doc'].join('_'); return (await tools.mcp[k]({})).tool;"
        rep = diff_report(scan(code), self.run_(code)["calls"]); self.assertEqual(rep["static_false_negatives"], ["mcp.get_doc"]); self.assertTrue(rep["static_flagged_unknown"])

    def test_loops_recursion_generators_promise_all_and_rejections(self):
        code = """
          let n = 0; for (let i = 0; i < 3; i++) await tools.mcp.get_doc({i}); n += 3;
          const rec = async (d) => { if (d === 0) return 0; await tools.utcp.get({d}); return 1 + await rec(d - 1); }; n += await rec(2);
          function* g(){ yield 1; yield 2; } for (const x of g()) await tools.mcp.get_doc({g:x}); n += 2;
          const all = await Promise.all([tools.mcp.get_doc({p:1}), tools.mcp.get_doc({p:2}), tools.utcp.get({p:3})]); n += all.length;
          const settled = await Promise.allSettled([tools.mcp.get_doc({}), Promise.reject(new Error('r'))]); return [n, settled.map(s => s.status)];"""
        r = self.run_(code); self.assertTrue(r["ok"], r); self.assertEqual(r["result"], [3 + 2 + 2 + 3, ["fulfilled", "rejected"]]); self.assertEqual(len(self.log), 3 + 2 + 2 + 3 + 1)

    def test_burst_of_parallel_calls_does_not_stall_the_protocol(self):
        for _ in range(5):
            r = self.run_("const rs = await Promise.all(Array.from({length: 60}, (_, i) => tools.mcp.get_doc({i}))); return rs.length;", timeout_s=20)
            self.assertEqual((r["ok"], r["result"]), (True, 60), r.get("error"))
        self.assertEqual(len(self.log), 300)

    def test_denied_call_rejects_inside_program_and_is_catchable(self):
        ex = Executor(lambda c: {"ok": False, "error": "DENIED"}); r = ex.run("try { await tools.mcp.get_doc({}); return 'bad'; } catch (e) { return e.code; }", ["mcp.get_doc"], principal="p")
        self.assertEqual(r["result"], "DENIED"); self.assertEqual(r["calls"][0]["outcome"], "denied_or_failed")

    def test_unknown_tool_never_reaches_mediator(self):
        r = self.run_("try { return await tools.admin.shell({}); } catch (e) { return String(e.message); }", tools=("mcp.get_doc",)); self.assertEqual(self.log, []); self.assertIn("undefined", r["result"] or r["message"] or "")

    def test_nested_callbacks_and_unawaited_calls_are_mediated_not_lost(self):
        r = self.run_("[1,2].forEach(async (i) => { await tools.mcp.get_doc({i}); }); tools.utcp.get({fire:'forget'}); return 'done';"); self.assertTrue(r["ok"], r)
        self.assertGreaterEqual(len(self.log), 1)                                                                                                  # in-flight work is mediated (and flagged), never silently skipped

    def test_effects_chained_after_outer_completion_never_happen(self):
        import time
        def slow(c): self.log.append(c); time.sleep(0.4); return {"ok": True, "result": 1}
        ex = Executor(slow); r = ex.run("tools.mcp.get_doc({step: 1}).then(() => tools.mcp.get_doc({step: 2})); return 'early';", ["mcp.get_doc"], principal="p")
        self.assertEqual((r["ok"], r["result"]), (True, "early")); self.assertEqual([c["args"]["step"] for c in self.log], [1]); self.assertEqual(r["pending_unconfirmed"], [])          # step 2 was never issued

    def test_calls_made_after_return_but_before_host_sees_completion_are_still_mediated(self):
        r = self.run_("(async () => { for (let i = 0; i < 20; i++) await null; await tools.mcp.get_doc({late: true}); })().catch(() => {}); return 'early';")
        self.assertEqual(r["result"], "early"); self.assertEqual(len([c for c in self.log if c["args"].get("late")]) + r["late_calls"], 1)           # either mediated or denied as late: never unmonitored

    def test_errors_and_cancellation_and_retries_are_audited(self):
        r = self.run_("throw new Error('boom sk-abcdefghijklmnop1234')"); self.assertEqual((r["ok"], r["error"]), (False, "PROGRAM_ERROR")); self.assertNotIn("sk-abcdef", json.dumps(r))
        self.assertIn("finished", [a["event"] for a in self.ex.audit]); self.assertEqual(self.ex.audit[-1]["outcome"], "PROGRAM_ERROR")
        ex = Executor(lambda c: (ex.cancel(c["exec_id"]), {"ok": True, "result": 1})[1]); r = ex.run("await tools.mcp.get_doc({}); await tools.mcp.get_doc({}); return 1", ["mcp.get_doc"], principal="p")
        self.assertEqual(r["error"], "CANCELLED"); self.assertEqual(sum(1 for c in r["calls"] if c["outcome"] == "ok"), 1)                          # no mediation after cancel

    def test_lineage_parent_ids(self):
        outer = self.run_("return await tools.mcp.get_doc({})"); inner = self.ex.run("return await tools.mcp.get_doc({})", ["mcp.get_doc"], principal="agent-a", parent_execution_id=outer["exec_id"])
        self.assertEqual(self.log[-1]["parent_execution_id"], outer["exec_id"]); self.assertEqual(self.ex.info[inner["exec_id"]]["parent_execution_id"], outer["exec_id"])
        self.assertTrue(all(c["parent_execution_id"] == outer["exec_id"] for c in outer["calls"]))

    def test_host_validates_inputs(self):
        for kw in (dict(principal=""), dict(principal=None)):
            with self.assertRaises(CodeModeError): self.ex.run("return 1", [], **kw)
        with self.assertRaises(CodeModeError): self.ex.run("return 1", ["a b"], principal="p")
        with self.assertRaises(CodeModeError): self.ex.run("x" * 300_000, [], principal="p")
        r = self.run_("return await tools.mcp.get_doc(() => 1)"); self.assertTrue(r["ok"] or r["error"])       # non-serialisable args do not crash the host


@unittest.skipUnless(HAVE_NODE, "node required")
class Isolation(unittest.TestCase):
    def setUp(self): self.log = []; self.ex = Executor(ok_mediator(self.log))
    def run_(self, code, **kw): kw.setdefault("timeout_s", 30); return self.ex.run(code, ["mcp.get_doc"], principal="p", **kw)

    def test_no_host_apis_in_isolate(self):
        names = ["require", "process", "fetch", "XMLHttpRequest", "WebSocket", "setTimeout", "setInterval", "setImmediate", "Buffer", "Deno", "Bun", "module", "exports", "__dirname", "__filename", "import", "ivm", "__call", "__log", "__tools", "navigator", "performance"]
        r = self.run_("const n = " + json.dumps(names) + "; return n.map(x => typeof globalThis[x] !== 'undefined' ? x : null).filter(Boolean)"); self.assertEqual(r["result"], [], r)

    def test_known_escape_attempts_fail(self):
        attempts = ["return (function(){}).constructor('return typeof process')()", "return (async()=>{}).constructor('return typeof require')().then(x=>x)", "return this.constructor.constructor('return typeof process')()",
                    "return Object.getPrototypeOf(async function(){}).constructor('return typeof process')()", "await import('node:fs')", "return typeof (0, eval)('process')", "return Reflect.ownKeys(globalThis).filter(k => /call|log|tools_|ivm/i.test(String(k)))"]
        for a in attempts:
            r = self.run_(a)
            if r["ok"]: self.assertIn(r["result"], ("undefined", []), a)
            else: self.assertIn(r["error"], ("PROGRAM_ERROR",), a)

    def test_tools_cannot_be_replaced_or_extended(self):
        r = self.run_("'use strict'; const res = []; for (const f of [() => { globalThis.tools = {}; }, () => { tools.mcp.get_doc = null; }, () => { tools.extra = 1; }, () => { delete tools.mcp; }]) { try { f(); res.push('mutated'); } catch (e) { res.push('blocked'); } } return res;")
        self.assertEqual(r["result"], ["blocked"] * 4, r)

    def test_runner_is_nonprivileged_and_env_scrubbed(self):
        os.environ["CM_SECRET"] = "s"; self.addCleanup(os.environ.pop, "CM_SECRET", None)
        r = self.run_("return 1"); want = 65534 if os.geteuid() == 0 else os.geteuid(); self.assertEqual(r["runner"]["uid"], want); self.assertNotIn("CM_SECRET", r["runner"]["env_keys"]); self.assertTrue(set(r["runner"]["env_keys"]) <= {"PATH", "HOME", "LANG", "PWD", "SHLVL", "_"}, r["runner"]["env_keys"])

    def test_timeout_infinite_loop_and_never_resolving_promise(self):
        for code in ("while (true) {}", "await new Promise(() => {})"):
            r = self.run_(code, timeout_s=1); self.assertEqual((r["ok"], r["error"]), (False, "TIMEOUT"), code)

    def test_memory_limit(self):
        r = self.run_("const a = []; while (true) a.push(new Array(1e6).fill(1.5));", memory_mb=32, timeout_s=10); self.assertFalse(r["ok"]); self.assertIn(r["error"], ("MEMORY_LIMIT", "PROGRAM_ERROR", "RUNNER_FAILED", "TIMEOUT"))
        self.assertTrue(self.run_("return 1")["ok"])                                                                                                  # host and executor unaffected

    def test_log_bounds_and_redaction(self):
        r = self.run_("for (let i = 0; i < 5000; i++) console.log('x'.repeat(100)); console.log('key sk-abcdefghijklmnop1234'); return 1", max_log_bytes=2000)
        self.assertTrue(r["ok"]); self.assertTrue(r["log_truncated"]); self.assertLessEqual(sum(len(l["text"]) for l in r["logs"]), 2000 + 200)
        r = self.run_("console.error('sk-abcdefghijklmnop1234'); console.log({a:'Bearer abcdefghij12345'})"); self.assertNotIn("sk-abcdef", json.dumps(r["logs"])); self.assertNotIn("abcdefghij12345", json.dumps(r["logs"]))

    def test_call_budget(self):
        ex = Executor(ok_mediator(self.log)); r = ex.run("let n=0; try { for (;;) { await tools.mcp.get_doc({}); n++; } } catch (e) { return [n, e.code]; }", ["mcp.get_doc"], principal="p", max_calls=5, timeout_s=30)
        self.assertEqual(r["result"], [5, "CALL_BUDGET"], {k: r[k] for k in ("ok", "error", "message", "runner")}); self.assertEqual(len(self.log), 5)

    def test_mediator_failure_is_generic(self):
        ex = Executor(lambda c: 1 / 0); r = ex.run("try { await tools.mcp.get_doc({}) } catch (e) { return [e.code, e.message] }", ["mcp.get_doc"], principal="p"); self.assertEqual(r["result"], ["MEDIATOR_ERROR", "MEDIATOR_ERROR"])
        ex = Executor(lambda c: "garbage"); r = ex.run("try { await tools.mcp.get_doc({}) } catch (e) { return e.code }", ["mcp.get_doc"], principal="p"); self.assertEqual(r["result"], "MEDIATOR_ERROR")

    def test_runner_killed_even_if_program_forks_nothing(self):
        r = self.run_("return 1"); self.assertEqual(subprocess.run(["pgrep", "-f", "codemode/runner.mjs"], capture_output=True).stdout.strip(), b"") if shutil.which("pgrep") else None

    @unittest.skipUnless(shutil.which("unshare") and subprocess.run(["unshare", "-Urn", "true"], capture_output=True).returncode == 0, "user+net namespaces unavailable here")
    def test_network_namespace_option_runs_and_has_no_interfaces_but_lo(self):
        p = subprocess.run(["unshare", "-Urn", "--", "cat", "/proc/net/dev"], capture_output=True, text=True); ifs = [l.split(":")[0].strip() for l in p.stdout.splitlines()[2:]]; self.assertEqual(ifs, ["lo"])
        r = Executor(ok_mediator([]), net_namespace=True).run("return await tools.mcp.get_doc({})", ["mcp.get_doc"], principal="p", timeout_s=8); self.assertTrue(r["ok"], r)


def mcp_mediator(b4):
    def m(c):
        _, name = c["tool"].split(".", 1)
        req = W.decode_modern(T4.hdr("tools/call", name), T4.body_mod("tools/call", {"name": name, "arguments": c["args"]}, rid=abs(hash(c["call_id"])) % 10**9), c["principal"])
        resp = b4.gate.handle("s1", req, run_artifacts=tuple(c["args"].get("_artifacts", ())) if False else ())
        return {"ok": True, "result": resp["result"]} if resp and "result" in resp else {"ok": False, "error": ((resp or {}).get("error") or {}).get("data", {}).get("verdict") or "DENIED"}
    return m


def router(b4, b5, arts4=(), arts5=()):
    def m(c):
        if c["tool"].startswith("mcp."):
            _, name = c["tool"].split(".", 1); args = {k: v for k, v in c["args"].items()}
            req = W.decode_modern(T4.hdr("tools/call", name), T4.body_mod("tools/call", {"name": name, "arguments": args}, rid=abs(hash(c["call_id"])) % 10**9), c["principal"])
            resp = b4.gate.handle("s1", req, run_artifacts=tuple(arts4))
            return {"ok": True, "result": resp["result"]} if resp and "result" in resp else {"ok": False, "error": "DENIED"}
        _, tool = c["tool"].split(".", 1); r = b5.gate.call(c["principal"], c["call_id"], "m", tool, c["args"], run_artifacts=tuple(arts5))
        return {"ok": True, "result": r["result"]} if r["ok"] else {"ok": False, "error": r["error"]}
    return m


@unittest.skipUnless(HAVE_NODE, "node required")
class MixedProtocols(unittest.TestCase):
    PROGRAM = """
      const out = [];
      const attempt = async (label, p) => { try { await p; out.push([label, 'ok']); } catch (e) { out.push([label, e.code]); } };
      await attempt('mcp-read', tools.mcp.get_doc({id: '1'}));
      await attempt('utcp-read', tools.utcp.get({id: '1'}));
      await attempt('mcp-send-registry', tools.mcp.publish({url: 'https://registry.example.com/x'}));
      await attempt('utcp-send-partner', tools.utcp.post({}));
      return out;"""

    def fixtures(self):
        b4 = T4.Enforcement("test_allow_forwards_and_labels_output"); b4.setUp(); b5 = T5.GateTests("test_deny_means_no_network_request"); b5.setUp(); return b4, b5

    def test_mixed_program_matches_direct_calls_semantically(self):
        b4, b5 = self.fixtures(); ex = Executor(router(b4, b5, ("pub1",), ("pub",)))
        r = ex.run(self.PROGRAM, ["mcp.get_doc", "mcp.publish", "utcp.get", "utcp.post"], principal="agent-a"); self.assertTrue(r["ok"], r)
        # same operations with Code Mode disabled, on fresh identical fixtures
        d4, d5 = self.fixtures(); direct = []
        for name, args in (("get_doc", {"id": "1"}), ("publish", {"url": "https://registry.example.com/x"})):
            req = W.decode_modern(T4.hdr("tools/call", name), T4.body_mod("tools/call", {"name": name, "arguments": args}, rid=len(direct) + 1), "agent-a"); resp = d4.gate.handle("s1", req, run_artifacts=("pub1",)); direct.append("ok" if "result" in resp else "denied")
        for tool, args in (("get", {"id": "1"}), ("post", {})): rr = d5.gate.call("agent-a", f"d{tool}", "m", tool, args, run_artifacts=("pub",)); direct.append("ok" if rr["ok"] else "denied")
        via = ["ok" if o[1] == "ok" else "denied" for o in r["result"]]
        self.assertEqual([via[0], via[2], via[1], via[3]], direct)                                                                                       # mcp.get, mcp.publish, utcp.get, utcp.post
        self.assertEqual((len(b4.forwards), len(b5.sent)), (len(d4.forwards), len(d5.sent)))

    def test_secret_input_denied_identically_inside_program_with_no_side_effect(self):
        b4, b5 = self.fixtures(); ex = Executor(router(b4, b5, ("sec1",), ("sec",)))
        r = ex.run("const o=[]; for (const f of [() => tools.mcp.publish({url:'https://registry.example.com/x'}), () => tools.utcp.post({})]) { try { await f(); o.push('ok'); } catch (e) { o.push(e.code); } } return o;", ["mcp.publish", "utcp.post"], principal="agent-a")
        self.assertEqual(r["result"], ["DENIED", "DENIED"]); self.assertEqual((b4.forwards, b5.sent), ([], []))

    def test_program_cannot_bypass_via_unsupported_host_api(self):
        b4, b5 = self.fixtures(); ex = Executor(router(b4, b5))
        r = ex.run("const res = []; for (const f of [() => fetch('https://169.254.169.254/'), () => require('http').get('http://x'), () => process.binding('tcp_wrap'), () => new WebSocket('wss://x')]) { try { f(); res.push('reached'); } catch (e) { res.push(e.name); } } return res;", ["mcp.get_doc"], principal="agent-a")
        self.assertEqual(r["result"], ["ReferenceError"] * 4); self.assertEqual((b4.forwards, b5.sent), ([], []))                                    # sandbox-denied, not silently missed by the scanner


if __name__ == "__main__": unittest.main()
