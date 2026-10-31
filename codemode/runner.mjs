// Code Mode runner (P6-02..P6-04, P6-11..P6-20). One program per process. Speaks JSON lines on stdin/stdout.
// The isolate gets NO host objects except one mediated async reference. isolated-vm exposes no fs/require/process/fetch/timers by default.
import ivm from "isolated-vm";
import readline from "node:readline";

const out = (o) => process.stdout.write(JSON.stringify(o) + "\n");
const rl = readline.createInterface({ input: process.stdin });
const lines = []; let waiter = null; const pending = new Map(); let nextCid = 1;
rl.on("line", (l) => {
  let m; try { m = JSON.parse(l); } catch { return; }
  if (m.t === "result" && pending.has(m.cid)) { pending.get(m.cid)(m); pending.delete(m.cid); return; }
  lines.push(m); if (waiter) { const w = waiter; waiter = null; w(); }
});
const nextConfig = () => new Promise((res) => { const t = () => (lines.length ? res(lines.shift()) : (waiter = t)); t(); });

const cfg = await nextConfig();
const MAX_LOG = cfg.max_log_bytes ?? 16384; let logBytes = 0, logTrunc = false;
out({ t: "hello", uid: process.getuid?.(), pid: process.pid, env_keys: Object.keys(process.env).sort() });
let completed = false, calls = 0;
const isolate = new ivm.Isolate({ memoryLimit: cfg.memory_mb ?? 64 });
const ctx = await isolate.createContext();
const jail = ctx.global; await jail.set("global", jail.derefInto());

// only channel to the host: name + JSON string in, JSON string out. Host validates and mediates everything.
const callRef = new ivm.Reference(async (name, argsJson) => {
  if (completed) { out({ t: "late_call", tool: String(name) }); return JSON.stringify({ ok: false, error: "AFTER_COMPLETION" }); }
  if (++calls > (cfg.max_calls ?? 200)) return JSON.stringify({ ok: false, error: "CALL_BUDGET" });
  const cid = nextCid++;
  const p = new Promise((res) => pending.set(cid, res));
  out({ t: "call", cid, tool: String(name), args: String(argsJson) });
  const r = await p; return JSON.stringify(r.payload);
});
const logRef = new ivm.Reference((level, text) => {
  const s = String(text); if (logBytes + s.length > MAX_LOG) { logTrunc = true; return; }
  logBytes += s.length; out({ t: "log", level: String(level), text: s });
});
await jail.set("__call", callRef); await jail.set("__log", logRef);
await jail.set("__tools", new ivm.ExternalCopy(cfg.tool_names).copyInto());
await ctx.eval(`
  (() => {
    const call = globalThis.__call, log = globalThis.__log, names = globalThis.__tools;
    delete globalThis.__call; delete globalThis.__log; delete globalThis.__tools;
    const mk = (name) => async (args) => {
      let j; try { j = JSON.stringify(args === undefined ? {} : args); } catch { throw new Error("arguments are not JSON-serialisable"); }
      const r = JSON.parse(await call.apply(undefined, [name, j], { arguments: { copy: true }, result: { promise: true, copy: true } }));
      if (!r.ok) { const e = new Error(String(r.error)); e.code = r.error; throw e; }
      return r.result;
    };
    const tools = {};
    for (const n of names) { const parts = n.split("."); let o = tools; for (let i = 0; i < parts.length - 1; i++) o = (o[parts[i]] ??= {}); o[parts[parts.length - 1]] = mk(n); }
    const freeze = (o) => { for (const k of Object.keys(o)) if (typeof o[k] === "object") freeze(o[k]); Object.freeze(o); };
    freeze(tools); Object.defineProperty(globalThis, "tools", { value: tools, writable: false, configurable: false });
    const fmt = (a) => a.map((x) => { try { return typeof x === "string" ? x : JSON.stringify(x); } catch { return "[unserialisable]"; } }).join(" ");
    globalThis.console = Object.freeze({ log: (...a) => log.applySync(undefined, ["log", fmt(a)]), error: (...a) => log.applySync(undefined, ["error", fmt(a)]), warn: (...a) => log.applySync(undefined, ["warn", fmt(a)]) });
  })();
`);
const deadline = setTimeout(() => { out({ t: "done", ok: false, error: "TIMEOUT" }); process.exit(0); }, cfg.timeout_ms ?? 5000);
try {
  const script = await isolate.compileScript(`(async () => {\n${cfg.code}\n})()`, { filename: "program.js" });
  const res = await script.run(ctx, { timeout: cfg.timeout_ms ?? 5000, promise: true, copy: true });
  completed = true;
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));       // drain: anything scheduled after outer completion is observed and denied
  let result; try { result = JSON.parse(JSON.stringify(res ?? null)); } catch { result = null; }
  out({ t: "done", ok: true, result, log_truncated: logTrunc });
} catch (e) {
  completed = true;
  const msg = String(e && e.message || e).slice(0, 300);
  out({ t: "done", ok: false, error: /memory/i.test(msg) ? "MEMORY_LIMIT" : /timed out/i.test(msg) ? "TIMEOUT" : "PROGRAM_ERROR", message: msg, log_truncated: logTrunc });
}
clearTimeout(deadline); try { isolate.dispose(); } catch {} process.exit(0);
