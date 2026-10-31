// Run against a live service: node --experimental-strip-types smoke.mjs <socket> <token>
import { HorizonClient, Denied } from "./client.ts";
const [sock, token] = process.argv.slice(2);
const c = new HorizonClient({ token, socketPath: sock }, { runId: "run-ts-1" });
const sha = "sha256:" + "a".repeat(64);
const base = { protocol: "utcp", native_operation: "http:POST", effect: "send", args_digest: sha, target: { kind: "url", raw: "https://registry.example.com/x" }, sink_zone: "registry" };
const fail = (m) => { console.error("FAIL " + m); process.exit(1); };
if ((await c.health()).status !== "ok") fail("health");
const ok = await c.requireAllow({ ...base, input_artifacts: ["a1"] }); if (ok.verdict !== "ALLOW") fail("allow");
let denied = false; try { await c.requireAllow({ ...base, input_artifacts: ["ghost"] }); } catch (e) { denied = e instanceof Denied; } if (!denied) fail("deny");
const down = await new HorizonClient({ token, socketPath: "/nonexistent.sock", timeoutMs: 300 }, { runId: "r" }).decide(base);
if (down.verdict !== "DENY" || down.reason_codes[0] !== "SERVICE_UNREACHABLE") fail("fail-closed");
let threw = false; try { new HorizonClient({ token, socketPath: sock }, { runId: "" }); } catch { threw = true; } if (!threw) fail("run context");
console.log("TS SDK OK");
