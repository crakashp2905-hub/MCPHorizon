// TypeScript SDK (P3-09). Zero runtime dependencies (node:http). Fail-closed: transport failure => synthetic DENY, never ALLOW.
import * as http from "node:http";

export type Verdict = "ALLOW" | "DENY" | "REVIEW" | "QUARANTINE" | "UNKNOWN" | "SHADOW_ALLOW";
export interface RunContext { runId: string; tenant?: string; experimentId?: string }
export interface DecisionRequest {
  protocol: string; native_operation: string; effect: string; args_digest: string;
  target: { kind: string; raw: string }; tool_id?: string; sink_zone?: string; purpose?: string;
  input_artifacts?: string[]; idempotency_key?: string; approval_id?: string; event_id?: string;
}
export interface Decision {
  verdict: Verdict; reason_codes: string[]; decision_id?: string; policy_version?: string;
  token?: Record<string, unknown> | null; expires_at?: string; error?: string;
}
export interface ClientOptions { token: string; socketPath?: string; host?: string; port?: number; timeoutMs?: number }
export class Denied extends Error {}

export class HorizonClient {
  private readonly o: ClientOptions; private readonly run: RunContext;
  constructor(o: ClientOptions, run: RunContext) {
    this.o = o; this.run = run;
    if (!run?.runId) throw new Error("explicit run context (runId) is required");
    if (!o.socketPath && !o.port) throw new Error("socketPath or port required");
  }
  private call<T>(method: string, path: string, body?: unknown): Promise<{ status: number; data: T }> {
    return new Promise((resolve, reject) => {
      const payload = body === undefined ? undefined : JSON.stringify(body);
      const req = http.request({
        method, path, socketPath: this.o.socketPath, host: this.o.socketPath ? undefined : (this.o.host ?? "127.0.0.1"), port: this.o.port,
        timeout: this.o.timeoutMs ?? 2000,
        headers: { Authorization: `Bearer ${this.o.token}`, "Content-Type": "application/json", "X-Trace-Id": this.run.runId,
                   ...(payload ? { "Content-Length": Buffer.byteLength(payload) } : {}) },
      }, (res) => {
        const chunks: Buffer[] = []; res.on("data", (c) => chunks.push(c));
        res.on("end", () => { try { resolve({ status: res.statusCode ?? 0, data: JSON.parse(Buffer.concat(chunks).toString() || "{}") }); } catch (e) { reject(e); } });
      });
      req.on("timeout", () => req.destroy(new Error("timeout"))); req.on("error", reject);
      if (payload) req.write(payload); req.end();
    });
  }
  /** Never throws on transport errors: returns a synthetic DENY (protected) or UNKNOWN so callers cannot mistake failure for ALLOW. */
  async decide(r: DecisionRequest, protectedEffect = true): Promise<Decision> {
    try {
      const { status, data } = await this.call<Decision>("POST", "/v2/decisions", { ...r, experiment_id: this.run.experimentId });
      if (status !== 200) return { verdict: protectedEffect ? "DENY" : "UNKNOWN", reason_codes: ["SERVICE_ERROR"], error: String(status) };
      return data;
    } catch (e) {
      return { verdict: protectedEffect ? "DENY" : "UNKNOWN", reason_codes: ["SERVICE_UNREACHABLE"], error: (e as Error).message };
    }
  }
  async requireAllow(r: DecisionRequest): Promise<Decision> {
    const d = await this.decide(r);
    if (d.verdict !== "ALLOW" && d.verdict !== "SHADOW_ALLOW") throw new Denied(`${d.verdict}: ${d.reason_codes.join(",")}`);
    return d;
  }
  async outcome(body: Record<string, unknown>) { return (await this.call("POST", "/v2/outcomes", body)).data; }
  async artifact(a: Record<string, unknown>) { return (await this.call("POST", "/v2/artifacts", { artifact: a })).data; }
  async health() { return (await this.call("GET", "/v2/health")).data; }
}
