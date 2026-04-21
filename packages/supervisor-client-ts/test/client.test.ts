import { describe, expect, it, vi } from "vitest";
import { Client, SupervisorError } from "../src/index.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("Client.evaluate", () => {
  it("sends auth header and body, returns typed Decision", async () => {
    const fetchSpy = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe("http://test/v1/actions/evaluate");
      expect((init?.headers as Record<string, string>)["authorization"]).toMatch(/^Bearer ey/);
      expect(JSON.parse(init?.body as string)).toEqual({ action_type: "refund", payload: { amount: 50 }, shadow: false });
      return jsonResponse(200, {
        action_id: "a-1",
        decision: "allow",
        reasons: ["passes-policy-and-risk"],
        risk_score: 0,
        policy_version: "refund.base@v1",
      });
    });

    const c = new Client({
      baseUrl: "http://test",
      appId: "app-1",
      sharedSecret: "s",
      scopes: ["refund"],
      fetchImpl: fetchSpy as unknown as typeof fetch,
    });
    const d = await c.evaluate("refund", { amount: 50 });
    expect(d.decision).toBe("allow");
    expect(fetchSpy).toHaveBeenCalledOnce();
  });

  it("appends ?dry_run=true when requested", async () => {
    const fetchSpy = vi.fn(async (url: string) => {
      expect(url).toBe("http://test/v1/actions/evaluate?dry_run=true");
      return jsonResponse(200, { action_id: "dry-run", decision: "review", reasons: [], risk_score: 0, policy_version: "v1" });
    });
    const c = new Client({ baseUrl: "http://test", appId: "a", sharedSecret: "s", fetchImpl: fetchSpy as unknown as typeof fetch });
    await c.evaluate("refund", {}, { dryRun: true });
  });

  it("sends shadow flag + reads shadow_would_have off the response", async () => {
    const fetchSpy = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(JSON.parse(init?.body as string).shadow).toBe(true);
      return jsonResponse(200, {
        action_id: "a-shadow",
        decision: "allow",
        reasons: [],
        risk_score: 0,
        policy_version: "v1",
        shadow_would_have: "deny",
      });
    });
    const c = new Client({ baseUrl: "http://test", appId: "a", sharedSecret: "s", fetchImpl: fetchSpy as unknown as typeof fetch });
    const d = await c.evaluate("refund", { amount: 999 }, { shadow: true });
    expect(d.decision).toBe("allow");
    expect(d.shadow_would_have).toBe("deny");
  });

  it("throws SupervisorError on 4xx with detail", async () => {
    const c = new Client({
      baseUrl: "http://test",
      appId: "a",
      sharedSecret: "s",
      fetchImpl: async () => jsonResponse(403, { detail: "scope 'refund' not granted" }),
    });
    await expect(c.evaluate("refund", {})).rejects.toBeInstanceOf(SupervisorError);
    await expect(c.evaluate("refund", {})).rejects.toMatchObject({ statusCode: 403, detail: "scope 'refund' not granted" });
  });
});
