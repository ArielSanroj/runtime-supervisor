import { beforeEach, describe, expect, it, vi } from "vitest";
import { Client } from "@runtime-supervisor/client";
import { configure, injectClientForTests, resetForTests } from "../src/config.js";
import { supervised, guarded } from "../src/guard.js";
import { SupervisorBlocked, SupervisorReviewPending } from "../src/errors.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function buildClient(fetchImpl: typeof fetch): Client {
  return new Client({
    baseUrl: "http://test",
    appId: "a",
    sharedSecret: "s",
    fetchImpl,
  });
}

beforeEach(() => {
  resetForTests();
});

describe("supervised", () => {
  it("runs wrapped fn on allow", async () => {
    const fetchSpy = vi.fn(async () =>
      jsonResponse(200, { action_id: "a1", decision: "allow", reasons: ["ok"], risk_score: 0, policy_version: "v1" }),
    );
    injectClientForTests(buildClient(fetchSpy as unknown as typeof fetch));

    const wrapped = supervised<[number], number>("refund", {
      payloadFrom: (amount) => ({ amount }),
    })(async (amount) => amount * 2);

    expect(await wrapped(50)).toBe(100);
  });

  it("raises SupervisorBlocked on deny", async () => {
    const fetchSpy = vi.fn(async () =>
      jsonResponse(200, { action_id: "a2", decision: "deny", reasons: ["amount-exceeds-hard-cap"], risk_score: 0, policy_version: "v1" }),
    );
    injectClientForTests(buildClient(fetchSpy as unknown as typeof fetch));

    const wrapped = supervised<[number], void>("refund", {
      payloadFrom: (amount) => ({ amount }),
    })(async () => {
      throw new Error("must not run");
    });

    await expect(wrapped(20000)).rejects.toBeInstanceOf(SupervisorBlocked);
  });

  it("fail_closed raises SupervisorReviewPending on review", async () => {
    const fetchSpy = vi.fn(async () =>
      jsonResponse(200, { action_id: "a3", decision: "review", reasons: ["risk-score-50"], risk_score: 50, policy_version: "v1" }),
    );
    injectClientForTests(buildClient(fetchSpy as unknown as typeof fetch));

    const wrapped = supervised<[number], void>("refund", {
      payloadFrom: (amount) => ({ amount }),
      onReview: "fail_closed",
    })(async () => {
      throw new Error("must not run");
    });

    await expect(wrapped(1200)).rejects.toBeInstanceOf(SupervisorReviewPending);
  });

  it("fail_open proceeds through review", async () => {
    const fetchSpy = vi.fn(async () =>
      jsonResponse(200, { action_id: "a4", decision: "review", reasons: ["risk-score-50"], risk_score: 50, policy_version: "v1" }),
    );
    injectClientForTests(buildClient(fetchSpy as unknown as typeof fetch));

    const wrapped = supervised<[number], string>("refund", {
      payloadFrom: (amount) => ({ amount }),
      onReview: "fail_open",
    })(async () => "ran");

    expect(await wrapped(1200)).toBe("ran");
  });

  it("guarded imperative form works", async () => {
    const fetchSpy = vi.fn(async () =>
      jsonResponse(200, { action_id: "a5", decision: "allow", reasons: [], risk_score: 0, policy_version: "v1" }),
    );
    injectClientForTests(buildClient(fetchSpy as unknown as typeof fetch));

    const out = await guarded("refund", { amount: 50 }, async () => "ok");
    expect(out).toBe("ok");
  });
});

describe("configure", () => {
  it("uses env vars when no args given", () => {
    process.env.SUPERVISOR_APP_ID = "env-app";
    process.env.SUPERVISOR_SECRET = "env-secret";
    configure();
    // Just assert no throw; client lazily initializes.
    expect(true).toBe(true);
  });
});
